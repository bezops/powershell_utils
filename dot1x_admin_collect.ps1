<#
dot1x_diag.ps1
LAN-only 802.1X diagnostics + CURRENTLY LOGGED-ON users' Personal certs (HKCU\My)
- PS 5.1 and PS 7 compatible
- Outputs to the current working directory
- Certificates exported as YAML (no external modules)
- Hostname-prefixed filenames
- Adds mapping checks, service/EAP checks, event-log summaries, and preliminary findings
#>

[CmdletBinding()]
param(
  [int]$Hours = 24,
  [int]$UserWaitSeconds = 120
)

# ----------------- Helpers -----------------
function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script in an elevated PowerShell (Run as Administrator)."
    exit 1
  }
}
function Run-Step { param([string]$Title,[scriptblock]$Action)
  Write-Host "==> $Title"
  try { & $Action } catch { Write-Warning "[$Title] failed: $($_.Exception.Message)" }
}
function Safe-RegExport([string]$Key,[string]$OutFile,[string]$MissingLog) {
  if (Test-Path "Registry::$Key") { & reg.exe export "$Key" "$OutFile" /y 2>$null | Out-Null }
  else { "Missing: $Key" | Out-File $MissingLog -Append }
}
# XML helpers (PS5/PS7-safe)
function Get-NodeText([xml]$doc,[string]$xpath){ $n=$doc.SelectSingleNode($xpath); if($n){$n.InnerText}else{$null} }
function Count-Nodes([xml]$doc,[string]$xpath){ $nl=$doc.SelectNodes($xpath); if($nl){$nl.Count}else{0} }

# Identify currently logged-on interactive users
function Get-InteractiveUserContexts {
  $ctx = @()

  # HKU\*\Volatile Environment (live sessions)
  Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue |
    Where-Object { Test-Path ("Registry::HKEY_USERS\{0}\Volatile Environment" -f $_.PSChildName) } |
    ForEach-Object {
      $sidHku = $_.PSChildName
      try {
        $ve = Get-ItemProperty -Path ("Registry::HKEY_USERS\{0}\Volatile Environment" -f $sidHku) -ErrorAction Stop
        $dom = $ve.USERDOMAIN; $usr = $ve.USERNAME
        $classic = $null
        if ($dom -and $usr) {
          try {
            $classic = (New-Object System.Security.Principal.NTAccount($dom,$usr)).
                        Translate([System.Security.Principal.SecurityIdentifier]).Value
          } catch {}
        }
        $ctx += [pscustomobject]@{ Domain=$dom; User=$usr; HKUSID=$sidHku; ClassicSID=$classic }
      } catch {}
    }

  # WMI (interactive + remote-interactive)
  try {
    $sessions = Get-CimInstance Win32_LogonSession -Filter "LogonType=2 OR LogonType=10"
    foreach ($s in $sessions) {
      $links = Get-CimAssociatedInstance -InputObject $s -Association Win32_LoggedOnUser -ErrorAction SilentlyContinue
      foreach ($a in $links) {
        if ($a.PSObject.TypeNames -like '*Win32_Account*') {
          $dom=$a.Domain; $usr=$a.Name
          $classic = $null
          try { $classic = (New-Object System.Security.Principal.NTAccount($dom,$usr)).
                          Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}
          if (-not ($ctx | Where-Object { $_.Domain -eq $dom -and $_.User -eq $usr })) {
            $ctx += [pscustomobject]@{ Domain=$dom; User=$usr; HKUSID=$null; ClassicSID=$classic }
          }
        }
      }
    }
  } catch {}

  # Merge per user; build CandidateSIDs
  $merged=@()
  foreach($g in ($ctx | Group-Object Domain,User)){
    $dom=$g.Group[0].Domain; $usr=$g.Group[0].User
    if (-not $usr) { continue }
    $hku = ($g.Group | Where-Object {$_.HKUSID}     | Select-Object -ExpandProperty HKUSID     -First 1)
    $cls = ($g.Group | Where-Object {$_.ClassicSID} | Select-Object -ExpandProperty ClassicSID -First 1)
    $cands=@(); if($hku){$cands+=$hku}; if($cls){ if($cands -notcontains $cls){$cands+=$cls} }
    $merged += [pscustomobject]@{
      Domain=$dom; User=$usr; Display=("{0}\{1}" -f $dom,$usr)
      HKUSID=$hku; ClassicSID=$cls; CandidateSIDs=$cands
    }
  }
  return $merged
}

# Utility: prepend every line of a file with fixed indent and append to another file
function Add-IndentedFileContent {
  param([Parameter(Mandatory)] [string]$SourcePath,
        [Parameter(Mandatory)] [string]$DestPath,
        [string]$Indent = '  ')
  if (Test-Path $SourcePath) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($ln in [System.IO.File]::ReadLines($SourcePath)) {
      $null = $sb.AppendLine($Indent + $ln)
    }
    Add-Content -Path $DestPath -Value $sb.ToString()
  }
}

# Preliminary findings helper
function Add-PrelimSection {
  param([string]$PrelimPath,[string]$Title,[string[]]$Lines)
  Add-Content -Path $PrelimPath -Value ("# "+$Title)
  if ($Lines) { $Lines | ForEach-Object { Add-Content -Path $PrelimPath -Value ("- "+$_) } }
  Add-Content -Path $PrelimPath -Value ""
}

# NEW: robustly format InterfaceGuid to {GUID}
function Format-GuidB([object]$g) {
  $s = [string]$g
  if     ($s -match '^\{[0-9a-fA-F-]+\}$') { return $s }
  elseif ($s -match '^[0-9a-fA-F-]+$')     { return '{' + $s + '}' }
  else {
    try { return ([Guid]$s).ToString('B') } catch { return $s }
  }
}

# ----------------- Main -----------------
Assert-Admin

$HostTag   = $env:COMPUTERNAME
$TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$RootName  = "${HostTag}_8021X_Collect_$TimeStamp"
$Root      = Join-Path (Get-Location) $RootName
New-Item -ItemType Directory -Force -Path $Root | Out-Null

$Prelim = Join-Path $Root ("{0}_preliminary_findings.txt" -f $HostTag)
"Preliminary findings for $HostTag @ $TimeStamp" | Out-File $Prelim -Encoding UTF8
"" | Out-File $Prelim -Append

Start-Transcript -Path (Join-Path $Root "Transcript.txt") -Force | Out-Null

# 0) Enable wired Operational logs
Run-Step "Enable Wired-AutoConfig & EapHost Operational logs" {
  wevtutil sl "Microsoft-Windows-Wired-AutoConfig/Operational" /e:true
  wevtutil sl "Microsoft-Windows-EapHost/Operational" /e:true
}

# 1) OS & build details
Run-Step "Collect OS & Build details" {
  Get-CimInstance Win32_OperatingSystem |
    Select-Object CSName, Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime |
    Format-List | Out-File (Join-Path $Root "os_info.txt")
  $ovf = Join-Path $Root "os_version_details.txt"
  $lines=@()
  try {
    $cur = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -ErrorAction Stop
    "DisplayVersion : $($cur.DisplayVersion)" | Out-File $ovf
    "ReleaseId      : $($cur.ReleaseId)"      | Out-File $ovf -Append
    "UBR (Patch)    : $($cur.UBR)"            | Out-File $ovf -Append
    "BuildLabEx     : $($cur.BuildLabEx)"     | Out-File $ovf -Append
    $lines += "Windows $($cur.DisplayVersion) (Build $($cur.CurrentBuild).$($cur.UBR))"
  } catch { "CurrentVersion key not found." | Out-File $ovf; $lines += "Could not read CurrentVersion registry." }
  Add-PrelimSection -PrelimPath $Prelim -Title "OS/Build" -Lines $lines
}

# 1.5) Service health (dot3svc, EapHost)
Run-Step "Check service health (dot3svc, EapHost)" {
  $svcFile = Join-Path $Root "service_health.txt"
  $lines=@()

  foreach ($name in @('dot3svc','EapHost')) {
    $svc  = Get-Service -Name $name -ErrorAction SilentlyContinue
    $cim  = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $name) -ErrorAction SilentlyContinue
    if ($svc) {
      "== $name ==" | Out-File $svcFile -Append
      $svc | Format-List * | Out-File $svcFile -Append
      if ($cim) { ("StartMode: {0}" -f $cim.StartMode) | Out-File $svcFile -Append }
      "" | Out-File $svcFile -Append

      $state = if ($svc.Status -eq 'Running') { 'OK' } else { 'NOT RUNNING' }
      $start = if ($cim) { $cim.StartMode } else { '<unknown>' }
      $lines += ("{0}: {1} (StartMode={2})" -f $name, $state, $start)
    } else {
      $lines += ("{0}: Service not found" -f $name)
    }
  }
  Add-PrelimSection -PrelimPath $Prelim -Title "Service Health" -Lines $lines
}

# 2) Wired-only snapshots (Ethernet only)  **HUMAN-READABLE IP DETAILS**
Run-Step "Collect Wired 802.1X service & Ethernet-only snapshots" {
  Get-Service dot3svc | Format-List * | Out-File (Join-Path $Root "dot3svc_status.txt")

  $Eth = Get-NetAdapter -Physical |
    Where-Object {
      ($_.InterfaceDescription -match 'Ethernet') -and
      ($_.InterfaceDescription -notmatch 'Wi-?Fi|Wireless|Bluetooth|Hyper-V|VMware|Virtual|Loopback|TAP|Npcap')
    } | Sort-Object ifIndex

  $ethFile = Join-Path $Root "netadapters_ethernet_only.txt"
  $Eth | Format-Table -Auto ifIndex, Name, InterfaceDescription, Status, MacAddress, LinkSpeed |
    Out-File $ethFile

  # Human-readable per-adapter IP summary
  $ipSummary = Join-Path $Root ("{0}_ip_ethernet_summary.txt" -f $HostTag)
  foreach ($a in $Eth) {
    "=== $($a.ifIndex) : $($a.Name) : $($a.InterfaceDescription) ===" | Out-File $ipSummary -Append

    $ip4 = Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
           Sort-Object PrefixLength -Descending
    $ip6 = Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue |
           Sort-Object PrefixLength -Descending

    $gw4 = Get-NetRoute -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
           Sort-Object RouteMetric, Metric |
           Select-Object -ExpandProperty NextHop -Unique
    $gw6 = Get-NetRoute -InterfaceIndex $a.ifIndex -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue |
           Sort-Object RouteMetric, Metric |
           Select-Object -ExpandProperty NextHop -Unique

    $dns = Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue |
           ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | Select-Object -Unique
    $dnsSuffix = (Get-DnsClient -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue).ConnectionSpecificSuffix
    $dhcp4 = (Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp

    "IPv4 Address(es): " + ($(if($ip4){ ($ip4 | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" }) -join ', ' } else { '-' })) | Out-File $ipSummary -Append
    "IPv6 Address(es): " + ($(if($ip6){ ($ip6 | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" }) -join ', ' } else { '-' })) | Out-File $ipSummary -Append
    "IPv4 Default GW: " + ($(if($gw4){ $gw4 -join ', ' } else { '-' })) | Out-File $ipSummary -Append
    "IPv6 Default GW: " + ($(if($gw6){ $gw6 -join ', ' } else { '-' })) | Out-File $ipSummary -Append
    "DNS Servers:     " + ($(if($dns){ $dns -join ', ' } else { '-' })) | Out-File $ipSummary -Append
    "DNS Suffix:      " + ($(if($dnsSuffix){ $dnsSuffix } else { '-' })) | Out-File $ipSummary -Append
    "DHCP (IPv4):     " + ($(if($dhcp4){ $dhcp4 } else { '-' })) | Out-File $ipSummary -Append
    "" | Out-File $ipSummary -Append
  }

  # Also capture classic ipconfig for auditing
  & ipconfig /all > (Join-Path $Root ("{0}_ipconfig_all.txt" -f $HostTag))

  # netsh LAN snapshots
  & netsh lan show settings    > (Join-Path $Root "netsh_lan_show_settings.txt")
  & netsh lan show interfaces  > (Join-Path $Root "netsh_lan_show_interfaces.txt")
  & netsh lan show profiles    > (Join-Path $Root "netsh_lan_show_profiles.txt")

  # Prelim summary
  $aOK = ($Eth | Where-Object {$_.Status -eq 'Up'}).Count
  Add-PrelimSection -PrelimPath $Prelim -Title "Ethernet adapters" -Lines @(
    ("Total physical Ethernet: {0}" -f $Eth.Count),
    ("Up: {0}, Down/Disabled: {1}" -f $aOK, ($Eth.Count - $aOK))
  )
}

# 3) Export wired 802.1X profiles (XML) + summary (+aggregate to prelim)
Run-Step "Export wired 802.1X profiles (XML) + summary" {
  $ProfDir = Join-Path $Root "lan_profiles"
  New-Item -ItemType Directory -Force -Path $ProfDir | Out-Null
  & netsh lan export profile folder="$ProfDir"

  # also try per-interface export
  $ifs = (netsh lan show interfaces) -match '^\s*Name\s*:\s*(.+)$' | ForEach-Object { ($_.Split(':')[1]).Trim() }
  foreach ($if in $ifs) { if ($if) { & netsh lan export profile folder="$ProfDir" interface="$if" } }

  $out = Join-Path $Root "lan_profiles_summary.txt"
  $total=0; $withEap=0
  $outerCounts = @{}; $innerCounts=@{}
  $serverNamesSeen=@(); $rootSum=0

  Get-ChildItem $ProfDir -Filter *.xml | ForEach-Object {
    $total++
    "=== $($_.Name) ===" | Out-File $out -Append
    try{
      [xml]$x = Get-Content $_.FullName -Raw
      $has = $x.SelectSingleNode("//*[local-name()='EapHostConfig']")
      if (-not $has) { "No EapHostConfig section found.`n" | Out-File $out -Append; return }

      $withEap++
      $outer = Get-NodeText $x "//*[local-name()='EapHostConfig']/*[local-name()='EapMethod']/*[local-name()='Type']"
      if ($outer) {
        if ($outerCounts.ContainsKey($outer)) { $outerCounts[$outer]++ } else { $outerCounts[$outer]=1 }
      }
      "Outer EAP type: $outer" | Out-File $out -Append

      $inner = Get-NodeText $x "//*[local-name()='EapHostConfig']/*[local-name()='Config']//*[local-name()='Eap']//*[local-name()='Type']"
      if (-not $inner) { $inner = Get-NodeText $x "//*[local-name()='EapHostConfig']/*[local-name()='Config']//*[local-name()='Eap']/*[local-name()='Eap']//*[local-name()='Type']" }
      if ($inner) {
        if ($innerCounts.ContainsKey($inner)) { $innerCounts[$inner]++ } else { $innerCounts[$inner]=1 }
      }
      "Inner EAP type: $inner" | Out-File $out -Append

      $srvPaths = @(
        "//*[local-name()='EapHostConfig']/*[local-name()='Config']//*[local-name()='EapTls']/*[local-name()='ServerValidation']",
        "//*[local-name()='EapHostConfig']/*[local-name()='Config']//*[local-name()='Ttls']/*[local-name()='ServerValidation']"
      )

      $names=$null; $rootCount=0
      foreach ($p in $srvPaths) {
        if (-not $names)     { $names     = Get-NodeText $x ($p+"/*[local-name()='ServerNames']") }
        if ($rootCount -eq 0){ $rootCount = Count-Nodes $x ($p+"/*[local-name()='TrustedRootCA']/*") }
      }
      if ($names) { "Server names: $names" | Out-File $out -Append; $serverNamesSeen += $names }
      "TrustedRootCA items: $rootCount`n" | Out-File $out -Append
      $rootSum += $rootCount

    } catch { "Parse error: $($_.Exception.Message)`n" | Out-File $out -Append }
  }

  # Prelim section
  $outerStr = if($outerCounts.Keys.Count){ ($outerCounts.Keys | ForEach-Object { "$_=$($outerCounts[$_])" }) -join ', ' } else { '-' }
  $innerStr = if($innerCounts.Keys.Count){ ($innerCounts.Keys | ForEach-Object { "$_=$($innerCounts[$_])" }) -join ', ' } else { '-' }
  $namesStr = if($serverNamesSeen){ ($serverNamesSeen | Select-Object -Unique) -join ', ' } else { '-' }
  Add-PrelimSection -PrelimPath $Prelim -Title "Wired profiles (XML)" -Lines @(
    ("Exported XML files: {0}, with EapHostConfig: {1}" -f $total,$withEap),
    ("Outer EAP types: {0}" -f $outerStr),
    ("Inner EAP types: {0}" -f $innerStr),
    ("ServerNames (union): {0}" -f $namesStr),
    ("Total TrustedRootCA references (sum): {0}" -f $rootSum)
  )
}

# 3.5) Map adapters to dot3svc\Interfaces and flag missing bindings
Run-Step "Map adapters to dot3svc\\Interfaces and flag missing bindings" {
  $mapFile  = Join-Path $Root ("{0}_wired_interface_map.txt" -f $HostTag)
  $findings = Join-Path $Root ("{0}_wired_findings.txt" -f $HostTag)
  if (Test-Path $findings) { Remove-Item $findings -Force -ErrorAction SilentlyContinue }

  $Eth = Get-NetAdapter -Physical |
    Where-Object {
      ($_.InterfaceDescription -match 'Ethernet') -and
      ($_.InterfaceDescription -notmatch 'Wi-?Fi|Wireless|Bluetooth|Hyper-V|VMware|Virtual|Loopback|TAP|Npcap')
    } | Sort-Object ifIndex

  $ok=0;$partial=0;$missing=0
  foreach ($a in $Eth) {
    $guidB   = Format-GuidB $a.InterfaceGuid   # {GUID} formatting safe for string/guid
    $regKey  = "HKLM:\SOFTWARE\Microsoft\dot3svc\Interfaces\$guidB"
    $regSeen = Test-Path $regKey

    "=== ifIndex $($a.ifIndex) : $($a.Name)  ($guidB)" | Out-File $mapFile -Append
    "AdapterDesc: $($a.InterfaceDescription)"           | Out-File $mapFile -Append
    "RegKeyPresent: $regSeen"                           | Out-File $mapFile -Append

    $ProfDir = Join-Path $Root "lan_profiles"
    $xmlMatch = Get-ChildItem -Path $ProfDir -Filter *.xml -ErrorAction SilentlyContinue |
                Where-Object { $_.BaseName -ieq $a.Name }
    if (-not $xmlMatch) {
      $xmlMatch = Get-ChildItem -Path $ProfDir -Filter *.xml -ErrorAction SilentlyContinue |
                  Where-Object { $_.BaseName -like "*$($a.Name)*" }
    }
    "ProfileXML: " + ($(if($xmlMatch){ $xmlMatch.Name -join ', ' } else { '<none>' })) | Out-File $mapFile -Append

    $safe = ($a.Name -replace '[\\/:*?""<>|]','_')
    $netshOut = Join-Path $Root ("netsh_lan_show_profile_{0}.txt" -f $safe)
    & netsh lan show profile interface="$($a.Name)" > $netshOut 2>$null

    if (-not $regSeen -and -not $xmlMatch) {
      "MISSING_BINDING: No per-NIC registry key and no exported profile for '$($a.Name)'" | Out-File $findings -Append
      $missing++
    } elseif (-not $regSeen) {
      "PARTIAL: XML present but no per-NIC registry key for '$($a.Name)' (profile not bound?)" | Out-File $findings -Append
      $partial++
    } elseif (-not $xmlMatch) {
      "PARTIAL: Registry key present but no exported profile matched '$($a.Name)' (naming mismatch or no profile?)" | Out-File $findings -Append
      $partial++
    } else {
      "OK: Profile appears exported and registry binding exists for '$($a.Name)'" | Out-File $findings -Append
      $ok++
    }

    "" | Out-File $mapFile -Append
  }

  Add-PrelimSection -PrelimPath $Prelim -Title "Adapter/profile binding checks" -Lines @(
    ("OK={0}, PARTIAL={1}, MISSING_BINDING={2}" -f $ok,$partial,$missing),
    ("See: {0} and {1}" -f (Split-Path $mapFile -Leaf), (Split-Path $findings -Leaf))
  )
}

# 4) Collect wired registry artifacts
Run-Step "Collect wired registry artifacts (safe)" {
  $Artifacts = Join-Path $Root "wired_artifacts"
  New-Item -ItemType Directory -Force -Path $Artifacts | Out-Null
  $missing = Join-Path $Artifacts "reg_missing_keys.txt"

  Safe-RegExport "HKLM\SOFTWARE\Microsoft\dot3svc"               (Join-Path $Artifacts "HKLM_SOFTWARE_Microsoft_dot3svc.reg")               $missing
  Safe-RegExport "HKLM\SYSTEM\CurrentControlSet\Services\EapHost" (Join-Path $Artifacts "HKLM_SYSTEM_CCS_Services_EapHost.reg")             $missing
  Safe-RegExport "HKLM\SOFTWARE\Microsoft\EapHost"                (Join-Path $Artifacts "HKLM_SOFTWARE_Microsoft_EapHost.reg")              $missing
}

# 4.5) EAPHost methods inventory
Run-Step "Inventory EAPHost methods" {
  $eapOut = Join-Path $Root "eaphost_methods.txt"
  if (Test-Path "HKLM:\SOFTWARE\Microsoft\EapHost\Methods") {
    Get-ChildItem "HKLM:\SOFTWARE\Microsoft\EapHost\Methods" |
      ForEach-Object {
        "Method key: $($_.PSChildName)" | Out-File $eapOut -Append
        try {
          Get-ChildItem $_.PSPath | ForEach-Object { "  Subkey: $($_.PSChildName)" | Out-File $eapOut -Append }
        } catch {}
      }
    Add-PrelimSection -PrelimPath $Prelim -Title "EAPHost methods" -Lines @("See eaphost_methods.txt (verify TEAP/TLS present)")
  } else {
    Add-PrelimSection -PrelimPath $Prelim -Title "EAPHost methods" -Lines @("Registry path not found (EAP stack may be damaged)")
  }
}

# 5) EVTX + last-N-hours summaries (wired only) + prelim stats
Run-Step "Export EVTX & last-$Hours-hour text summaries" {
  $StartTime = (Get-Date).AddHours(-1 * $Hours)
  wevtutil epl "Microsoft-Windows-Wired-AutoConfig/Operational" (Join-Path $Root "Wired-AutoConfig.evtx") /ow:true
  wevtutil epl "Microsoft-Windows-EapHost/Operational"          (Join-Path $Root "EapHost.evtx")          /ow:true

  $waTxt = Join-Path $Root "Wired-AutoConfig-last${Hours}h.txt"
  $ehTxt = Join-Path $Root "EapHost-last${Hours}h.txt"

  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Wired-AutoConfig/Operational'; StartTime=$StartTime} |
    Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
    Sort-Object TimeCreated -Descending |
    Out-File $waTxt -Width 500

  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-EapHost/Operational'; StartTime=$StartTime} |
    Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
    Sort-Object TimeCreated -Descending |
    Out-File $ehTxt -Width 500

  # Prelim stats (errors & warnings by log)
  $waErr = (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Wired-AutoConfig/Operational'; StartTime=$StartTime; Level=2} -ErrorAction SilentlyContinue).Count
  $waWrn = (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Wired-AutoConfig/Operational'; StartTime=$StartTime; Level=3} -ErrorAction SilentlyContinue).Count
  $ehErr = (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-EapHost/Operational';          StartTime=$StartTime; Level=2} -ErrorAction SilentlyContinue).Count
  $ehWrn = (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-EapHost/Operational';          StartTime=$StartTime; Level=3} -ErrorAction SilentlyContinue).Count

  function TopIDs($log){
    $ids = Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$StartTime} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id
    if($ids){ ($ids | Group-Object | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "{0} (x{1})" -f $_.Name,$_.Count }) -join ', ' } else { '-' }
  }
  $waTop = TopIDs 'Microsoft-Windows-Wired-AutoConfig/Operational'
  $ehTop = TopIDs 'Microsoft-Windows-EapHost/Operational'

  Add-PrelimSection -PrelimPath $Prelim -Title "Event logs (last $Hours h)" -Lines @(
    ("Wired-AutoConfig: Errors={0}, Warnings={1}, Top IDs: {2}" -f $waErr,$waWrn,$waTop),
    ("EapHost:          Errors={0}, Warnings={1}, Top IDs: {2}" -f $ehErr,$ehWrn,$ehTop)
  )
}

# 6) CURRENT SESSIONS: helper per logged-on user (Interactive token) -> YAML + per-user stats
Run-Step "Collect certs for CURRENTLY LOGGED-ON users (run in user context, YAML + stats)" {
  $cuRoot     = Join-Path $Root "CurrentUsers_Personal"
  $perUserDir = Join-Path $cuRoot "PerUser"
  New-Item -ItemType Directory -Force -Path $perUserDir | Out-Null
  $masterYaml = Join-Path $cuRoot ("{0}_CurrentUsers_Personal_My.yaml" -f $HostTag)
  $dbg        = Join-Path $cuRoot "certs_debug.log"

  # helper script content — runs as the user and dumps Cert:\CurrentUser\My to YAML + tiny stats
  $helperPath = Join-Path $cuRoot "helper_collect_user_certs.ps1"
  @'
param(
  [string]$OutDir,
  [string]$UserLabel,
  [string]$HostTag
)
function YamlEscape([string]$s){
  if ($null -eq $s) { return "''" }
  $s = $s -replace "(`r`n|`n|`r)", ' '
  $s = $s -replace '\s+', ' '
  return "'" + ($s -replace "'", "''") + "'"
}
function Write-YamlArray([string]$Path, $Items){
  $sb = New-Object System.Text.StringBuilder
  foreach ($it in $Items) {
    $null = $sb.AppendLine("- UserName: " + (YamlEscape $it.UserName))
    $null = $sb.AppendLine("  SID: " + (YamlEscape $it.SID))
    $null = $sb.AppendLine("  IssuedTo: " + (YamlEscape $it.IssuedTo))
    $null = $sb.AppendLine("  IssuedBy: " + (YamlEscape $it.IssuedBy))
    $null = $sb.AppendLine("  Expiration: " + (YamlEscape ($it.Expiration.ToString('o'))))
    if ($it.IntendedPurposes -and $it.IntendedPurposes.Count -gt 0) {
      $null = $sb.AppendLine("  IntendedPurposes:")
      foreach ($ek in $it.IntendedPurposes) { $null = $sb.AppendLine("    - " + (YamlEscape $ek)) }
    } else { $null = $sb.AppendLine("  IntendedPurposes: []") }
    $null = $sb.AppendLine("  FriendlyName: " + (YamlEscape $it.FriendlyName))
    $null = $sb.AppendLine("  TemplateName: " + (YamlEscape $it.TemplateName))
    $null = $sb.AppendLine("  TemplateOID: " + (YamlEscape $it.TemplateOID))
    $null = $sb.AppendLine("  Thumbprint: " + (YamlEscape $it.Thumbprint))
  }
  Set-Content -Path $Path -Value $sb.ToString() -Encoding UTF8
}
function EKU-List($cert){
  $ekuExt = $cert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] }
  if($ekuExt){ return @($ekuExt.EnhancedKeyUsages | ForEach-Object { $_.FriendlyName }) } else { @() }
}
function TemplateName($cert){
  foreach($ext in $cert.Extensions){ if($ext.Oid.Value -eq '1.3.6.1.4.1.311.20.2'){
    try{ return (New-Object System.Security.Cryptography.AsnEncodedData($ext.Oid,$ext.RawData)).Format($true) }catch{}
  }}
  return ''
}
function TemplateOID($cert){
  foreach($ext in $cert.Extensions){ if($ext.Oid.Value -eq '1.3.6.1.4.1.311.21.7' -or $ext.Oid.Value -eq '1.3.6.1.4.1.311.21.8'){ return $ext.Oid.Value } }
  return ''
}
function SimpleName($cert,[bool]$forIssuer){
  try{ return $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$forIssuer) }catch{ return $null }
}

$rows=@()
if(Test-Path 'Cert:\CurrentUser\My'){
  Get-ChildItem 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue | ForEach-Object {
    $rows += [pscustomobject]@{
      UserName        = $UserLabel
      SID             = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
      IssuedTo        = (SimpleName $_ $false)
      IssuedBy        = (SimpleName $_ $true)
      Expiration      = $_.NotAfter
      IntendedPurposes= (EKU-List $_)
      FriendlyName    = $_.FriendlyName
      TemplateName    = (TemplateName $_)
      TemplateOID     = (TemplateOID $_)
      Thumbprint      = ($_.Thumbprint -replace ' ','').ToUpper()
    }
  }
}
$fnSafe = ($UserLabel -replace '[\\/:*?""<>|]','_')
$perUser = Join-Path $OutDir "PerUser"
New-Item -ItemType Directory -Force -Path $perUser | Out-Null

# YAML file (host-prefixed)
$yamlFile = Join-Path $perUser ("{0}_{1}.yaml" -f $HostTag,$fnSafe)
if($rows.Count){ Write-YamlArray -Path $yamlFile -Items $rows } else { Set-Content -Path $yamlFile -Value "" -Encoding UTF8 }

# Tiny per-user stats (for prelim merge)
$stats = Join-Path $perUser ("{0}_{1}_certstats.txt" -f $HostTag,$fnSafe)
if($rows.Count){
  $client = ($rows | Where-Object { $_.IntendedPurposes -contains 'Client Authentication' })
  $minExp = ($rows | Sort-Object Expiration | Select-Object -First 1).Expiration
  @(
    "User: $UserLabel"
    "Total certs: $($rows.Count)"
    "Client Authentication certs: $($client.Count)"
    ("Nearest expiry (all): {0:o}" -f $minExp)
  ) | Set-Content -Path $stats -Encoding UTF8
} else {
  @("User: $UserLabel","No certs in CurrentUser\My") | Set-Content -Path $stats -Encoding UTF8
}

# completion flag (host-prefixed)
New-Item -ItemType File -Path (Join-Path $perUser ("{0}_{1}.done" -f $HostTag,$fnSafe)) -Force | Out-Null
'@ | Set-Content -Path $helperPath -Encoding UTF8

  # grant each user write permission to PerUser
  $contexts = Get-InteractiveUserContexts
  if(-not $contexts -or $contexts.Count -eq 0){
    "No interactive user contexts found." | Out-File $dbg -Append
  }

  foreach($ctx in $contexts){
    if(-not $ctx.Domain -or -not $ctx.User){ continue }
    $display = $ctx.Display
    $userId  = "$($ctx.Domain)\$($ctx.User)"
    try {
      $acl = Get-Acl $perUserDir
      $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($userId,"Modify","ContainerInherit,ObjectInherit","None","Allow")
      $acl.AddAccessRule($rule) | Out-Null
      Set-Acl -Path $perUserDir -AclObject $acl
    } catch { "Failed to grant folder perms to $userId : $($_.Exception.Message)" | Out-File $dbg -Append }

    # register and start a one-shot task for that user
    $nSafe = ($ctx.User -replace '[\\/:*?""<>|]','_')
    $tn = "Dot1x-Collect-UserCerts-$nSafe"
    try{
      $action    = New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
                   -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$helperPath`" -OutDir `"$cuRoot`" -UserLabel `"$display`" -HostTag `"$HostTag`""
      $principal = New-ScheduledTaskPrincipal -UserId $userId -RunLevel Limited -LogonType Interactive
      $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility Win8
      try { Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue } catch {}
      Register-ScheduledTask -TaskName $tn -Action $action -Principal $principal -Settings $settings | Out-Null
      Start-ScheduledTask -TaskName $tn

      # wait for host-prefixed .done flag
      $flagBase = ($display -replace '[\\/:*?""<>|]','_')
      $flag = Join-Path $perUserDir ("{0}_{1}.done" -f $HostTag,$flagBase)
      $wait=$UserWaitSeconds
      while($wait -gt 0 -and -not (Test-Path $flag)){ Start-Sleep -Seconds 1; $wait-- }
      if(-not (Test-Path $flag)){ "Timeout waiting for helper completion for $display" | Out-File $dbg -Append }

    } catch {
      "Task run failed for $display : $($_.Exception.Message)" | Out-File $dbg -Append
    } finally {
      try { Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    }
  }

  # Merge: build master YAML with a top-level 'certificates:' list (host-prefixed filename)
  if (Test-Path $masterYaml) { Remove-Item $masterYaml -Force -ErrorAction SilentlyContinue }
  "certificates:" | Out-File $masterYaml -Encoding UTF8
  $allYaml = Get-ChildItem -Path $perUserDir -Filter ("{0}_*.yaml" -f $HostTag) -File -ErrorAction SilentlyContinue
  if ($allYaml) {
    foreach ($f in $allYaml) {
      if ((Get-Item $f.FullName).Length -gt 0) {
        Add-IndentedFileContent -SourcePath $f.FullName -DestPath $masterYaml -Indent '  '
      }
    }
  }

  # Merge per-user stats into prelim
  $statsFiles = Get-ChildItem -Path $perUserDir -Filter ("{0}_*_certstats.txt" -f $HostTag) -File -ErrorAction SilentlyContinue
  if ($statsFiles) {
    $lines = @()
    foreach ($sf in $statsFiles) { $lines += ("`t" + (Get-Content -Path $sf.FullName -Raw).Trim().Replace("`n"," | ")) }
    Add-PrelimSection -PrelimPath $Prelim -Title "User certs (summary)" -Lines $lines
  } else {
    Add-PrelimSection -PrelimPath $Prelim -Title "User certs (summary)" -Lines @("No per-user stats produced.")
  }
}

# 7) Wrap-up
Stop-Transcript | Out-Null
Run-Step "Create ZIP archive" {
  $zipPath = Join-Path (Get-Location) ("{0}.zip" -f $RootName)
  Compress-Archive -Path $Root -DestinationPath $zipPath -Force
  Write-Host "Archive created: $zipPath"
}
Write-Host "`nCollection complete. Folder: $Root"
