<#
dot1x_user_collect.ps1
Standard-user LAN 802.1X data collector (no admin required)

Captures:
- OS/build info (read-only)
- Ethernet adapters & human-readable IP details
- netsh LAN snapshots + per-interface profile views (+ best-effort XML export)
- EAPHost methods inventory (read-only)
- Event summaries for Wired-AutoConfig & EapHost (last N hours, text only)
- Current user's Personal certs (Cert:\CurrentUser\My) to YAML
- Preliminary findings summary
- ZIP archive of the collection folder

Outputs are written to current directory in: <HOST>_8021X_UserCollect_<timestamp>\

Tested for PS 5.1 and PS 7; LAN-only (no WLAN).
#>

[CmdletBinding()]
param(
  [int]$Hours = 24
)

# ---------- Helpers ----------
function Run-Step { param([string]$Title,[scriptblock]$Action)
  Write-Host "==> $Title"
  try { & $Action } catch { Write-Warning "[$Title] failed: $($_.Exception.Message)" }
}
function Get-SafeItemProperty {
  param([string]$Path)
  try { return Get-ItemProperty -Path $Path -ErrorAction Stop } catch { return $null }
}
# XML helpers (PS5/PS7-safe)
function Get-NodeText([xml]$doc,[string]$xpath){ $n=$doc.SelectSingleNode($xpath); if($n){$n.InnerText}else{$null} }
function Count-Nodes([xml]$doc,[string]$xpath){ $nl=$doc.SelectNodes($xpath); if($nl){$nl.Count}else{0} }

# GUID formatting to {GUID}
function Format-GuidB([object]$g) {
  $s = [string]$g
  if     ($s -match '^\{[0-9a-fA-F-]+\}$') { return $s }
  elseif ($s -match '^[0-9a-fA-F-]+$')     { return '{' + $s + '}' }
  else {
    try { return ([Guid]$s).ToString('B') } catch { return $s }
  }
}

# YAML helpers for current-user certs
function YamlEscape([string]$s){
  if ($null -eq $s) { return "''" }
  $s = $s -replace "(`r`n|`n|`r)", ' '
  $s = $s -replace '\s+', ' '
  return "'" + ($s -replace "'", "''") + "'"
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

# Preliminary findings helper
function Add-PrelimSection {
  param([string]$PrelimPath,[string]$Title,[string[]]$Lines)
  Add-Content -Path $PrelimPath -Value ("# "+$Title)
  if ($Lines) { $Lines | ForEach-Object { Add-Content -Path $PrelimPath -Value ("- "+$_) } }
  Add-Content -Path $PrelimPath -Value ""
}

# ---------- Setup ----------
$HostTag   = $env:COMPUTERNAME
$TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$RootName  = "${HostTag}_8021X_UserCollect_$TimeStamp"
$Root      = Join-Path (Get-Location) $RootName
New-Item -ItemType Directory -Force -Path $Root | Out-Null

$Prelim = Join-Path $Root ("{0}_preliminary_findings.txt" -f $HostTag)
"Preliminary findings (standard user) for $HostTag @ $TimeStamp" | Out-File $Prelim -Encoding UTF8
"" | Out-File $Prelim -Append

# ---------- Collection ----------
Run-Step "Collect OS & Build details" {
  Get-CimInstance Win32_OperatingSystem |
    Select-Object CSName, Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime |
    Format-List | Out-File (Join-Path $Root "os_info.txt")
  $ovf = Join-Path $Root "os_version_details.txt"
  $lines=@()
  $cur = Get-SafeItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
  if ($cur) {
    "DisplayVersion : $($cur.DisplayVersion)" | Out-File $ovf
    "ReleaseId      : $($cur.ReleaseId)"      | Out-File $ovf -Append
    "UBR (Patch)    : $($cur.UBR)"            | Out-File $ovf -Append
    "BuildLabEx     : $($cur.BuildLabEx)"     | Out-File $ovf -Append
    $lines += "Windows $($cur.DisplayVersion) (Build $($cur.CurrentBuild).$($cur.UBR))"
  } else {
    "Access denied or key missing." | Out-File $ovf
    $lines += "Could not read CurrentVersion registry."
  }
  Add-PrelimSection -PrelimPath $Prelim -Title "OS/Build" -Lines $lines
}

Run-Step "Ethernet adapters & readable IP details" {
  # Try Get-NetAdapter; fall back to CIM if unavailable
  $Eth = $null
  try {
    $Eth = Get-NetAdapter -Physical -ErrorAction Stop |
      Where-Object {
        ($_.InterfaceDescription -match 'Ethernet') -and
        ($_.InterfaceDescription -notmatch 'Wi-?Fi|Wireless|Bluetooth|Hyper-V|VMware|Virtual|Loopback|TAP|Npcap')
      } | Sort-Object ifIndex
  } catch {
    $Eth = Get-CimInstance Win32_NetworkAdapter -ErrorAction SilentlyContinue |
      Where-Object { $_.PhysicalAdapter -eq $true -and $_.Name -match 'Ethernet' } |
      Sort-Object InterfaceIndex
  }

  $ethFile = Join-Path $Root "netadapters_ethernet_only.txt"
  if ($Eth) {
    $Eth | Select-Object `
      @{n='IfIndex';e={($_.ifIndex, $_.InterfaceIndex | Where-Object {$_} | Select-Object -First 1)}},
      @{n='Name';e={$_.Name}},
      @{n='Description';e={$_.InterfaceDescription, $_.Description | Where-Object {$_} | Select-Object -First 1}},
      @{n='Status';e={$_.Status, $_.NetConnectionStatus | Where-Object {$_} | Select-Object -First 1}},
      @{n='MAC';e={$_.MacAddress, $_.MACAddress | Where-Object {$_} | Select-Object -First 1}} |
      Format-Table -Auto | Out-File $ethFile
  }

  # Human-readable IP summary (works for std user)
  $ipSummary = Join-Path $Root ("{0}_ip_ethernet_summary.txt" -f $HostTag)
  if ($Eth) {
    foreach ($a in $Eth) {
      $ifx = ($a.ifIndex, $a.InterfaceIndex | Where-Object {$_} | Select-Object -First 1)
      $name = ($a.Name, $a.NetConnectionID | Where-Object {$_} | Select-Object -First 1)
      $desc = ($a.InterfaceDescription, $a.Description | Where-Object {$_} | Select-Object -First 1)

      "=== $ifx : $name : $desc ===" | Out-File $ipSummary -Append

      # Prefer modern cmdlets; fall back to WMI
      $ip4 = $null; $ip6 = $null; $gw4=@(); $gw6=@(); $dns=@(); $dnsSuffix='-'; $dhcp4='-'
      try {
        $ip4 = Get-NetIPAddress -InterfaceIndex $ifx -AddressFamily IPv4 -ErrorAction SilentlyContinue | Sort-Object PrefixLength -Descending
        $ip6 = Get-NetIPAddress -InterfaceIndex $ifx -AddressFamily IPv6 -ErrorAction SilentlyContinue | Sort-Object PrefixLength -Descending
        $gw4 = Get-NetRoute -InterfaceIndex $ifx -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric, Metric | Select-Object -ExpandProperty NextHop -Unique
        $gw6 = Get-NetRoute -InterfaceIndex $ifx -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric, Metric | Select-Object -ExpandProperty NextHop -Unique
        $dns = Get-DnsClientServerAddress -InterfaceIndex $ifx -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | Select-Object -Unique
        $dnsSuffix = (Get-DnsClient -InterfaceIndex $ifx -ErrorAction SilentlyContinue).ConnectionSpecificSuffix
        $dhcp4 = (Get-NetIPInterface -InterfaceIndex $ifx -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp
      } catch {
        $cfg = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" -ErrorAction SilentlyContinue |
               Where-Object { $_.Index -eq $ifx -or $_.InterfaceIndex -eq $ifx }
        if ($cfg) {
          $ip4 = @(); if ($cfg.IPAddress) { $ip4 = @($cfg.IPAddress | Where-Object {$_ -match '^\d+\.'} | ForEach-Object { [pscustomobject]@{IPAddress=$_;PrefixLength=($cfg.IPSubnet | Select-Object -First 1)} }) }
          $ip6 = @(); if ($cfg.IPAddress) { $ip6 = @($cfg.IPAddress | Where-Object {$_ -match ':'}        | ForEach-Object { [pscustomobject]@{IPAddress=$_;PrefixLength=64} }) }
          $gw4 = @(); if ($cfg.DefaultIPGateway){ $gw4 = @($cfg.DefaultIPGateway | Where-Object {$_ -match '^\d+\.'}) }
          $gw6 = @(); if ($cfg.DefaultIPGateway){ $gw6 = @($cfg.DefaultIPGateway | Where-Object {$_ -match ':'}) }
          $dns = @(); if ($cfg.DNSServerSearchOrder){ $dns = $cfg.DNSServerSearchOrder }
          $dnsSuffix = ($cfg.DNSDomain, $cfg.DNSDomainSuffixSearchOrder | Where-Object {$_} | Select-Object -First 1)
          $dhcp4 = $(if($cfg.DHCPEnabled){'Enabled'}else{'Disabled'})
        }
      }

      "IPv4 Address(es): " + ($(if($ip4){ ($ip4 | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" }) -join ', ' } else { '-' })) | Out-File $ipSummary -Append
      "IPv6 Address(es): " + ($(if($ip6){ ($ip6 | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" }) -join ', ' } else { '-' })) | Out-File $ipSummary -Append
      "IPv4 Default GW: " + ($(if($gw4){ $gw4 -join ', ' } else { '-' })) | Out-File $ipSummary -Append
      "IPv6 Default GW: " + ($(if($gw6){ $gw6 -join ', ' } else { '-' })) | Out-File $ipSummary -Append
      "DNS Servers:     " + ($(if($dns){ $dns -join ', ' } else { '-' })) | Out-File $ipSummary -Append
      "DNS Suffix:      " + ($(if($dnsSuffix){ $dnsSuffix } else { '-' })) | Out-File $ipSummary -Append
      "DHCP (IPv4):     " + ($(if($dhcp4){ $dhcp4 } else { '-' })) | Out-File $ipSummary -Append
      "" | Out-File $ipSummary -Append
    }
  }

  & ipconfig /all > (Join-Path $Root ("{0}_ipconfig_all.txt" -f $HostTag))

  $up = 0; if ($Eth) { $up = ($Eth | Where-Object { $_.Status -eq 'Up' -or $_.NetConnectionStatus -eq 2 }).Count }
  Add-PrelimSection -PrelimPath $Prelim -Title "Ethernet adapters" -Lines @(
    ("Detected: {0}" -f ($Eth | Measure-Object).Count),
    ("Up: {0}" -f $up)
  )
}

Run-Step "netsh LAN snapshots (read-only) & best-effort profile export" {
  & netsh lan show settings    > (Join-Path $Root "netsh_lan_show_settings.txt")   2>&1
  & netsh lan show interfaces  > (Join-Path $Root "netsh_lan_show_interfaces.txt") 2>&1
  & netsh lan show profiles    > (Join-Path $Root "netsh_lan_show_profiles.txt")   2>&1

  $ProfDir = Join-Path $Root "lan_profiles"
  New-Item -ItemType Directory -Force -Path $ProfDir | Out-Null

  # Per-interface profile view (always works if interface exists)
  $ifNames = Select-String -Path (Join-Path $Root "netsh_lan_show_interfaces.txt") -Pattern "^\s*Name\s*:\s*(.+)$" |
             ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() } | Sort-Object -Unique
  foreach ($if in $ifNames) {
    $safe = ($if -replace '[\\/:*?""<>|]','_')
    & netsh lan show profile interface="$if" > (Join-Path $Root ("netsh_lan_show_profile_{0}.txt" -f $safe)) 2>&1
  }

  # Best-effort XML export (may fail for std user; that's OK)
  $xmlLog = Join-Path $ProfDir "export_log.txt"
  try {
    & netsh lan export profile folder="$ProfDir" > $xmlLog 2>&1
  } catch {
    "netsh export not permitted for standard user." | Out-File $xmlLog
  }

  # Parse any exported XML we did get
  $sum = Join-Path $Root "lan_profiles_summary.txt"
  $total=0; $withEap=0; $outerCounts=@{}; $innerCounts=@{}; $serverNames=@(); $rootSum=0

  Get-ChildItem $ProfDir -Filter *.xml -ErrorAction SilentlyContinue | ForEach-Object {
    $total++
    "=== $($_.Name) ===" | Out-File $sum -Append
    try{
      [xml]$x = Get-Content $_.FullName -Raw
      $has = $x.SelectSingleNode("//*[local-name()='EapHostConfig']")
      if (-not $has) { "No EapHostConfig section found.`n" | Out-File $sum -Append; return }
      $withEap++

      $outer = Get-NodeText $x "//*[local-name()='EapHostConfig']/*[local-name()='EapMethod']/*[local-name()='Type']"
      if ($outer) { if ($outerCounts.ContainsKey($outer)){$outerCounts[$outer]++}else{$outerCounts[$outer]=1} }
      "Outer EAP type: $outer" | Out-File $sum -Append

      $inner = Get-NodeText $x "//*[local-name()='EapHostConfig']/*[local-name()='Config']//*[local-name()='Eap']//*[local-name()='Type']"
      if (-not $inner) { $inner = Get-NodeText $x "//*[local-name()='EapHostConfig']/*[local-name()='Config']//*[local-name()='Eap']/*[local-name()='Eap']//*[local-name()='Type']" }
      if ($inner) { if ($innerCounts.ContainsKey($inner)){$innerCounts[$inner]++}else{$innerCounts[$inner]=1} }
      "Inner EAP type: $inner" | Out-File $sum -Append

      $srvPaths = @(
        "//*[local-name()='EapHostConfig']/*[local-name()='Config']//*[local-name()='EapTls']/*[local-name()='ServerValidation']",
        "//*[local-name()='EapHostConfig']/*[local-name()='Config']//*[local-name()='Ttls']/*[local-name()='ServerValidation']"
      )
      $names=$null; $rootCount=0
      foreach ($p in $srvPaths) {
        if (-not $names)     { $names     = Get-NodeText $x ($p+"/*[local-name()='ServerNames']") }
        if ($rootCount -eq 0){ $rootCount = Count-Nodes $x ($p+"/*[local-name']='TrustedRootCA']/*") }
      }
      # fix typo
      $rootCount = Count-Nodes $x "//*[local-name()='TrustedRootCA']/*" | ForEach-Object {$_} | Select-Object -First 1
      if ($names) { "Server names: $names" | Out-File $sum -Append; $serverNames += $names }
      "TrustedRootCA items: $rootCount`n" | Out-File $sum -Append
      if ($rootCount) { $rootSum += $rootCount }

    } catch { "Parse error: $($_.Exception.Message)`n" | Out-File $sum -Append }
  }

  $outerStr = if($outerCounts.Keys.Count){ ($outerCounts.Keys | ForEach-Object { "$_=$($outerCounts[$_])" }) -join ', ' } else { '-' }
  $innerStr = if($innerCounts.Keys.Count){ ($innerCounts.Keys | ForEach-Object { "$_=$($innerCounts[$_])" }) -join ', ' } else { '-' }
  $namesStr = if($serverNames){ ($serverNames | Select-Object -Unique) -join ', ' } else { '-' }

  Add-PrelimSection -PrelimPath $Prelim -Title "Wired profiles (best-effort XML parse)" -Lines @(
    ("Exported XML files: {0}, with EapHostConfig: {1}" -f $total,$withEap),
    ("Outer EAP types: {0}" -f $outerStr),
    ("Inner EAP types: {0}" -f $innerStr),
    ("ServerNames (union): {0}" -f $namesStr),
    ("Total TrustedRootCA references (sum): {0}" -f $rootSum)
  )
}

Run-Step "EAPHost methods inventory (read-only)" {
  $eapOut = Join-Path $Root "eaphost_methods.txt"
  if (Test-Path "HKLM:\SOFTWARE\Microsoft\EapHost\Methods") {
    try {
      Get-ChildItem "HKLM:\SOFTWARE\Microsoft\EapHost\Methods" -ErrorAction Stop |
        ForEach-Object {
          "Method key: $($_.PSChildName)" | Out-File $eapOut -Append
          try {
            Get-ChildItem $_.PSPath | ForEach-Object { "  Subkey: $($_.PSChildName)" | Out-File $eapOut -Append }
          } catch {}
        }
      Add-PrelimSection -PrelimPath $Prelim -Title "EAPHost methods" -Lines @("See eaphost_methods.txt (verify TEAP/TLS present)")
    } catch {
      Add-PrelimSection -PrelimPath $Prelim -Title "EAPHost methods" -Lines @("Access denied reading registry.")
    }
  } else {
    Add-PrelimSection -PrelimPath $Prelim -Title "EAPHost methods" -Lines @("Methods key not present.")
  }
}

Run-Step "Event summaries (last $Hours h): Wired-AutoConfig & EapHost" {
  $start = (Get-Date).AddHours(-1 * $Hours)
  $waTxt = Join-Path $Root "Wired-AutoConfig-last${Hours}h.txt"
  $ehTxt = Join-Path $Root "EapHost-last${Hours}h.txt"

  try {
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Wired-AutoConfig/Operational'; StartTime=$start} -ErrorAction Stop |
      Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
      Sort-Object TimeCreated -Descending |
      Out-File $waTxt -Width 500
  } catch { "Access denied or log unavailable." | Out-File $waTxt }

  try {
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-EapHost/Operational'; StartTime=$start} -ErrorAction Stop |
      Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
      Sort-Object TimeCreated -Descending |
      Out-File $ehTxt -Width 500
  } catch { "Access denied or log unavailable." | Out-File $ehTxt }

  function CountLvl($log,$lvl){
    try { (Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$start; Level=$lvl} -ErrorAction Stop).Count } catch { 0 }
  }
  function TopIDs($log){
    try {
      $ids = Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$start} -ErrorAction Stop | Select-Object -ExpandProperty Id
      if($ids){ ($ids | Group-Object | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "{0} (x{1})" -f $_.Name,$_.Count }) -join ', ' } else { '-' }
    } catch { '-' }
  }

  $waErr = CountLvl 'Microsoft-Windows-Wired-AutoConfig/Operational' 2
  $waWrn = CountLvl 'Microsoft-Windows-Wired-AutoConfig/Operational' 3
  $ehErr = CountLvl 'Microsoft-Windows-EapHost/Operational' 2
  $ehWrn = CountLvl 'Microsoft-Windows-EapHost/Operational' 3
  $waTop = TopIDs 'Microsoft-Windows-Wired-AutoConfig/Operational'
  $ehTop = TopIDs 'Microsoft-Windows-EapHost/Operational'

  Add-PrelimSection -PrelimPath $Prelim -Title "Event logs (last $Hours h)" -Lines @(
    ("Wired-AutoConfig: Errors={0}, Warnings={1}, Top IDs: {2}" -f $waErr,$waWrn,$waTop),
    ("EapHost:          Errors={0}, Warnings={1}, Top IDs: {2}" -f $ehErr,$ehWrn,$ehTop)
  )
}

Run-Step "Current user's Personal certs (HKCU\My) -> YAML" {
  $cuRoot = Join-Path $Root "CurrentUser_Personal"
  New-Item -ItemType Directory -Force -Path $cuRoot | Out-Null
  $yaml = Join-Path $cuRoot ("{0}_CurrentUser_My.yaml" -f $HostTag)

  $rows=@()
  if(Test-Path 'Cert:\CurrentUser\My'){
    Get-ChildItem 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue | ForEach-Object {
      $rows += [pscustomobject]@{
        UserName        = $env:USERDOMAIN + "\" + $env:USERNAME
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

  # Emit YAML list
  $sb = New-Object System.Text.StringBuilder
  foreach ($it in $rows) {
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
  Set-Content -Path $yaml -Value $sb.ToString() -Encoding UTF8

  # Tiny stats into prelim
  if ($rows.Count) {
    $client = ($rows | Where-Object { $_.IntendedPurposes -contains 'Client Authentication' }).Count
    $minExp = ($rows | Sort-Object Expiration | Select-Object -First 1).Expiration
    Add-PrelimSection -PrelimPath $Prelim -Title "Current user certs" -Lines @(
      ("Total: {0}" -f $rows.Count),
      ("Client Authentication: {0}" -f $client),
      ("Nearest expiry: {0:o}" -f $minExp)
    )
  } else {
    Add-PrelimSection -PrelimPath $Prelim -Title "Current user certs" -Lines @("No certs in CurrentUser\My")
  }
}

# ---------- Zip ----------
Run-Step "Create ZIP archive" {
  $zipPath = Join-Path (Get-Location) ("{0}.zip" -f $RootName)
  Compress-Archive -Path $Root -DestinationPath $zipPath -Force
  Write-Host "Archive created: $zipPath"
}
Write-Host "`nCollection complete. Folder: $Root"
