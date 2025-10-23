<#
Test-PerHopMtu.ps1
------------------
Purpose:
  - Perform a traceroute (fast, no name lookups) to a given IPv4 target,
    extract the responding hop IPs, and perform DF-bit (Don't Fragment)
    ICMP probes (binary-search) to estimate the largest payload that
    succeeds to each hop. From that value the script computes an
    estimated Path MTU (PayloadOK + 28 bytes for IPv4).
  - Also measures simple RTT/loss/jitter baselines per hop (ping).
  - Useful for validating MTU issues or fragmentation points along the
    path before escalating to your ISP (attach CSV output + traceroute).

Key notes:
  - This script is compatible with Windows PowerShell 5.x and PowerShell 7+.
  - Uses tracert -d -w 1000 to avoid reverse DNS delays (fast).
  - Some routers drop ICMP or drop DF-packets; those hops will be marked
    as "No ICMP / filtered" or "DF blocked or timed out".
  - Path MTU estimate = PayloadOK + 28 (20 byte IPv4 header + 8 byte ICMP).
  - The destination hop (target) is always included if resolvable.
  - The script does not attempt to alter system MTU. It only probes.

Parameters:
  -Target <string>           (Required)
      IP address or hostname to run the traceroute / MTU tests against.
      Example: 13.107.136.10 or navitas.sharepoint.com

  -MaxPayload <int>
      The maximum ICMP payload to attempt during DF testing.
      Default 1472 (1500 MTU -> 1472 payload). Increase if you expect
      jumbo frames (e.g., set to 8972 for ~9000 MTU testing).

  -TimeoutMs <int>
      Timeout per ping in milliseconds (used by DF probes and reachability).
      Default 2000 (2 seconds). Lower to speed up noisy traces, but risk
      false negatives on very high-latency links.

  -Retries <int>
      Number of retry attempts per DF probe size to avoid transient loss
      giving false negatives. Default 2.

  -IncludeUnresolvedHops (switch)
      When set, script will include '*' hops (where tracert shows no IP)
      as informational rows in the output (TargetIP = "<no reply>").

  -CsvPath <string>
      Optional file path to save results as CSV for ticketing/escalation.
      Example: -CsvPath C:\Temp\perhop_mtu.csv

Output:
  - A single formatted table showing one row per hop with these columns:
      Hop, TargetIP, Responded, PayloadOK, PathMTU, AvgRttMs, JitterMs, LossPct, Notes
  - If -CsvPath is provided, a CSV file is written with the same fields.
  - The script prints concise warning messages for unreachable/unresponsive hops.

Interpretation guidelines:
  - PayloadOK = largest ICMP payload (bytes) that succeeded with DF=1
  - PathMTU = PayloadOK + 28
  - If PathMTU < (MaxPayload + 28) at hop N and subsequent hops show same
    lower PathMTU, that indicates the MTU reduction occurs no later than
    hop N (useful evidence for ISP escalation).
  - If many hops show "No ICMP / filtered", you can still include the
    table in your ticket; focus on the last responding hop before the
    non-responsive region and the destination.

Example usage:
  # Basic test to Microsoft front door anycast IP
  .\Test-PerHopMtu.ps1 -Target 13.107.136.10

  # Include unresolved hops and export CSV for ISP
  .\Test-PerHopMtu.ps1 -Target 13.107.136.10 -IncludeUnresolvedHops -CsvPath C:\Temp\perhop_mtu.csv

  # Test with larger payload ceiling (if you expect non-1500 MTU)
  .\Test-PerHopMtu.ps1 -Target 13.107.136.10 -MaxPayload 8972 -CsvPath C:\Temp\jumbo_check.csv

Troubleshooting tips:
  - If you see "No hops found" or no output, ensure your local host can run tracert
    and has IP connectivity to the target; try plain: tracert -d -w 1000 <target>
  - If many hops show "No ICMP / filtered", ask ISP to run an internal test or
    provide mirrored traceroute from their edge — some providers filter ICMP.
  - Combine this output with:
     * traceroute -d -w 1000 <target> (paste raw output)
     * ping -n 100 <target> (loss/jitter baseline)
     * HAR file capturing the slow download (download.aspx entry) for application-layer proof.
  - Attach both the CSV and raw tracert to your ISP ticket; they can correlate the MTU drop
    and where the DF probes fail.

# End of comment block
#>


param(
  [Parameter(Mandatory = $true)][string]$Target,
  [int]$MaxPayload = 1472,     # 1500 MTU -> 1472 payload
  [int]$TimeoutMs  = 2000,     # per ping timeout (ms)
  [int]$Retries    = 2,        # retries per DF size
  [switch]$IncludeUnresolvedHops,
  [string]$CsvPath
)

function Test-DFPing {
  param([string]$Dest, [int]$Payload, [int]$TimeoutMs, [int]$Retries)
  for ($i = 0; $i -le $Retries; $i++) {
    $out = (ping $Dest -f -l $Payload -n 1 -w $TimeoutMs 2>$null | Out-String)
    if ($out -match "bytes=" -and $out -notmatch "fragmented" -and $out -notmatch "timed out") {
      return @{ Success = $true; Raw = $out }
    }
  }
  return @{ Success = $false; Raw = $out }
}

function Find-PayloadMax {
  param([string]$Dest, [int]$MaxPayload, [int]$TimeoutMs, [int]$Retries)
  $low = 0; $high = $MaxPayload; $lastGood = -1
  while ($low -le $high) {
    $mid = [int](($low + $high)/2)
    $r = Test-DFPing -Dest $Dest -Payload $mid -TimeoutMs $TimeoutMs -Retries $Retries
    if ($r.Success) { $lastGood = $mid; $low = $mid + 1 } else { $high = $mid - 1 }
  }
  return $lastGood
}

function Measure-RTT {
  param([string]$Dest, [int]$Count = 5, [int]$TimeoutMs = 1000)
  $out = (ping $Dest -n $Count -w $TimeoutMs 2>$null | Out-String)
  $avg = $null; $min = $null; $max = $null; $jitter = $null; $lossPct = $null
  if ($out -match "Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms") {
    $min = [int]$Matches[1]; $max = [int]$Matches[2]; $avg = [int]$Matches[3]; $jitter = $max - $min
  }
  if ($out -match "Lost = \d+ \((\d+)% loss\)") { $lossPct = [int]$Matches[1] }
  return [pscustomobject]@{ AvgMs = $avg; JitterMs = $jitter; LossPct = $lossPct }
}

Write-Host "`n=== Traceroute (ICMP) to $Target ===`n"
$traceLines = tracert -d -w 1000 $Target | ForEach-Object { $_ }

# Extract hop index + IP (if any). Works with "<1 ms" columns, etc.
$hopObjs = @()
foreach ($line in $traceLines) {
  # Match: hop number + ... + IPv4 address somewhere later on the line
  $m = [regex]::Match($line, '^\s*(\d+)\s+.*?((\d{1,3}\.){3}\d{1,3})')
  if ($m.Success) {
    $idx = [int]$m.Groups[1].Value
    $ip  = $m.Groups[2].Value
    $hopObjs += [pscustomobject]@{ Hop = $idx; IP = $ip; Responded = $true }
  } elseif ($IncludeUnresolvedHops -and $line -match '^\s*(\d+)\s+\*') {
    # Lines with '*' timeouts but no IP
    $hopObjs += [pscustomobject]@{ Hop = [int]$Matches[1]; IP = $null; Responded = $false }
  }
}

if (-not $hopObjs) {
  Write-Warning "No hops found."
  return
}


# Ensure destination IP is included if Target is a hostname
$destIP = $null
try { [void][System.Net.IPAddress]::Parse($Target); $destIP = $Target } catch {
  try { $res = Resolve-DnsName -Name $Target -Type A -ErrorAction Stop | Select-Object -First 1
        if ($res -and $res.IPAddress) { $destIP = $res.IPAddress } } catch {}
}
if ($destIP) {
  $exists = $false; foreach ($h in $hopObjs) { if ($h.IP -eq $destIP) { $exists = $true; break } }
  if (-not $exists) {
    $maxHop = ($hopObjs | Measure-Object -Property Hop -Maximum).Maximum
    $hopObjs += [pscustomobject]@{ Hop = ($maxHop + 1); IP = $destIP; Responded = $true }
  }
}

$results = @()
foreach ($h in ($hopObjs | Sort-Object Hop)) {
  if (-not $h.Responded -or -not $h.IP) {
    $results += [pscustomobject]@{
      Hop       = $h.Hop
      TargetIP  = (if ($h.IP) { $h.IP } else { "<no reply>" })
      Responded = $false
      PayloadOK = $null
      PathMTU   = $null
      AvgRttMs  = $null
      JitterMs  = $null
      LossPct   = $null
      Notes     = "No ICMP / filtered"
    }
    continue
  }

  # Basic reachability
  $reach = (ping $h.IP -n 1 -w $TimeoutMs 2>$null | Out-String)
  if ($reach -notmatch "bytes=") {
    $results += [pscustomobject]@{
      Hop       = $h.Hop
      TargetIP  = $h.IP
      Responded = $false
      PayloadOK = $null
      PathMTU   = $null
      AvgRttMs  = $null
      JitterMs  = $null
      LossPct   = $null
      Notes     = "No ICMP echo reply"
    }
    continue
  }

  $rtt = Measure-RTT -Dest $h.IP -Count 5 -TimeoutMs ([Math]::Min($TimeoutMs, 1000))
  $pOK = Find-PayloadMax -Dest $h.IP -MaxPayload $MaxPayload -TimeoutMs $TimeoutMs -Retries $Retries

  $payloadOkValue = $null
  $pathMtuValue   = $null
  $note           = "OK"
  if ($pOK -ge 0) {
    $payloadOkValue = $pOK
    $pathMtuValue   = $pOK + 28
    if ($pathMtuValue -lt ($MaxPayload + 28)) { $note = "MTU drop on/after this hop" }
  } else {
    $note = "DF blocked or timed out"
  }

  $results += [pscustomobject]@{
    Hop       = $h.Hop
    TargetIP  = $h.IP
    Responded = $true
    PayloadOK = $payloadOkValue
    PathMTU   = $pathMtuValue
    AvgRttMs  = $rtt.AvgMs
    JitterMs  = $rtt.JitterMs
    LossPct   = $rtt.LossPct
    Notes     = $note
  }
}

$results | Format-Table -AutoSize
if ($CsvPath) { $results | Export-Csv -NoTypeInformation -Path $CsvPath -Encoding UTF8 }
