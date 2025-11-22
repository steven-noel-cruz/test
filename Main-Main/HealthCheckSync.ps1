<#
Deploy HealthCheckSync.ps1 to a remote lab host and register a DAILY task.
Benign names:
 - Script on remote:  C:\ProgramData\Corp\Ops\HealthCheckSync.ps1
 - Scheduled task:    System Health Telemetry
 - Log file:          C:\ProgramData\Corp\Ops\health_sync.log
#>

# --- CONFIG: set local path to your HealthCheckSync.ps1 ---
$LocalScriptPath = "C:\Local\HealthCheckSync.ps1"   # <- change if stored elsewhere

# Prompt for target + creds
$RemoteHost = Read-Host "Remote host (name or IP)"
$Cred       = Get-Credential -Message "Enter lab admin creds for $RemoteHost"

# Benign names / remote locations
$TaskName         = "System Health Telemetry"
$RemoteBase       = "C:\ProgramData\Corp\Ops"
$RemoteScriptPath = Join-Path $RemoteBase "HealthCheckSync.ps1"
$RemoteLogPath    = Join-Path $RemoteBase "health_sync.log"

# Daily schedule (remote host local time)
$DailyAt        = "10:00"   # HH:mm
$RandomDelayMin = 5         # 0 = no jitter

if (-not (Test-Path $LocalScriptPath)) { throw "Local script not found: $LocalScriptPath" }

# Ensure remote dirs
Invoke-Command -ComputerName $RemoteHost -Credential $Cred -ScriptBlock {
  param($base)
  if (-not (Test-Path $base)) { New-Item -Path $base -ItemType Directory -Force | Out-Null }
  $staging = Join-Path $base "staging"
  if (-not (Test-Path $staging)) { New-Item -Path $staging -ItemType Directory -Force | Out-Null }
} -ArgumentList $RemoteBase

# Copy script (SMB first, fallback to WinRM)
$copied = $false
try {
  $dest = "\\$RemoteHost\C$\ProgramData\Corp\Ops\HealthCheckSync.ps1"
  Copy-Item -Path $LocalScriptPath -Destination $dest -Force -ErrorAction Stop
  Write-Host "Copied via SMB -> $dest" -ForegroundColor Green
  $copied = $true
} catch {
  Write-Warning "SMB copy failed; falling back to WinRM content write."
}
if (-not $copied) {
  $content = Get-Content -Path $LocalScriptPath -Raw -ErrorAction Stop
  Invoke-Command -ComputerName $RemoteHost -Credential $Cred -ScriptBlock {
    param($path,$text)
    $dir = Split-Path $path -Parent
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    Set-Content -Path $path -Value $text -Encoding UTF8 -Force
  } -ArgumentList $RemoteScriptPath,$content
  Write-Host "Wrote script via WinRM -> $RemoteScriptPath" -ForegroundColor Green
}

# Build schedule time
$parts  = $DailyAt -split ":", 2
$hour   = [int]$parts[0]; $minute = [int]$parts[1]
$runAt  = (Get-Date).Date.AddHours($hour).AddMinutes($minute)

# Register DAILY task (Highest), benign name/desc
Invoke-Command -ComputerName $RemoteHost -Credential $Cred -ScriptBlock {
  param($tn,$scriptPath,$runAt,$randMin,$userName)
  $action   = New-ScheduledTaskAction -Execute "PowerShell.exe" `
              -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
  if ($randMin -gt 0) {
    $trigger = New-ScheduledTaskTrigger -Daily -At $runAt -RandomDelay (New-TimeSpan -Minutes $randMin)
  } else {
    $trigger = New-ScheduledTaskTrigger -Daily -At $runAt
  }
  $principal = New-ScheduledTaskPrincipal -UserId $userName -LogonType S4U -RunLevel Highest
  $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName $tn -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Description "Periodic system health telemetry" -Force | Out-Null
} -ArgumentList $TaskName, $RemoteScriptPath, $runAt, $RandomDelayMin, $Cred.UserName
Write-Host "Registered '$TaskName' (daily at $DailyAt, jitter up to $RandomDelayMin min)." -ForegroundColor Green

# Kick an immediate run
Invoke-Command -ComputerName $RemoteHost -Credential $Cred -ScriptBlock { param($tn) Start-ScheduledTask -TaskName $tn } -ArgumentList $TaskName
Write-Host "Started task once immediately." -ForegroundColor Green

# Tail benign log
Write-Host "`nTailing $RemoteLogPath for 20s..." -ForegroundColor Cyan
$end = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $end) {
  try {
    $lines = Invoke-Command -ComputerName $RemoteHost -Credential $Cred -ScriptBlock {
      param($p) if (Test-Path $p) { Get-Content -Path $p -Tail 20 -ErrorAction SilentlyContinue } else { "" }
    } -ArgumentList $RemoteLogPath
    if ($lines) { $lines | ForEach-Object { Write-Host $_ } }
  } catch {}
  Start-Sleep -Seconds 2
}

Write-Host "`nDone. Task '$TaskName' runs daily; script '$RemoteScriptPath' writes '$RemoteLogPath'." -ForegroundColor Yellow
