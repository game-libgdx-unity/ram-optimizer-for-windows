# install-windows.ps1
# Registers the "RamOptimizer" scheduled task: runs the native binary every
# N minutes, hidden (no console flash), via run-hidden.vbs.
#
# By DEFAULT this creates a per-user task that needs NO admin — so the dashboard
# (which runs non-elevated) can Start/Stop/retime it from the Schedule tab. Pass
# -Elevated to register an admin (RunLevel Highest) task instead; note that the
# non-elevated dashboard then CANNOT change its schedule ("Access is denied").
#
# Build FIRST as your normal (non-elevated) user:
#     cargo build --release
#     powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1

param([int]$IntervalMinutes = 5, [switch]$Elevated)
$ErrorActionPreference = 'Stop'

# Only the -Elevated install needs admin; the default per-user task does not.
if ($Elevated) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "Requesting administrator rights (UAC) for -Elevated install..."
        Start-Process powershell.exe -Verb RunAs -ArgumentList @(
            '-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"",
            '-IntervalMinutes',"$IntervalMinutes",'-Elevated'
        )
        exit
    }
}

$root = Split-Path -Parent $PSScriptRoot
$vbs  = Join-Path $PSScriptRoot 'run-hidden.vbs'

$cfg = Join-Path $root 'config.json'
if (-not (Test-Path $cfg)) {
    Copy-Item (Join-Path $root 'config.example.json') $cfg
    Write-Host "Created $cfg"
}

$exe = Join-Path $root 'target\release\ram-optimizer.exe'
if (-not (Test-Path $exe)) {
    Write-Warning "Release binary missing: $exe"
    Write-Host    "Build it first (normal user):  cargo build --release"
    Write-Host    "Registering the task anyway; it works once the binary exists."
}

$taskName  = 'RamOptimizer'
$action    = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument "`"$vbs`""
$trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date)
$trigger.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) `
                -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)).Repetition
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
$runLevel  = if ($Elevated) { 'Highest' } else { 'Limited' }
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel $runLevel

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings `
    -Principal $principal -Description "RAM Optimizer monitor (every $IntervalMinutes min)" -Force | Out-Null

Write-Host ("Registered '{0}' (every {1} min, RunLevel {2})." -f $taskName, $IntervalMinutes, $runLevel)
if ($Elevated) {
    Write-Host "Note: -Elevated task is admin-owned; the non-elevated dashboard can't change its schedule."
}
Write-Host ("Dashboard:  {0} ui" -f $exe)
