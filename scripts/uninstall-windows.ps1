# uninstall-windows.ps1 — removes the RamOptimizer scheduled task. Self-elevates.
$ErrorActionPreference = 'SilentlyContinue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList @(
        '-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
    exit
}
Unregister-ScheduledTask -TaskName 'RamOptimizer' -Confirm:$false
Write-Host "RamOptimizer task removed."
Start-Sleep 2
