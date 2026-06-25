' ===========================================================================
'  run-hidden.vbs
'  Hidden launcher for the "RamOptimizer" scheduled task. Runs one headless
'  ram-optimizer.exe pass (--once) with NO console window (no flash), fire-and-forget.
'  The --once flag is required: a bare ram-optimizer.exe opens the dashboard, so the
'  scheduled task must pass it to stay windowless.
'  Path-independent: resolves the repo root from this script's location.
'  Output is appended to %USERPROFILE%\.ram-optimizer\cron.log.
' ===========================================================================
Option Explicit

Dim shell, fso, here, root, exe, cmd
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

here = fso.GetParentFolderName(WScript.ScriptFullName)   ' ...\scripts
root = fso.GetParentFolderName(here)                      ' repo root

exe = root & "\target\release\ram-optimizer.exe"
If Not fso.FileExists(exe) Then exe = root & "\target\debug\ram-optimizer.exe"

cmd = "cmd /c cd /d """ & root & """ && """ & exe & """ --once " & _
      ">> ""%USERPROFILE%\.ram-optimizer\cron.log"" 2>&1"

' Style 0 = hidden window; False = return immediately (fire-and-forget).
shell.Run cmd, 0, False
