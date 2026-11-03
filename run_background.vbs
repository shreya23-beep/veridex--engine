Set WshShell = CreateObject("WScript.Shell")
scriptDir = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = scriptDir

' Launch Floating Overlay Companion silently with pythonw (no console window)
WshShell.Run "pythonw.exe run_floating_overlay.py", 0, False

' Launch Web Cyber-Dashboard server silently with pythonw
WshShell.Run "pythonw.exe run_web_dashboard.py", 0, False
