Option Explicit
Dim fso, shell, wmi, rows, row, version, sp, count, root, setup, result
Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")
On Error Resume Next
Set wmi = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
Set rows = wmi.ExecQuery("SELECT Version,ServicePackMajorVersion FROM Win32_OperatingSystem")
If Err.Number <> 0 Then
    WScript.Echo "Cannot verify Windows. Nothing was installed."
    WScript.Quit 3
End If
version = ""
sp = 0
For Each row In rows
    version = row.Version
    sp = row.ServicePackMajorVersion
Next
If Err.Number <> 0 Or Left(version, 4) <> "5.1." Or sp < 3 Then
    WScript.Echo "This candidate is only for Windows XP 32-bit SP3. Nothing was installed."
    WScript.Quit 3
End If
Set rows = wmi.ExecQuery("SELECT DeviceID FROM Win32_PnPEntity WHERE DeviceID LIKE 'PCI%VEN_10DE&DEV_1C31%'")
If Err.Number <> 0 Then WScript.Quit 4
count = 0
For Each row In rows
    count = count + 1
Next
If Err.Number <> 0 Or count <> 1 Then
    WScript.Echo "Expected exactly one P2200 (10DE:1C31). Nothing was installed."
    WScript.Quit 4
End If
On Error GoTo 0
root = fso.GetParentFolderName(WScript.ScriptFullName)
If fso.FileExists(fso.BuildPath(root, "BUILD-FAILED.txt")) Or Not fso.FileExists(fso.BuildPath(root, "BUILD-REPORT.json")) Then
    WScript.Echo "A completed rebuild report is required beside this launcher."
    WScript.Quit 5
End If
setup = fso.BuildPath(root, "XP-payload\setup.exe")
If Not fso.FileExists(setup) Then WScript.Quit 5
WScript.Echo "Opening P2200 Driver 72 Clean RC1 setup. Use Express, then reboot."
result = shell.Run(Chr(34) & setup & Chr(34), 1, True)
WScript.Quit result
