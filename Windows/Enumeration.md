
# Windows Initial Checks
## Basic Info
```
hostname
systeminfo
systeminfo | findstr /b /C:"OS Name" /C"OS Version"
whoami
```
## Network Info
### Network Details
```
ipconfig /all  
route print  
arp -A  
netstat -ano
```
### Firewall  
```
netsh firewall show state  
netsh firewall show config  
netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all
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
#  CVEs
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
#  Sensitive data
## Show Unmounted Disks
```
mountvol

mountvol c:\\test \\\?\\Volume{93131ba8-0000-0000-0000-100000000000}\
```
## Passwords reuse
https://pentestlab.blog/tag/privilege-escalation/page/3/  
### cmdkey
\*If there are entries, it means that we may able to runas certain user who stored his cred in windows\* 
```
cmdkey /list 
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
### Raw text search
```
reg query HKLM /f password /t REG_SZ /s  
reg query HKCU /f password /t REG_SZ /s  
```
#  Misconfigurations 
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

