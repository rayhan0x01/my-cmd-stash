#### smb enum with nmap, will display target path too 
```bash
nmap --script smb-enum-shares.nse -p445 <TARGET-IP>
```

#### list share with anonymous login [anonymous login/blank pass]:
```bash
smbclient -L\\ -N -I <TARGET-IP>
```
#### enable directory acl listing and find writable directory for anonymous user
```bash
smbclient -L\\ -N -I <TARGET-IP> # connect
smb: \> showacls # enable acl listing
smb: \> dir # list directories with acls
#### now look for SID: S-1-1-0 which has WRITE_OWNER_ACCESS and WRITE_DAC_ACCESS permissions
```

#### list shares with their permissions [anonymous login]:
```bash
smbmap -H <TARGET-IP>
```

#### list shares with their permissions [guest login]:
```bash
smbmap -u DoesNotExists -H <TARGET-IP>
```

#### mount a share on local machine
```bash
#### create mount directory first
sudo mount -t cifs //10.10.10.134/SHARENAME ~/path/to/mount_directory
```

#### list shares with their permissions [with user login]:
```bash
smbmap -u USERNAME -p PASSWORD -d DOMAIN.TLD -H <TARGET-IP>
```

#### recursively list shares with their permission:
```bash
smbmap -R -H <TARGET-IP>
smbmap -R Replication -H <TARGET-IP>

or with smbclient (recurse downloads all files)

smbclient //<TARGET-IP>/Replication
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```

#### recursively look for a filename pattern and download if match found:
```bash
smbmap -R Replication -A Groups.xml -H <TARGET-IP> -q
```

#### download a file from share
```bash
smbmap -H <TARGET-IP> --download 'Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml'

*** in older smbmap file may be saved in /usr/share/smbmap
```

#### upload a file to share
```bash
smbmap -H <TARGET-IP> --upload test.txt SHARENAME/test.txt 
```