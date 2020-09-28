
## list naming Contexts 
```bash
ldapsearch -h 10.10.10.161 -x -s base namingContexts

# output
...
...
dn:
namingContexts: DC=htb,DC=local
namingContexts: CN=Configuration,DC=htb,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=htb,DC=local
...
...
```
## search a base and show structures and data 
```bash
ldapsearch -h 10.10.10.161 -x -b "DC=htb,DC=local"
```

## filter an object class from base data
```bash
ldapsearch -h 10.10.10.161 -x -b "DC=htb,DC=local" '(ObjectClass=User)'

```

## list all user accounts # will miss service accounts
```bash
ldapsearch -h 10.10.10.161 -x -b "DC=htb,DC=local" '(ObjectClass=User)' sAMAccountName | grep sAMAccountName | sed 's/.*: //g'

```