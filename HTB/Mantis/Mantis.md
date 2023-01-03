Nmap --> Keberos Users brute force with kerbrute --> mssql investigation with impacket-mssqlclient, mssql gui-tool with dbeaver, User credential --> MS14-068 Kerberoasting

What I learned from this case. 


`https://wizard32.net/blog/knock-and-pass-kerberos-exploitation.html`

## Port scanning
```
# Nmap 7.92 scan initiated Tue Dec  6 15:12:40 2022 as: nmap -sC -sV -p- -oN all.nmap 10.10.10.52
Nmap scan report for mantis.htb (10.10.10.52)
Host is up (0.055s latency).
Not shown: 65508 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Microsoft DNS 6.1.7601 (1DB15CD4) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15CD4)
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2022-12-06 20:13:28Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2008 R2 Standard 7601 Service Pack 1 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1337/tcp  open  http         Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000.00; RTM
|_ssl-date: 2022-12-06T20:14:33+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2022-12-06T20:08:20
|_Not valid after:  2052-12-06T20:08:20
| ms-sql-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: MANTIS
|   DNS_Domain_Name: htb.local
|   DNS_Computer_Name: mantis.htb.local
|   DNS_Tree_Name: htb.local
|_  Product_Version: 6.1.7601
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc        Microsoft Windows RPC
8080/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Tossed Salad - Blog
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc        Microsoft Windows RPC
49161/tcp open  msrpc        Microsoft Windows RPC
49169/tcp open  msrpc        Microsoft Windows RPC
50255/tcp open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000
|_ssl-date: 2022-12-06T20:14:33+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2022-12-06T20:08:20
|_Not valid after:  2052-12-06T20:08:20
| ms-sql-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: MANTIS
|   DNS_Domain_Name: htb.local
|   DNS_Computer_Name: mantis.htb.local
|   DNS_Tree_Name: htb.local
|_  Product_Version: 6.1.7601
51664/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: MANTIS; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time: 
|   date: 2022-12-06T20:14:26
|_  start_date: 2022-12-06T20:08:11
|_clock-skew: mean: 42m51s, deviation: 1h53m23s, median: 0s
| ms-sql-info: 
|   10.10.10.52:1433: 
|     Version: 
|       name: Microsoft SQL Server 2014 RTM
|       number: 12.00.2000.00
|       Product: Microsoft SQL Server 2014
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb-os-discovery: 
|   OS: Windows Server 2008 R2 Standard 7601 Service Pack 1 (Windows Server 2008 R2 Standard 6.1)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: mantis
|   NetBIOS computer name: MANTIS\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: mantis.htb.local
|_  System time: 2022-12-06T15:14:24-05:00
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Dec  6 15:14:35 2022 -- 1 IP address (1 host up) scanned in 114.78 seconds

```


```

┌──(kali㉿kali)-[~/…/mantis/github/kerbrute/dist]
└─$ ./kerbrute_linux_amd64 userenum --domain htb.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.52

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 12/08/22 - Ronnie Flathers @ropnop

2022/12/08 17:48:47 >  Using KDC(s):
2022/12/08 17:48:47 >   10.10.10.52:88

2022/12/08 17:48:47 >  [+] VALID USERNAME:       james@htb.local
2022/12/08 17:48:50 >  [+] VALID USERNAME:       James@htb.local
2022/12/08 17:49:00 >  [+] VALID USERNAME:       administrator@htb.local
2022/12/08 17:49:11 >  [+] VALID USERNAME:       mantis@htb.local
2022/12/08 17:49:34 >  [+] VALID USERNAME:       JAMES@htb.local
2022/12/08 17:50:24 >  [+] VALID USERNAME:       Administrator@htb.local
2022/12/08 17:51:01 >  [+] VALID USERNAME:       Mantis@htb.local
2022/12/08 18:45:20 >  [!] cooter25@htb.local - KRB Error: (29) KDC_ERR_SVC_UNAVAILABLE A service is not available
2022/12/08 18:45:20 >  [!] cootee@htb.local - KRB Error: (29) KDC_ERR_SVC_UNAVAILABLE A service is not available
2022/12/08 18:45:20 >  [!] coopsies@htb.local - KRB Error: (29) KDC_ERR_SVC_UNAVAILABLE A service is not available
2022/12/08 18:45:20 >  [!] coopsam@htb.local - KRB Error: (29) KDC_ERR_SVC_UNAVAILABLE A service is not available
2022/12/08 18:45:20 >  Done! Tested 495385 usernames (7 valid) in 3392.822 seconds

```


	8080 --> gobuster
1337 --> gobuster 
`http://10.10.10.52:1337/secure_notes/


https://www.rapidtables.com/convert/number/binary-to-ascii.html

from binary
010000000110010001101101001000010110111001011111010100000100000001110011011100110101011100110000011100100110010000100001
to ascii
**@dm!n_P@ssW0rd!**


└─$ echo NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx|base64 -d|xxd -r -p 
m$$ql_S@_P@ssW0rd!    

