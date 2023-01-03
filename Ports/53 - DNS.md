## What is DNS?
```
## DNS Basics

All computers on the Internet, from your smart phone or laptop to the servers that serve content for massive retail websites, find and communicate with one another by using numbers. These numbers are known as **IP addresses**. When you open a web browser and go to a website, you don't have to remember and enter a long number. Instead, you can enter a **domain name** like example.com and still end up in the right place.

A DNS service such as Amazon Route 53 is a globally distributed service that translates human readable names like www.example.com into the numeric IP addresses like 192.0.2.1 that computers use to connect to each other. The Internet’s DNS system works much like a phone book by managing the mapping between names and numbers. DNS servers translate requests for names into IP addresses, controlling which server an end user will reach when they type a domain name into their web browser. These requests are called **queries**.

Resource: https://aws.amazon.com/route53/what-is-dns/
```
## What is Zone Transfer
```
DNS zones allow exactly this, to manage a partition of the domain namespace. The DNS administrator of a higher level needs to delegate a Master DNS zone to another administrator, so he or she can manage a lower level zone. The DNS zones have zone files that define them.DNS zones allow exactly this, to manage a partition of the domain namespace. The DNS administrator of a higher level needs to delegate a Master DNS zone to another administrator, so he or she can manage a lower level zone. The DNS zones have zone files that define them.

https://www.cloudns.net/blog/zone-transfer-zone-file-domain-namespace/
```


dig any victim.com @<DNS_IP>

## Zone Transfer

```

dig axfr @<DNS_IP> #Try zone transfer without domain
dig axfr @<DNS_IP> <DOMAIN> #Try zone transfer guessing the domain
fierce --domain <DOMAIN> --dns-servers <DNS_IP> #Will try toperform a zone transfer against every authoritative name server and if this doesn'twork, will launch a dictionary attack

```

```
dig ANY @<DNS_IP> <DOMAIN>     #Any information
dig A @<DNS_IP> <DOMAIN>       #Regular DNS request
dig AAAA @<DNS_IP> <DOMAIN>    #IPv6 DNS request
dig TXT @<DNS_IP> <DOMAIN>     #Information
dig MX @<DNS_IP> <DOMAIN>      #Emails related
dig NS @<DNS_IP> <DOMAIN>      #DNS that resolves that name
dig -x 192.168.0.2 @<DNS_IP>   #Reverse lookup
dig -x 2a00:1450:400c:c06::93 @<DNS_IP> #reverse IPv6 lookup

#Use [-p PORT]  or  -6 (to use ivp6 address of dns)
```

## nslookup
```
nslookup
> SERVER <IP_DNS> #Select dns server
> 127.0.0.1 #Reverse lookup of 127.0.0.1, maybe...
> <IP_MACHINE> #Reverse lookup of a machine, maybe...
```

## nmap scripts
```
nmap -n --script "(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport" <IP>

```

## DNS- Reverse BF
```
dnsrecon -r 127.0.0.0/24 -n <IP_DNS>  #DNS reverse of all of the addresses
dnsrecon -r 127.0.1.0/24 -n <IP_DNS>  #DNS reverse of all of the addresses
dnsrecon -r <IP_DNS>/24 -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d active.htb -a -n <IP_DNS> #Zone transfer
```

## Active Directory Servers
```
dig -t _gc._tcp.lab.domain.com
dig -t _ldap._tcp.lab.domain.com
dig -t _kerberos._tcp.lab.domain.com
dig -t _kpasswd._tcp.lab.domain.com
nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='domain.com'"
```

## DNSSec
```
 #Query paypal subdomains to ns3.isc-sns.info
 nmap -sSU -p53 --script dns-nsec-enum --script-args dns-nsec-enum.domains=paypal.com ns3.isc-sns.info
```

## IPv6
```
dnsdict6 -s -t <domain>

dnsrevenum6 pri.authdns.ripe.net 2001:67c:2e8::/48 #Will use the dns pri.authdns.ripe.net
```

## Config files
```
host.conf
/etc/resolv.conf
/etc/bind/named.conf
/etc/bind/named.conf.local
/etc/bind/named.conf.options
/etc/bind/named.conf.log
/etc/bind/*
```

## HackTricks Automatic Commands
```
Protocol_Name: DNS    #Protocol Abbreviation if there is one.
Port_Number:  53     #Comma separated if there is more than one.
Protocol_Description: Domain Name Service        #Protocol Abbreviation Spelled out

Entry_1:
  Name: Notes
  Description: Notes for DNS
  Note: |
    #These are the commands I run every time I see an open DNS port

    dnsrecon -r 127.0.0.0/24 -n {IP} -d {Domain_Name}
    dnsrecon -r 127.0.1.0/24 -n {IP} -d {Domain_Name}
    dnsrecon -r {Network}{CIDR} -n {IP} -d {Domain_Name}
    dig axfr @{IP}
    dig axfr {Domain_Name} @{IP}
    nslookup
        SERVER {IP}
        127.0.0.1
        {IP}
        Domain_Name
        exit

    https://book.hacktricks.xyz/pentesting/pentesting-dns

Entry_2:
  Name: Banner Grab
  Description: Grab DNS Banner
  Command: dig version.bind CHAOS TXT @DNS

Entry_3:
  Name: Nmap Vuln Scan
  Description: Scan for Vulnerabilities with Nmap
  Command: nmap -n --script "(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport" {IP}

Entry_4:
  Name: Zone Transfer
  Description: Three attempts at forcing a zone transfer
  Command: dig axfr @{IP} && dix axfr @{IP} {Domain_Name} && fierce -dns {Domain_Name}

Entry_5:
  Name: Active Directory
  Description: Eunuerate a DC via DNS
  Command: dig -t _gc._{Domain_Name} && dig -t _ldap._{Domain_Name} && dig -t _kerberos._{Domain_Name} && dig -t _kpasswd._{Domain_Name} && nmap --script dns-srv-enum --script-args "dns-srv-enum.domain={Domain_Name}"
  
Entry_6:
  Name: consolesless mfs enumeration
  Description: DNS enumeration without the need to run msfconsole
  Note: sourced from https://github.com/carlospolop/legion
  Command: msfconsole -q -x 'use auxiliary/scanner/dns/dns_amp; set RHOSTS {IP}; set RPORT 53; run; exit' && msfconsole -q -x 'use auxiliary/gather/enum_dns; set RHOSTS {IP}; set RPORT 53; run; exit' 
```