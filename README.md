# Enumeration
Enumeration Techniques

# Explore Google hacking and enumeration 

# AIM:

To use Google for gathering information and perform enumeration of targets

## STEPS:

### Step 1:

Install kali linux either in partition or virtual box or in live mode

### Step 2:

Investigate on the various Google hacking keywords and enumeration tools as follows:


### Step 3:
Open terminal and try execute some kali linux commands

## Pen Test Tools Categories:  

Following Categories of pen test tools are identified:
Information Gathering.

Google Hacking:

Google hacking, also known as Google dorking, is a technique that involves using advanced operators to perform targeted searches on Google. These operators can be used to search for specific types of information, such as sensitive data that may have been inadvertently exposed on the web. Here are some advanced operators that can be used for Google hacking:

site: This operator allows you to search for pages that are within a specific website or domain. For example, "site:example.com" would search for pages that are on the example.com domain.
Following searches for all the sites that is in the domain crunchyroll.com

filetype: This operator allows you to search for files of a specific type. For example, "filetype:pdf" would search for all PDF files.
Following searches for pdf file in the domain yahoo.com
![Screenshot 2025-03-17 101544](https://github.com/user-attachments/assets/5102bff7-a075-41d4-9e20-7191ebc74907)




intext: This operator allows you to search for pages that contain specific text within the body of the page. For example, "intext:password" would search for pages that contain the word "password" within the body of the page.
![Screenshot 2025-03-17 101633](https://github.com/user-attachments/assets/ee238b8a-02b1-4017-815c-1439dc0fb2b1)



inurl: This operator allows you to search for pages that contain specific text within the URL. For example, "inurl:admin" would search for pages that contain the word "admin" within the URL.
![Screenshot 2025-03-17 114647](https://github.com/user-attachments/assets/cdf61855-33e8-4921-9822-6c5c1ce5030a)


intitle: This operator allows you to search for pages that contain specific text within the title tag. For example, "intitle:index of" would search for pages that contain "index of" within the title tag.
![Screenshot 2025-03-17 114759](https://github.com/user-attachments/assets/88d983b8-64aa-4b63-82e9-3c50d683eb2d)


link: This operator allows you to search for pages that link to a specific URL. For example, "link:example.com" would search for pages that link to the example.com domain.
![Screenshot 2025-03-17 114820](https://github.com/user-attachments/assets/0ee63678-7762-4d71-849f-b7ef8dfd90fe)

cache: This operator allows you to view the cached version of a page. For example, "cache:example.com" would show the cached version of the example.com website.
![Screenshot 2025-03-17 114849](https://github.com/user-attachments/assets/f35d966b-4e82-4193-b508-9b45f2552587)


 
# DNS Enumeration

## DNS Recon
provides the ability to perform:
Check all NS records for zone transfers
Enumerate general DNS records for a given domain (MX, SOA, NS, A, AAAA, SPF , TXT)
Perform common SRV Record Enumeration
Top level domain expansion
## OUTPUT:
![Screenshot 2025-03-21 090741](https://github.com/user-attachments/assets/bd430cb0-300f-48ea-a611-774964364050)



## smtp-user-enum
Username guessing tool primarily for use against the default Solaris SMTP service. Can use either EXPN, VRFY or RCPT TO.


In metasploit list all the usernames using head /etc/passwd or cat /etc/passwd:

select any username in the first column of the above file and check the same


#Telnet for smtp enumeration
Telnet allows to connect to remote host based on the port no. For smtp port no is 25
telnet <host address> 25 to connect
and issue appropriate commands
  
 ## Output
 ![Screenshot 2025-03-21 100929](https://github.com/user-attachments/assets/54299e28-6fce-4112-a8f1-c0463ba132c6)

# dnsenum
Dnsenum is a multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks. The main purpose of Dnsenum is to gather as much information as possible about a domain. The program currently performs the following operations:

Get the host’s addresses (A record).
Get the namservers (threaded).
Get the MX record (threaded).
Perform axfr queries on nameservers and get BIND versions(threaded).
Get extra names and subdomains via google scraping (google query = “allinurl: -www site:domain”).
Brute force subdomains from file, can also perform recursion on subdomain that have NS records (all threaded).
Calculate C class domain network ranges and perform whois queries on them (threaded).
Perform reverse lookups on netranges (C class or/and whois netranges) (threaded).
Write to domain_ips.txt file ip-blocks.
This program is useful for pentesters, ethical hackers and forensics experts. It also can be used for security tests.

  
![Screenshot 2025-03-21 100655](https://github.com/user-attachments/assets/135f697b-479c-44e2-8ba2-710569fe4d39)


## nmap –script smtp-enum-users.nse <hostname>

The smtp-enum-users.nse script attempts to enumerate the users on a SMTP server by issuing the VRFY, EXPN or RCPT TO commands. The goal of this script is to discover all the user accounts in the remote system.
![Screenshot 2025-03-21 101058](https://github.com/user-attachments/assets/12f1a438-6316-46b7-9ef2-917ff8397bff)


![Screenshot 2025-03-14 091100](https://github.com/user-attachments/assets/dabfff3f-11c7-4e61-b5bc-5c8e4ddc1939)

## OUTPUT:
# Telnet for smtp enumeration
Telnet allows to connect to remote host based on the port no. For smtp port no is 25
telnet <host address> 25 to connect
and issue appropriate commands
![Screenshot 2025-03-16 150434](https://github.com/user-attachments/assets/00a42e26-818c-4e70-a23c-cac21fbb6f34)
# nmap –script smtp-enum-users.nse <hostname>

The smtp-enum-users.nse script attempts to enumerate the users on a SMTP server by issuing the VRFY, EXPN or RCPT TO commands. The goal of this script is to discover all the user accounts in the remote system.
![Screenshot 2025-03-21 101058](https://github.com/user-attachments/assets/2d7e73e5-0f83-4fcf-98c2-dec18e97981c)



## RESULT:
The Google hacking keywords and enumeration tools were identified and executed successfully

