# 🛡️ Network Penetration Testing with Real-World Exploits and Security Remediation

This project simulates real-world network attacks and defense strategies using *Kali Linux* as the attacker machine and *Metasploitable 2* as the vulnerable target. It covers scanning, enumeration, exploitation, user privilege escalation, password cracking, and remediation — all within a controlled lab setup for ethical cybersecurity learning.

---

## 🎯 Objectives

- Simulate real-world network attacks in a virtual lab
- Use Nmap for scanning, enumeration, and OS detection
- Exploit known vulnerabilities using Metasploit
- Create users and escalate privileges in Linux
- Crack password hashes using John the Ripper
- Recommend remediation steps based on CVEs

---

## 💻 Lab Setup

### 🖥️ Operating Systems
- *Kali Linux* – Attacker VM
- *Metasploitable 2* – Target VM

### 🛠️ Tools Used
- nmap – Port scanning, OS detection, service enumeration
- Metasploit – Exploitation of vulnerable services
- John the Ripper – Password hash cracking
- Linux commands – for user management and analysis

---

## 🚀 Tasks Performed

### 🔍 Network Scanning
- nmap -v 192.168.1.6 – Basic network scan
- nmap -v -p- 192.168.1.6 – Full port scan
- nmap -sV 192.168.1.6 – Service version detection
- nmap -O 192.168.1.6 – Operating system detection

### 🔐 Hidden Ports Discovered
Ports like 2121, 8180, 8787, 36525, 38819, 41246, 59082 found through full port scans.

### 📡 Enumeration
- *Target IP*: 192.168.1.6
- *OS*: Linux 2.6.x (Metasploitable)
- *Detected services*: FTP (vsftpd 2.3.4), SSH, Apache, MySQL, Samba, Java RMI, VNC, etc.

### 💥 Exploitation
- *vsftpd 2.3.4* backdoor exploit
- *Java RMI* remote code execution
- *Samba "username map script"* vulnerability exploit

### 👤 Privilege Escalation
- Created user anshu with root-like privileges
- Extracted hash from /etc/shadow
- Cracked password using john

### 🔧 Remediation Steps
| Service   | Vulnerability                    | Fix                                 |
|-----------|----------------------------------|--------------------------------------|
| vsftpd    | Backdoor (CVE-2011-2523)         | Upgrade to 3.0.5 / switch to SFTP    |
| Samba     | RCE (CVE-2007-2447)              | Update to Samba 3.5.1+               |
| Java RMI  | Insecure defaults (CVE-2015-2370)| Disable/secure RMI, use a firewall   |

---

## 📚 Major Learning

This project helped me understand how attackers use tools like Nmap and Metasploit to probe and exploit vulnerabilities. I practiced creating users, analyzing Linux password files, cracking hashes with John the Ripper, and identifying outdated or risky services like FTP, Samba, and R Services. I also learned to research and apply relevant CVEs to suggest practical security remediations.

---

## ⚠️ Disclaimer

This project was performed *strictly in a virtual lab environment* for *educational purposes only*. Do not replicate these activities on live networks without proper authorization.

---

## 📎 References

- [CVE-2011-2523 – vsftpd Backdoor](https://nvd.nist.gov/vuln/detail/CVE-2011-2523)
- [CVE-2007-2447 – Samba Exploit](https://nvd.nist.gov/vuln/detail/CVE-2007-2447)
- [CVE-2015-2370 – Java RMI Risk](https://nvd.nist.gov/vuln/detail/CVE-2015-2370)
- [John the Ripper](https://www.openwall.com/john/)
- [Metasploit Modules](https://docs.rapid7.com/metasploit/)
- [Samba Security Advisories](https://www.samba.org/samba/security/)
