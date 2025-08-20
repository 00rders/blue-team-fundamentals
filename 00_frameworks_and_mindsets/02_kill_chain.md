# 🧠 Unified Kill Chain – Field Reference

A tactical reference sheet for the Unified Kill Chain — a comprehensive model combining Cyber Kill Chain and MITRE ATT&CK to map adversary operations in full detail.

---

## 📚 Unified Kill Chain Phases

The Unified Kill Chain has **18 attack phases**, grouped into 3 categories:

### 🔍 Initial Foothold

1. **Reconnaissance** – Identify potential targets and vulnerabilities  
2. **Weaponization** – Create or prepare attack payloads  
3. **Delivery** – Transmit payload (e.g., phishing, USB, drive-by)  
4. **Social Engineering** – Trick the user into executing payload  
5. **Exploitation** – Trigger a vulnerability or abuse functionality  
6. **Persistence** – Maintain access over time  

### 💻 Network Propagation

7. **Command & Control (C2)** – Establish communication with remote server  
8. **Internal Reconnaissance** – Learn about internal systems, accounts  
9. **Credential Access** – Harvest usernames, passwords, tokens  
10. **Privilege Escalation** – Gain higher-level permissions  
11. **Lateral Movement** – Move between systems in the network  
12. **Collection** – Gather sensitive files, logs, or screenshots  

### 🎯 Action on Objectives

13. **Exfiltration** – Remove data from the target environment  
14. **Impact** – Destroy, encrypt, or manipulate systems/data  
15. **Defense Evasion** – Disable AV, hide processes, clean logs  
16. **Obfuscation** – Encode payloads, use LOLBins, blend in  
17. **Anti-Analysis** – Evade sandboxes, delay execution  
18. **Command Repeat** – Re-establish C2 or reinitiate attack chain  

---

## 💡 Analyst Tips

- The Unified Kill Chain is **non-linear** — attackers may skip or repeat steps.
- Most mature threats include **defense evasion + persistence** tactics early.
- Use **MITRE ATT&CK** to map TTPs at each phase with precision.
- Knowing each phase helps **break the chain** early (especially delivery or C2).
- Use it for **threat hunting, detection engineering, and purple teaming**.

---

## 🧰 Tools & Detection Ideas

| Phase                  | Detection Methods / Tools                                  |
|------------------------|------------------------------------------------------------|
| Reconnaissance         | OSINT tools, web access logs, passive DNS                  |
| Weaponization          | Static/dynamic file analysis, YARA                         |
| Delivery               | Email filtering, proxy logs, download monitoring           |
| Social Engineering     | User training, email click tracking                        |
| Exploitation           | EDR alerts, Sysmon  exploit telemetry                      |
| Persistence            | Autoruns, service creation logs, Registry audit            |
| C2                     | Zeek, Suricata, abnormal outbound comms                    |
| Internal Recon         | PowerShell logs, AD enumeration patterns                   |
| Credential Access      | LSASS access logs, Honeycreds, brute force detection       |
| Privilege Escalation   | Token manipulation, new admin groups, kernel exploits      |
| Lateral Movement       | SMB/WinRM logs, RDP sessions, PsExec usage                 |
| Collection             | File access logs, screen capture detection                 |
| Exfiltration           | DLP tools, compressed archives over DNS/HTTP               |
| Impact                 | File deletion, ransomware behavior, WMI process events     |
| Defense Evasion        | Process hollowing, signed binaries, AV tampering           |
| Obfuscation            | Base64 usage, PowerShell encoding, LOLBins                 |
| Anti-Analysis          | Sandbox evasion, sleep timers, debugger checks             |
| Command Repeat         | Beaconing patterns, retry logic, domain rotation           |

---

## 🧪 Practice Scenario Example

**APT-style Attack Chain:**

- **Recon:** Attacker scans GitHub repos for internal domain leaks  
- **Delivery:** Phishing email with malicious Excel macro  
- **Social Engineering:** Victim opens and enables macros  
- **Exploitation:** Macro spawns obfuscated PowerShell  
- **Persistence:** Registry Run key + scheduled task  
- **C2:** HTTPS beacon to dynamic DNS domain  
- **Recon (internal):** PowerView used to enumerate AD  
- **Cred Access:** Mimikatz run from memory  
- **Priv Esc:** Token impersonation to SYSTEM  
- **Lateral Move:** PsExec used to reach Domain Controller  
- **Collection:** Gathers sensitive HR files  
- **Exfiltration:** Sends ZIP file to Dropbox via API  
- **Impact:** Deletes backups, drops ransomware  
- **Defense Evasion:** Clears logs with wevtutil, sleeps 30 min  
- **Obfuscation:** All scripts base64-encoded  
- **Anti-Analysis:** Macro checks for sandbox and VM  
- **Command Repeat:** Tries fallback C2 via backup domain  

---

## 🧭 Use Cases

- Track **end-to-end attacker movement** across environments  
- Identify **weak detection areas** in the kill chain  
- Create **realistic purple team exercises**  
- Correlate alerts to understand attack progress  
- Strengthen defenses at the **earliest breakable phase**
