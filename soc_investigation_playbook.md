# 🧠 Tier 1/2 SOC Analyst Threat Investigation Playbook

This playbook provides a structured, end-to-end guide for investigating suspicious or compromised systems (Windows and Linux). It is optimized for Tier 1/2 analysts working in on-premise environments and prioritizes real-world threats: ransomware, phishing, persistence, C2, and account compromise.

> 🧭 **MITRE ATT\&CK Mapping:** Relevant techniques are listed under each section using their technique IDs (e.g., T1059.001). Refer to [https://attack.mitre.org/](https://attack.mitre.org/) for detailed descriptions.

---

## 🚨 1. Initial Alert Context

* Identify the alert type, timestamp, affected system, and user.
* Check what triggered the alert: file, IP, command, process, behavior.
* Extract all IOCs (hashes, domains, usernames, ports, etc.)
* Correlate with EDR/SIEM if available.
* Document alert metadata for timeline reconstruction.

**MITRE ATT\&CK:** T1082, T1598, T1566.001

---

## 🧩 2. Running Process Analysis

**Windows:**

```bash
tasklist /v
wmic process list full
```

**Linux:**

```bash
ps aux
ps -eo pid,ppid,user,cmd,%cpu,%mem --sort=-%cpu
```

* Investigate unsigned, unknown, or oddly-named processes.
* Check parent-child relationships (`pstree`, `Process Explorer`).
* Review binary path — system32 is normal, `AppData\Roaming` is not.
* Hash binaries and scan with VirusTotal or Hybrid Analysis.

**MITRE ATT\&CK:** T1057, T1059.001, T1087.001, T1543

---

## 🌐 3. Network Connections

**Windows:**

```bash
netstat -ano
Get-NetTCPConnection
```

**Linux:**

```bash
ss -tunap
lsof -i
```

* Look for connections to unknown IPs or countries.
* Flag uncommon ports (e.g., high TCP, 1337, 4444).
* Correlate PIDs with processes (`netstat` → `tasklist`).
* Query suspicious IPs in AbuseIPDB or ThreatFox.

**MITRE ATT\&CK:** T1049, T1071.001, T1105, T1016

---

## 📜 4. Logs & Authentication Review

**Windows Event IDs to check:**

* 4624: Successful login
* 4625: Failed login
* 4672: Admin login
* 7045: New service installed
* 1102: Log cleared

**Linux Logs:**

```bash
cat /var/log/auth.log
cat /var/log/syslog
```

* Look for off-hours logins, brute-force patterns, new users.
* Check if logs were tampered (e.g., Event ID 1102).
* Confirm what happened before/after alert time.

**MITRE ATT\&CK:** T1110.001, T1078, T1086, T1003, T1562.002

### 📑 Key Linux Log Files

| File/Directory                | Purpose                                                                 | SOC Relevance                                                                 |
|-------------------------------|-------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| `/var/log/syslog`             | General system messages, services, kernel events                        | Baseline system behavior, crash/error detection, suspicious service activity  |
| `/var/log/auth.log`           | Authentication events: logins, sudo usage, SSH attempts                 | Detect brute force, privilege escalation, lateral movement                    |
| `/var/log/kern.log`           | Kernel-level messages                                                   | Driver/rootkit issues, kernel exploits                                        |
| `/var/log/dmesg`              | Boot and hardware-related messages                                      | Look for persistence attempts via kernel modules or boot-time anomalies       |
| `/var/log/faillog`            | Failed login attempts summary                                           | Brute-force attack tracking, account abuse                                    |
| `/var/log/ufw.log`            | UFW firewall activity (blocked/allowed connections)                     | Detect port scans, blocked C2 traffic, unauthorized inbound/outbound          |
| `/var/log/fail2ban.log`       | Logs from fail2ban (brute-force protection)                             | Validation of brute-force mitigation, source IPs for correlation              |
| `/var/log/apache2/access.log` | Apache web server requests (IP, method, URL, status)                     | Identify web shells, LFI/RFI attempts, brute force on web apps                |
| `/var/log/apache2/error.log`  | Apache web server errors, misconfigurations, crashes                     | Evidence of exploitation attempts (e.g., malformed requests causing errors)   |
| `/var/log/mysql/error.log`    | MySQL database errors and startup issues                                | SQL injection detection, failed/abnormal DB access attempts                   |
| `/var/log/secure`             | (RHEL/CentOS) Authentication and security-related events (like auth.log) | Same use cases as `/var/log/auth.log` for Red Hat-based systems               |

📌 **Tip for SOC triage:** Focus on `auth.log`, `syslog`, firewall logs, and service-specific logs first. These often contain the earliest indicators of compromise.
📌 **Tip:** Use `tail -f /var/log/<file>` to watch logs live in real-time.

---

## 🧠 5. Persistence Checks

**Windows:**

* `schtasks /query /fo LIST /v`
* Check `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* Inspect Task Scheduler + Services (`services.msc`)

**Linux:**

```bash
crontab -l
ls /etc/cron.*
systemctl list-units --type=service
```

* Look for auto-start scripts in temp directories or hidden folders.
* Flag any service or cron job referencing a suspicious script or path.

**MITRE ATT\&CK:** T1053.005, T1547.001, T1543.003

---

## 👤 6. Account and Privilege Activity

**Windows:**

```bash
net user
net localgroup administrators
```

**Linux:**

```bash
cat /etc/passwd
sudo less /var/log/secure
```

* Identify new accounts or sudden group membership changes.
* Flag accounts with unexpected admin rights.
* Check login activity for abuse or credential reuse.

**MITRE ATT\&CK:** T1078, T1136.001, T1098

---

## 🔗 7. Lateral Movement & Remote Access Indicators

* Look for RDP (Logon Type 10), SMB sessions, or SSH from strange sources.
* Inspect scheduled tasks pushing to other hosts.
* Use `quser`, `query session`, or `last` to view user sessions.

**MITRE ATT\&CK:** T1021.001, T1021.002, T1021.004

---

## 🧪 8. Malware/Threat Intel Validation

* Hash any files and scan with:

  * [VirusTotal](https://www.virustotal.com/)
  * [Hybrid Analysis](https://www.hybrid-analysis.com/)
* Check:

  * Process command lines for obfuscation
  * Domains against [AbuseIPDB](https://www.abuseipdb.com/)

**MITRE ATT\&CK:** T1204.002, T1065, T1105

---

## 🛡️ 9. Containment Actions (Tier 1/2)

* Isolate the host from the network.
* Terminate confirmed malicious processes.
* Disable malicious persistence (cron job, task, service).
* Force password resets for compromised accounts.
* Trigger IR escalation per SOP if needed.

**MITRE ATT\&CK:** T1562.001, T1550, T1566, T1033

---

## 🧾 10. Document & Report

* Record:

  * Hostname, IP, user, timeline, tools used, IOCs found.
  * Actions taken: killed processes, removed services, etc.
* Share findings with IR team or senior analyst.
* Save logs and artifacts (memory dump, screenshots, IOC list).

---

> 🎯 Use this playbook to approach every alert methodically. Don’t rely on intuition — rely on data, process, and discipline.
