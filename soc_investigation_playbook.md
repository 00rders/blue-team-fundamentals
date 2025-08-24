# 🧠 Tier 1/2 SOC Analyst Threat Investigation Playbook

This playbook provides a structured, end-to-end guide for investigating suspicious or compromised systems (Windows and Linux). It is optimized for Tier 1/2 analysts working in on-premise environments and prioritizes real-world threats: ransomware, phishing, persistence, C2, and account compromise.

---

## 🚨 1. Initial Alert Context

* Identify the alert type, timestamp, affected system, and user.
* Check what triggered the alert: file, IP, command, process, behavior.
* Extract all IOCs (hashes, domains, usernames, ports, etc.)
* Correlate with EDR/SIEM if available.
* Document alert metadata for timeline reconstruction.

---

## 🧹 2. Running Process Analysis

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

---

## 🔗 7. Lateral Movement & Remote Access Indicators

* Look for RDP (Logon Type 10), SMB sessions, or SSH from strange sources.
* Inspect scheduled tasks pushing to other hosts.
* Use `quser`, `query session`, or `last` to view user sessions.

---

## 🧪 8. Malware/Threat Intel Validation

* Hash any files and scan with:

  * [VirusTotal](https://www.virustotal.com/)
  * [Hybrid Analysis](https://www.hybrid-analysis.com/)
* Check:

  * Process command lines for obfuscation
  * Domains against [AbuseIPDB](https://www.abuseipdb.com/)

---

## 🛡️ 9. Containment Actions (Tier 1/2)

* Isolate the host from the network.
* Terminate confirmed malicious processes.
* Disable malicious persistence (cron job, task, service).
* Force password resets for compromised accounts.
* Trigger IR escalation per SOP if needed.

---

## 📟 10. Document & Report

* Record:

  * Hostname, IP, user, timeline, tools used, IOCs found.
  * Actions taken: killed processes, removed services, etc.
* Share findings with IR team or senior analyst.
* Save logs and artifacts (memory dump, screenshots, IOC list).

---

> 🎯 Use this playbook to approach every alert methodically. Don’t rely on intuition — rely on data, process, and discipline.
