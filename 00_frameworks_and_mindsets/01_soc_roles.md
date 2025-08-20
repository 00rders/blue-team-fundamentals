### 🧠 Field Reference: SOC Roles

> **Use this section as a quick-look reference while working cases, building detection rules, or studying for interviews.**

---

#### 🎯 Role Breakdown

| Role               | Primary Focus                              | Common Tools                                                       |
|--------------------|---------------------------------------------|--------------------------------------------------------------------|
| **Tier 1 Analyst** | Alert triage, log review, escalation        | SIEMs (Splunk, ELK), EDR (CrowdStrike), Ticketing (TheHive)        |
| **Tier 2 Analyst** | In-depth investigation, incident handling   | PCAP tools (Wireshark), Threat Intel (VirusTotal, AbuseIPDB)       |
| **Threat Hunter**  | Proactive threat search, hypothesis testing | EDR, Query tools (KQL, SPL), MITRE ATT&CK                           |
| **Detection Eng.** | Rule creation, tuning, coverage mapping     | SIEM/EDR, Sigma rules, ATT&CK Navigator                            |
| **SOC Lead**       | Workflow design, escalations, reporting     | Jira, Case management, Compliance tooling                          |

---

#### 🧩 Kill Chain vs Roles

| Kill Chain Phase        | Role Most Involved                   |
|--------------------------|--------------------------------------|
| Recon → Weaponization    | Threat Hunter, Detection Engineer    |
| Delivery → Exploitation  | Tier 1/2 Analyst                     |
| Installation → C2        | Tier 2 Analyst, Threat Hunter        |
| Exfiltration             | Tier 2 Analyst, SOC Lead             |

---

#### 🛠️ Tools Reference

- **SIEMs**: Splunk, Elastic, Sentinel  
- **EDR**: CrowdStrike, SentinelOne, Defender for Endpoint  
- **Intel**: VirusTotal, GreyNoise, AbuseIPDB  
- **Case Mgmt**: TheHive, Jira, MISP  
- **Kill Chain Models**: MITRE ATT&CK, Cyber Kill Chain, Diamond Model  

---

#### 🗣️ Interview Cheat Sheet

- “As a Tier 1, I’d first validate the alert, check context in the SIEM, and escalate if needed.”
- “A Threat Hunter differs by proactively searching without a trigger.”
- “Detection Engineers map rules to ATT&CK to ensure coverage across all tactics.”
