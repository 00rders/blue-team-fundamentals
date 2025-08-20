# 🧠 SOC Roles – Field Reference

A quick-access tactical sheet for understanding SOC team structure and responsibilities.

---

## 📚 SOC Role Definitions

1. **Tier 1 Analyst** – Alert triage, initial investigation, escalate as needed  
2. **Tier 2 Analyst** – Deeper log analysis, threat validation, incident scoping  
3. **Threat Hunter** – Proactively hunts threats without alerts, uses hypothesis-driven methods  
4. **Detection Engineer** – Develops detection rules, maps coverage to MITRE ATT&CK  
5. **SOC Lead / Manager** – Oversees SOC operations, handles reporting, ensures SLA compliance  

---

## 💡 Analyst Tips

- Tier 1 = **frontline**, handle high volume, focus on noise reduction  
- Tier 2 = **context builder**, connect dots, ask “what else?”  
- Threat Hunters should **build hypotheses** and test using real data  
- Detection Engineers must balance **coverage vs noise**  
- SOC Leads should maintain **communication pipelines** and incident quality  

---

## 🧰 Tools & Detection Coverage

| Role               | Common Tools Used                                        |
|--------------------|----------------------------------------------------------|
| Tier 1 Analyst     | SIEM (Splunk/ELK), Ticketing (TheHive), MITRE ATT&CK     |
| Tier 2 Analyst     | EDR, PCAP tools (Wireshark), Sandbox (ANY.RUN)           |
| Threat Hunter      | KQL/SPL queries, EDR, Zeek, Sigma, ATT&CK Navigator      |
| Detection Engineer | Sigma, Sysmon configs, Rule testing platforms            |
| SOC Lead           | Dashboards, Reporting tools, Workflow diagrams           |

---

## 🧪 Practice Scenario Example

**Scenario:**  
An alert triggers on a suspicious PowerShell command execution.

- **Tier 1:** Confirms alert, gathers context, escalates
- **Tier 2:** Investigates scope, lateral movement, and parent-child process trees
- **Threat Hunter:** Hunts for similar techniques across environment
- **Detection Engineer:** Tunes alert, reduces false positives, maps to MITRE T1059
- **SOC Lead:** Reviews incident timeline and reporting to stakeholders

---

## 🧭 Use Cases

- Use this reference during **on-call rotations**  
- Structure SOC playbooks around **who does what**  
- Align responsibilities to tools during tabletop exercises  
- Build detection rules and queries per role’s responsibilities  
