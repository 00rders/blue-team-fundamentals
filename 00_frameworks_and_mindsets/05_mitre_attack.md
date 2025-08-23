# 🧠 MITRE ATT&CK – Field Reference  

A quick-access tactical sheet for understanding and applying the MITRE ATT&CK Framework in SOC operations.  

---

## 📚 Core Concepts & Definitions  

1. **Tactics** – The *why*. Adversary’s high-level goal during an intrusion.  
   *Examples*: Reconnaissance, Initial Access, Execution, Persistence, Exfiltration.  

2. **Techniques** – The *how*. Specific methods adversaries use to achieve a tactic.  
   *Example*: “Spearphishing Link” under Initial Access.  

3. **Sub-Techniques** – More detail under techniques.  
   *Example*: “Spearphishing via Service” vs “Spearphishing via Attachment.”  

4. **Procedures** – The *implementation*. Exact commands, scripts, or malware families adversaries use.  
   *Example*: PowerShell one-liner delivered via phishing email.  

---

## ⚪ Framework Structure  

1. **Matrix View** – Tactics across the top, techniques under each.  
2. **Mapping** – Link alerts, IOCs, or behaviors to TTPs for context.  
3. **Navigator Tool** – Highlight relevant TTPs, build layers for adversary profiles.  
4. **Updates** – ATT&CK is living; tactics/techniques evolve with adversary behavior.  

---

## 🔍 Operational Use  

* **Detection Engineering** – Map detections to ATT&CK techniques to measure coverage.  
* **Threat Intel** – Enrich reports by tagging observed TTPs with ATT&CK IDs.  
* **Adversary Emulation** – Red-teamers replicate techniques to test defenses.  
* **Gap Analysis** – Identify missing detections or defensive blind spots.  
* **Hunt Hypotheses** – Build proactive hunts based on likely TTP chains.  

---

## 💡 Analyst Tips  

* Always ask: *Which tactic does this alert map to?* (e.g., Lateral Movement vs. Persistence).  
* Use ATT&CK IDs (`T1059`, `T1566`) for precision and easy reference.  
* Navigator layers = fast triage → highlight, pivot, annotate.  
* Build **eviction phases** aligned to ATT&CK (Recon → Exfil).  
* ATT&CK is not static — cross-reference with real procedures in intel reports.  

---

## 🧪 Practice Scenario Example  

**Alert:** PowerShell executing encoded commands on a user endpoint.  

* **Tactic**: Execution.  
* **Technique**: Command and Scripting Interpreter (T1059).  
* **Sub-Technique**: PowerShell (T1059.001).  
* **Procedure**: `powershell.exe -enc ...` observed in command line.  
* **Detection Strategy**: Monitor `Event ID 4104` (PowerShell script block logging).  
* **Follow-On**: Check for Persistence (registry run keys) and Defense Evasion (rundll32).  

---

## 🧭 Use Cases  

* Standardize **incident triage** by aligning all activity to TTPs.  
* Support **reporting** to leadership with ATT&CK context.  
* Enable **cross-team communication**: detection engineers, intel, red/blue teams all use ATT&CK as a shared language.  
* Train new analysts to think in **tactics → techniques → procedures**.  
