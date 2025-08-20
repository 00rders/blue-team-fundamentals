# 🧠 Cyber Kill Chain – Field Reference

A quick-access tactical sheet for the Cyber Kill Chain framework.

---

## 📚 Kill Chain Phases & Definitions

1. **Reconnaissance** – Identify targets, gather intel
2. **Weaponization** – Create malicious payloads (e.g., spearphishing attachment)
3. **Delivery** – Transmit payload via email, USB, web, etc.
4. **Exploitation** – Trigger the exploit (e.g., PowerShell abuse)
5. **Installation** – Establish persistence (e.g., dynamic linker hijacking)
6. **Command & Control (C2)** – Remote access setup (e.g., fallback channels)
7. **Actions on Objectives** – Exfiltration, destruction, privilege escalation

---

## 💡 Analyst Tips

- Kill Chain is **linear**: Break one link to disrupt the attack.
- Think **prevent, detect, respond** at each phase.
- Use with MITRE ATT&CK for **granular TTP mapping**.
- **Recon + Delivery** are weakest links to defend early.
- **Persistence & C2** often give the attacker long-term access.

---

## 🧰 Tools & Detection Tips

| Phase           | Tools / Detections                            |
|----------------|------------------------------------------------|
| Recon          | Shodan, Google dorks, OSINT tools              |
| Weaponization  | Static analysis, sandboxing (ANY.RUN)          |
| Delivery       | Email gateway logs, spam filters               |
| Exploitation   | EDR alerts, PowerShell logging (Sysmon 4104)   |
| Installation   | Autoruns, DLL hijack detection (MITRE T1574)   |
| C2             | Zeek, IDS (Snort), suspicious domains          |
| Objectives     | DLP tools, audit logs, SIEM correlation rules  |

---

## 🧪 Practice Scenario Example

**Target Breach 2013:**

- Recon: 3rd party HVAC vendor credentials exposed
- Delivery: Spearphishing or malicious link
- Exploitation: Malware used to access POS systems
- C2: External IPs communicating outbound
- Exfil: Credit card data stolen from POS terminals

---

## 🧭 Use Cases

- Write detections that **map to each phase**
- Trace attacks backward to find entry point
- Use Kill Chain in **incident reporting & triage**

