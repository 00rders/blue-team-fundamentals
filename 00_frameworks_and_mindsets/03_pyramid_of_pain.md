# 🧠 Pyramid of Pain – Field Reference

A quick-access tactical sheet for understanding the Pyramid of Pain and its impact on adversary operations.

---

## 📚 Pyramid Levels & Definitions

1. **Hash Values** – File-level signatures (e.g., MD5, SHA256)
2. **IP Addresses** – Network-level indicators of compromise
3. **Domain Names** – C2 or malicious infrastructure
4. **Network/Host Artifacts** – Registry keys, file names, mutexes
5. **Tools** – Known attacker toolkits (e.g., Mimikatz, Cobalt Strike)
6. **Tactics, Techniques, and Procedures (TTPs)** – Behavior patterns and methods (e.g., credential dumping)

---

## 💡 Analyst Tips

- The higher up the pyramid, the **more it hurts the attacker** when you detect/disrupt.
- Lower-level indicators are **easy to change** (hash, IP), providing short-term wins.
- TTPs are **hard to swap** – disrupting them forces attacker retooling.
- Use TTP-based detections for **longer-lasting defense** and **threat hunting**.
- Combine with **MITRE ATT&CK** to operationalize TTP-level defense.

---

## 🧰 Tools & Detection Coverage

| Level             | Detection Methods / Tools                                |
|------------------|-----------------------------------------------------------|
| Hash Values      | AV/EDR signature matches, VirusTotal, YARA                |
| IP Addresses     | Firewall/IDS, threat intel feeds                          |
| Domain Names     | DNS monitoring, sinkholes, Zeek                           |
| Artifacts        | Sysmon logs, file integrity monitoring (FIM)              |
| Tools            | EDR telemetry, behavioral detections, tool fingerprinting |
| TTPs             | MITRE ATT&CK mapping, anomaly detection, threat hunting   |

---

## 🧪 Practice Scenario Example

**Example Threat: Ransomware Campaign**

- Hash: `abc123...` – Detected, blocked at AV
- IP: `104.21.92.211` – Listed on AbuseIPDB
- Domain: `malicious-c2[.]com` – Detected via DNS logs
- Artifact: Scheduled task named `backup-agent.exe`
- Tool: Mimikatz seen dumping LSASS
- TTP: MITRE T1003 – Credential Access via LSASS memory dump

---

## 🧭 Use Cases

- Prioritize **TTP-level detection** for durable defense
- Use pyramid levels to **grade your IOC coverage**
- Guide **incident response** by mapping observed artifacts
- Educate analysts on **IOC volatility** and detection value
