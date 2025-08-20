# 🧠 Diamond Model – Field Reference

A quick-access tactical sheet for understanding the Diamond Model of Intrusion Analysis.

---

## 📚 Core Features & Definitions

1. **Adversary** – The attacker or threat actor (individual or group) conducting the intrusion.

   * *Operator*: The hacker(s) executing the attack.
   * *Customer*: The entity that benefits from the attack (can be same or separate).

2. **Victim** – The target of the adversary.

   * *Persona*: Who is being targeted (people, orgs, industries).
   * *Assets*: What is being attacked (IP addresses, email accounts, hosts, networks).

3. **Capability** – The skills, tools, and techniques used.

   * *Capacity*: Vulnerabilities or exposures the capability exploits.
   * *Arsenal*: The full set of capabilities the adversary controls.

4. **Infrastructure** – The systems or resources used to deliver or control capabilities.

   * *Type 1*: Owned/controlled directly by the adversary.
   * *Type 2*: Indirect/compromised infrastructure, often to hide attribution.
   * *Service Providers*: ISPs, registrars, cloud hosts enabling infrastructure.

---

## ⚪ Meta-Features

1. **Timestamp** – When the event occurred (start/stop). Useful for pattern and time-zone analysis.
2. **Phase** – Stage of the attack (e.g., Recon, Exploit, C2, Exfil).
3. **Result** – Outcome of the event (success, failure, unknown, CIA impact).
4. **Direction** – Flow of activity (e.g., Infrastructure → Victim).
5. **Methodology** – Attack type (phishing, DDoS, port scan, etc.).
6. **Resources** – What adversary required (software, creds, money, access, hardware).

---

## 🔍 Additional Components

* **Socio-Political** – Adversary motive (financial gain, reputation, hacktivism, espionage).
* **Technology** – The relationship between capability and infrastructure (e.g., watering-hole attack = compromised site + malware delivery).

---

## 💡 Analyst Tips

* Always map **Adversary ↔ Victim ↔ Capability ↔ Infrastructure** for a full view.
* Add meta-features to capture **context** beyond raw indicators.
* **Socio-political** and **technology** components highlight *why* and *how* the attack was structured.
* Use Diamond Model diagrams for clear event reporting and linking related intrusions.

---

## 🧪 Practice Scenario Example

**Alert:** Multiple failed logins followed by a successful login from a suspicious IP.

* **Adversary**: Unknown brute-force actor.
* **Victim**: Employee account (persona) and VPN endpoint (asset).
* **Capability**: Credential attack (password spraying).
* **Infrastructure**: Type 2 VPS IP (`185.123.45.67`).
* **Timestamp**: 2025-08-20 02:15:22 UTC.
* **Phase**: Exploitation.
* **Result**: Success, confidentiality compromised.
* **Direction**: Infrastructure → Victim.
* **Methodology**: Credential access.
* **Resources**: Credential list, VPS server, automated script.
* **Socio-Political**: Likely financial gain (selling access).
* **Technology**: Infrastructure + capability combined via brute-force tool from rented server.

---

## 🧭 Use Cases

* Standardize **incident documentation** in SOC environments.
* Map alerts to **Diamond Model** for clarity and pattern recognition.
* Support **threat attribution** by separating operator vs. customer.
* Provide **training and reporting structure** for analysts.
