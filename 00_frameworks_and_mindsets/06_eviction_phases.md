# 📖 MITRE ATT\&CK Navigator — Eviction Phases Handbook

A universal triage + eviction workflow for SOC analysts. Use this as a **one-page guide** when working with ATT\&CK Navigator to identify, contain, and evict adversaries.

---

## 🚨 Eviction Phases Flow

```
🕵️ Recon → 🎯 Initial Access → 💻 Execution → ♻️ Persistence →
🛡️ Defense Evasion → 🔍 Discovery → 🔄 Lateral Movement →
📦 Collection → 📤 Exfiltration → 🌐 Command & Control
```

At each phase:

1. **Identify** TTPs in Navigator.
2. **Validate** with logs/artifacts.
3. **Evict** by containing, blocking, or escalating.

---

## 🕵️ Phase 1 — Reconnaissance

* **Look for**: Domain reg, scanning, phishing setup.
* **Artifacts**: WHOIS, scan logs, suspicious email prep.
* **Evict**: Block domains, rate-limit scans, alert on mass probes.

## 🎯 Phase 2 — Initial Access

* **Look for**: Spearphishing, exploited apps, valid accounts.
* **Artifacts**: Email gateway hits, web server logs, unusual logins.
* **Evict**: Quarantine inbox, patch apps, disable stolen accounts.

## 💻 Phase 3 — Execution

* **Look for**: Malicious scripts, user execution, native API use.
* **Artifacts**: PowerShell, cmd, bash logs.
* **Evict**: Kill malicious processes, restrict interpreters.

## ♻️ Phase 4 — Persistence

* **Look for**: Registry run keys, scheduled tasks, rogue accounts.
* **Artifacts**: Registry baselines, cron, AD changes.
* **Evict**: Remove persistence entries, disable unauthorized accounts.

## 🛡️ Phase 5 — Defense Evasion

* **Look for**: Rundll32/regsvr32, masquerading, obfuscation.
* **Artifacts**: Process creation, renamed binaries.
* **Evict**: Terminate proxy binaries, block obfuscated payloads.

## 🔍 Phase 6 — Discovery

* **Look for**: Account enumeration, network sniffing, system scans.
* **Artifacts**: net, ipconfig, tcpdump, PowerView logs.
* **Evict**: Alert on broad enumeration, cut compromised host’s network.

## 🔄 Phase 7 — Lateral Movement

* **Look for**: SMB, RDP, admin share abuse.
* **Artifacts**: Auth anomalies, ticket use, login spikes.
* **Evict**: Reset credentials, restrict remote services.

## 📦 Phase 8 — Collection

* **Look for**: File share dumps, email collection, repository access.
* **Artifacts**: File copy/archive logs, mail dumps.
* **Evict**: Lock down repositories, revoke suspicious access.

## 📤 Phase 9 — Exfiltration

* **Look for**: Exfil over C2, cloud, alt protocols.
* **Artifacts**: Proxy logs, encrypted outbound, compression traces.
* **Evict**: Block outbound channels, monitor for retries.

## 🌐 Phase 10 — Command & Control

* **Look for**: DNS tunneling, web protocols, proxies.
* **Artifacts**: DNS queries, HTTPS tunnels, domain fronting.
* **Evict**: Cut comms, isolate host, sinkhole domains.

---

## ⚡ Eviction Rules

* **Break the chain early**: each phase blocked = adversary evicted sooner.
* **Map TTP → Artifact → Action** at every step.
* **Contain fast, confirm later**: stop activity first, analyze deeper after.

---

👉 This handbook = eviction phase reference. Scan Navigator, spot TTPs, evict adversaries systematically.
