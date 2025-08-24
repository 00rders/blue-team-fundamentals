## 🛠️ Linux Log Investigation – SOC Cheat Sheet

Use these commands during triage to search key logs fast. Assumes Ubuntu/Debian structure.

---

### 🔐 Authentication & Access

```bash
# Failed login attempts
grep "Failed password" /var/log/auth.log

# Successful root logins
grep "session opened for user root" /var/log/auth.log

# Sudo command usage
grep "sudo" /var/log/auth.log

# Suspicious login times/IPs (e.g., outside business hours)
grep "Accepted" /var/log/auth.log | awk '{print $1, $2, $3, $9, $11}'
```

---

### 🌐 Network & Firewall

```bash
# Denied connections by UFW
grep "BLOCK" /var/log/ufw.log

# Repeated connections from same IP (potential brute force)
awk '{print $NF}' /var/log/ufw.log | sort | uniq -c | sort -nr | head
```

---

### 🧱 System Errors & Service Issues

```bash
# Kernel warnings or errors
grep -i "error\|warn" /var/log/kern.log

# Boot anomalies or missing services
dmesg | grep -i fail

# General service failures
grep -i "failed" /var/log/syslog
```

---

### 🌍 Web Server (Apache)

```bash
# See recent web requests
tail -n 50 /var/log/apache2/access.log

# Look for 404s, 500s, etc. (may signal scanning or exploit attempts)
grep " 404 " /var/log/apache2/access.log
grep " 500 " /var/log/apache2/error.log

# Suspicious IPs making repeated requests
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -nr | head
```

---

### 🔄 Log Rotation Awareness

Logs like `auth.log`, `syslog`, and `kern.log` rotate weekly/daily.
Use `ls -l /var/log/` to spot `.1`, `.gz`, or `.old` versions for older activity.

---

### 📌 Extra Tools

```bash
# Real-time log monitoring
tail -f /var/log/auth.log

# Search compressed logs (.gz)
zgrep "Failed password" /var/log/auth.log.1.gz
```

---

## 🧠 Triage Tip

If compromised:
1. Start with `auth.log` (initial access + privilege escalation)
2. Check `ufw.log` for egress/ingress attempts
3. Review service logs (Apache, MySQL, etc.)
4. Scan `/etc/crontab` and `crontab -l` for persistence
