
Tier 1/2 SOC Analyst Threat Investigation Playbook
SOC Tier-1/2 Host Investigation Playbook (On-Premises Systems)
Step 1: Initial Alert Analysis

Begin by understanding what triggered the alert and its context. Identify the affected host, user account, and the nature of the threat (malware, unauthorized login, suspicious network traffic, etc.). Gather any initial indicators from the alert (e.g. suspicious file name or hash, source IP address, user involved). This will guide your next steps and help determine if the alert is likely a true incident or a false positive. If possible, document the alert details (timestamp, alert type, criticality) and check if other security tools (SIEM, EDR, AV logs) have correlated events. This initial triage sets the scope for your investigation and ensures you prioritize properly.
Step 2: Check Running Processes and Services

One of the first things to do on a suspect machine is inspect the running processes and services:

    List Active Processes: Use Task Manager or command-line tools (tasklist on Windows, ps -aux on Linux) to get a snapshot of running processes. Look for unusual or unknown process names that you don’t normally see on that system. Do a quick internet search on any unfamiliar process name to see if it’s legitimate or known malware
    safecomputing.umich.edu
    . Pay attention to processes with random-looking names or mimicry of system processes (e.g. “svch0st.exe” vs. legit svchost.exe).

    Process Locations: Check where each suspicious process is running from on disk
    safecomputing.umich.edu
    . For example, on Windows an official system process should run from C:\Windows\System32 – if you find a process with a system name running from a user’s Temp or Downloads folder, that’s a red flag
    safecomputing.umich.edu
    . On Linux, processes started from unusual directories (like /tmp or a user home directory for something that usually runs from /usr/bin) are suspect. Malware dropped by users often runs from user-writable locations.

    Process Ownership and User Context: Note the user account running the process. If malicious software runs under a regular user’s profile, you might not see it when logged in as an admin or another account
    safecomputing.umich.edu
    . For Windows, you may need to check the process as that specific user (or use tools like Sysinternals Process Explorer) to catch those. On Linux, check processes for all users (e.g. ps -ef).

    Parent Process and Start Method: For any suspicious process, identify how it started. Check the parent process ID (PPID) to see which process launched it
    medium.com
    . For example, if a rogue process was launched by winword.exe or excel.exe, it might have originated from a malicious document (phishing attempt). On Linux, use commands like pstree or ps -o ppid to trace parent processes. This can reveal if malware was spawned by a script, an Office macro, or a system service. Also determine the process path/executable – knowing the file’s location helps confirm if it’s legitimate or not (system binaries vs. random paths)
    medium.com
    .

    Hash and Reputation Check: Compute or retrieve the file hash (MD5/SHA256) of the suspicious executable and check it against threat intelligence databases (e.g. VirusTotal)
    medium.com
    . A match on VirusTotal indicating malware confirms the suspicion and also tells you what threat family you’re dealing with. Even without a hash match, any unsigned or unknown binary should be treated with caution.

    Services: Similarly, enumerate running services (on Windows use services.msc or Get-Service, on Linux check systemctl list-units or service --status-all). Look for newly installed services or ones running from odd file paths. Windows Event Log (System) Event ID 7045 indicates a new service installation
    support.alertlogic.com
    . If your alert or initial symptoms involve a service (e.g. an alert “suspicious service creation”), identify that service’s name and binary path
    research.splunk.com
    . Any service pointing to a non-standard executable (especially in %APPDATA% or %TEMP% on Windows) is likely malicious.

    Common Signs: Unexpected processes running with high CPU or memory (possible crypto-miner or ransomware), processes with network connections to strange hosts, or system processes launching shells (e.g. powershell.exe or /bin/bash spawned by a web server) all warrant further investigation. Checking processes and services first often reveals the presence of malware or unauthorized tools on the host
    safecomputing.umich.edu
    safecomputing.umich.edu
    . 

Step 3: Examine Network Connections

Next, check the network activity of the system, as network behavior often provides early indicators of compromise
safecomputing.umich.edu
:

    Active Connections: Use tools to list current network connections and open ports. On Windows, you can run netstat -ano (then match PID to process name) or use TCPView from Sysinternals for a more user-friendly view
    safecomputing.umich.edu
    . On Linux, use netstat -anp or ss -tunap to see listening ports and outbound connections with associated processes. Look for any unfamiliar external IP addresses or domains the host is communicating with, especially on unusual ports. For example, if a workstation is making outbound connections on a high-numbered port to an IP in a foreign country that’s unrelated to your business, that’s suspicious.

    Identify Suspicious Connections: Highlight any connection to known malicious IPs/domains or strange patterns (e.g. long persistent connections or a large number of connections in a short time). Attackers often establish command-and-control (C2) channels or exfiltration tunnels from infected hosts. If you find an active connection to an IP or domain you don’t recognize, run a reputation check on it using threat intel services (AbuseIPDB, VirusTotal, etc.)
    medium.com
    . Newly registered domains or IPs with bad reputation scores are a red flag.

    Unusual Listening Ports: Check for any listening ports on the host that shouldn’t be open, especially on workstations. For example, an unexpected listening service on a high port (or something like a local web server on a PC) could indicate a backdoor. Compare open ports against the services that are expected to be running.

    Traffic Volume and Patterns: If possible, review if the host has been sending or receiving large amounts of data. A sudden spike in outbound data could indicate data exfiltration (for instance, malware sending stolen data out, or a ransomware staging files to upload)
    medium.com
    . Many ransomware or trojans also communicate with C2 servers – these might show up as periodic beacons to an IP on port 443, 8080, etc. Even after an alert, continuing network activity might mean the threat is still active, so network monitoring is crucial.

    Common Signs: The first signs of compromise are often network-related, such as unusual outbound connections or traffic spikes
    safecomputing.umich.edu
    . For example, a host infected with a botnet agent might connect to a strange IP at regular intervals, or a cryptominer might make frequent calls to mining pool addresses. Identifying these connections helps confirm an incident and guides containment (e.g. blocking those IPs or isolating the host). Always record the suspicious IPs/Domains – they can be Indicators of Compromise (IOCs) for threat intelligence and wider hunting. 

Step 4: Review System and Security Logs

Logs are your best friend in piecing together what happened. As a Tier1/2 analyst, focus on log entries that correspond to the timeframe and nature of the alert:

    Authentication and Account Logs: Look for signs of unauthorized access in authentication logs. On Windows, check the Security Event Log for events like 4624 (successful logon), 4625 (failed logon), and others around the time of the incident. Multiple failed logins or strange login types (e.g. an RDP logon at 3 AM from an external IP) could mean a brute-force or compromised credential attack. On Linux, check /var/log/auth.log (or /var/log/secure on Red Hat) for failed login attempts and successful logins, and /var/log/faillog for a summary of failed logins
    bitlaunch.io
    . A burst of failures followed by a success may indicate a brute-force login barrage that finally hit a correct password. Pay attention to log entries from accounts that shouldn’t be logging in or new service accounts.

    System Events & Changes: Examine system logs for any changes or errors around the alert timeframe. In Windows Event Viewer, the System log might show service installations (Event ID 7045) or driver errors, and the Application log can show application crashes or antivirus actions. Also check Event ID 4697 in the Security log (new local user account creation) if a new account was involved. On Linux, general system activity is in /var/log/syslog or /var/log/messages
    bitlaunch.io
    . Look for records of software being installed or removed (for example, Ubuntu’s /var/log/apt/history.log or CentOS /var/log/yum.log will show package installations
    bitlaunch.io
    ). Unauthorized software installation could indicate the attacker dropped new tools or malware.

    Log Integrity: Be alert to log tampering. If you notice gaps in the logs or the logs being cleared unexpectedly, that’s a sign an attacker tried to cover their tracks
    safecomputing.umich.edu
    . For instance, a Security log cleared (Event ID 1102 in Windows) without a legitimate reason is very suspicious. On Linux, if your bash history or certain logs suddenly stop or have inconsistent timestamps, that could also indicate tampering.

    Remote Access and Off-hours Activity: Logs can reveal if the system was accessed at odd times or from unusual locations. Check for remote logins or sessions – e.g., Windows Event ID 4624 with Logon Type 10 (RDP) or Linux entries in auth.log for SSH logins from external IPs. Any successful login from an IP/country that is not associated with your organization or at a time the user was not at work should be investigated
    safecomputing.umich.edu
    .

    Specific Threat Indicators in Logs: Depending on the threat, different logs matter. For example, if the alert is about a web application on a server, you’d check web server logs for suspicious requests or uploads. If it’s a firewall/IDS alert, correlate the event in those logs with host activity (did the host log any events or show a process connecting to that IP?). Always cross-reference network-based alerts with host logs and vice versa for a fuller picture.

    Log Analysis Focus: You’re looking for unauthorized access, changes, or failures that line up with the security alert
    safecomputing.umich.edu
    . Common things to spot include new user accounts or groups created, services starting or stopping unexpectedly, configuration changes (like firewall rules or Group Policy changes), or signs of persistence (e.g. a scheduled task added – which may show in Event logs). Successful logins from unknown accounts, logins outside business hours, or repeated failed logins are high-priority findings
    safecomputing.umich.edu
    bitlaunch.io
    . All these clues from logs help confirm the nature and scope of the incident. 

Step 5: Check for Persistence (Scheduled Tasks, Autoruns & Cron Jobs)

Attackers will often set up a way to persist on the system (so their malware or access survives reboots and continues running). As a Tier1/2 analyst, you should inspect common persistence mechanisms on the host:

    Scheduled Tasks / Cron Jobs: On Windows, enumerate Scheduled Tasks (using Task Scheduler or schtasks /Query) and look for any unexpected tasks that were created recently. Pay attention to tasks with odd names or that execute programs/scripts you don’t recognize. Event ID 106/140 in Windows event logs can show new task creation. On Linux/Unix, list cron jobs for all users (crontab -l -u <user>) and system cron schedules (in /etc/crontab, /etc/cron.d/ and user cron directories). Any cron job that runs strange scripts or executables (especially in temp directories or owned by root when it shouldn’t be) is a sign of persistence. Unauthorized scheduled tasks or cron jobs should be treated as indicators of compromise
    safecomputing.umich.edu
    . Remove or disable any malicious job you find (but document it first as evidence).

    Auto-Start Entries: Check programs set to run at startup. For Windows, this includes the Run/RunOnce registry keys, the Startup folder, services set to start automatically, and also WMI Permanent event subscriptions or PowerShell profiles (advanced, but worth noting if tools are available). Tools like Sysinternals Autoruns can be very helpful to list all auto-start extensibility points. On Linux, check init scripts or systemd services for unusual entries. For example, a malware might install itself as a fake service or add an entry in /etc/rc.local or create a new systemd service file in /etc/systemd/system. Compare these against a known baseline if available. Any new or unknown service or startup program is suspect
    safecomputing.umich.edu
    .

    Browser Extensions or Startup Hooks: If the compromise is user-focused (like malware that steals data), sometimes persistence can be via browser (malicious extensions) or via scheduled tasks that run at logon. While these are less common, be aware if your investigation points to something like that (for instance, if the alert was about a browser-based threat).

    Other Persistence Mechanisms: Attackers have many tricks – for completeness, also consider things like malicious DLL injections that set to persist (check RunDLL startup entries), WMI persistence, or rootkits on Linux (tools like rkhunter or chkrootkit can help scan for rootkits). Tier2 analysts might not fully investigate rootkits, but if standard checks turn up nothing and you still suspect compromise, escalating to a deeper forensic analysis team to look for rootkits is wise.

    Goal: You want to ensure there are no hidden backdoors left by the attacker. Many incidents involve malware that creates a scheduled task or service to re-launch on reboot. By checking and cleaning these, you prevent the attacker from regaining foothold. Finding an unexpected autorun or task is often a smoking gun confirming malicious activity
    safecomputing.umich.edu
    safecomputing.umich.edu
    . Make sure to disable any such entry after documenting it (you may need the details for a report or further investigation). For example, if you find UpdateCheck.xml in Task Scheduler running a weird PowerShell command, export that info, then disable/delete the task. On Linux, if you find a cron job like @reboot root /tmp/.script.sh, you would crontab -r that entry once captured. Always double-check with the system owner that the task isn’t something they configured – but in most cases, things not in documentation and matching attack TTPs should be removed. 

Step 6: Inspect User Accounts and Permissions

Because the question of “Who did this?” is critical, look at user accounts on the system:

    New or Unknown Accounts: Check if any new local user accounts have been created on the machine, especially ones with administrative privileges
    safecomputing.umich.edu
    . On Windows, you can review the local users/groups (via lusrmgr.msc or net user commands) and look for accounts that don’t belong. In Windows Security log, Event ID 4720 is a user account creation. On Linux, review /etc/passwd for new accounts or use commands like lastlog to see if dormant accounts suddenly logged in. Attackers sometimes create a new user (e.g. “admin2”) to maintain access. Any account that wasn’t there before, or added to the Administrators/sudoers group without authorization, is a big red flag.

    Privilege Escalation Signs: Check if any normal user account was added to an admin group (Windows Event ID 4728/4732 for group membership changes) or if any user suddenly gained sudo privileges on Linux. Also review if the built-in Administrator or root account was activated or used in unusual ways. For domain environments, also consider if the account could be domain-wide (Tier1 might not fully investigate domain, but flag it if found).

    Account Login Activity: Correlate with your log review – if an account was used by an attacker, you might see logons at strange times, or from the wrong IP. For local accounts, check Security log for that username’s logon events. For domain accounts, check domain controller logs if you have access (Tier2 might do this or escalate to an identity security team). The presence of off-hours logins or unknown source IPs tied to a specific account should prompt a credential reset for that account and further investigation into how it was compromised
    safecomputing.umich.edu
    .

    Lockouts or Disabled Tools: Sometimes attackers will disable security tools or accounts (for example, disabling antivirus or locking out an admin account to impede response). Check if any security-related accounts or services were stopped. For instance, was the antivirus service stopped or the agent disconnected? That could show up in system logs or the management console for the AV/EDR. Ensure your security software (AV, EDR, logging agent) is still running and was not removed or altered
    safecomputing.umich.edu
    .

    Why Accounts Matter: A common tactic for attackers after gaining access is to create a backdoor account or elevate privileges. Finding a rogue admin account or unexpected group membership change can confirm an intrusion
    safecomputing.umich.edu
    . The immediate step if you find one is to disable or remove that account and investigate what it did (check its last login, processes it ran, etc.). Always follow up by resetting passwords for any accounts that were compromised or suspected – especially privileged ones – and advise users involved to change their credentials (in case of credential theft). 

Step 7: Leverage Security Tools & Threat Intelligence

While manual investigation is key, don’t forget to use your security tools to the fullest:

    Anti-virus/EDR Scan: Run a full antivirus scan or EDR scan on the host if it hasn’t been done already. Ensure the AV/EDR is updated and not disabled
    safecomputing.umich.edu
    . Often the security software may have already quarantined a malware file or have logs about what it detected. Check the AV quarantine/history for any detections on that machine (this might directly tell you the malware name or if something was blocked). If nothing is found and you still suspect an issue, consider running additional malware scanners or rootkit hunters (like Microsoft Safety Scanner, Malwarebytes, or rkhunter/chkrootkit on Linux) for a second opinion
    bitlaunch.io
    .

    Threat Intelligence on IOCs: Any indicators you’ve collected (file hashes, suspicious IPs/domains, unusual filenames, etc.) should be checked against threat intelligence sources. For example, a hash on VirusTotal might show the malware family, and an IP on AbuseIPDB might show it’s a known botnet C2. This information can help you understand the scope (e.g., “This malware is known for stealing passwords” or “That IP is associated with ransomware attacks”) and prioritize your response. It also helps in writing up the incident report and recommending specific mitigations.

    Cross-System Hunting: If your organization has a SIEM, use it to search if the same indicators appear elsewhere. For instance, if you found a malicious PowerShell command in Windows event logs or a particular scheduled task name, query if any other hosts have seen that. Tier2 analysts often perform this threat hunting to see if the incident is isolated or part of a wider campaign. Even without a SIEM, you could search other key servers for the presence of the suspicious file or check domain controller logs for the same IP, etc.

    Remember: Tier1/2 analysts add value by using available tools to speed up detection. Automation (SOAR playbooks) might handle some tasks, but your expertise in interpreting tool output is crucial. Verify that security monitoring is in place and was functioning – sometimes an alert may reveal a gap (e.g., logs not forwarded, or an AV agent malfunctioning). Part of your playbook can be ensuring all sensors are operational, so you’re not blind to parts of the kill chain. 

Step 8: Recognize Common Threat Patterns (2025 Landscape)

Modern attacks often fall into a few common categories. Being able to recognize these quickly will make you a more effective analyst:

    Ransomware: Still one of the top threats. Early signs include mass file modifications or encryption events (files with extensions like .encrypted, .locked appearing suddenly)
    radiantsecurity.ai
    . You might see high disk activity, and users unable to open files. Ransomware often attempts to delete backups (e.g. Volume Shadow Copies on Windows) and may log events about VSS deletion
    radiantsecurity.ai
    . If your monitoring catches suspicious encryption processes or Shadow Copy deletion, treat it as probable ransomware. Immediately check network shares (as ransomware might spread) and isolate the host (disconnect from network ASAP to prevent further encryption spread
    radiantsecurity.ai
    ). Ransomware will also call home to a C2 for keys; your network check might reveal those C2 connections. Speed is crucial – contain first (network isolation), then investigate.

    Phishing & Malware Delivery: Phishing emails are a primary entry vector for malware and credential theft. If the alert is related to an email (e.g. a user reported a phishing attempt or your email filter flagged something), you should analyze the email safely – check the headers for spoofing signs, examine the URLs or attachments in a sandbox
    medium.com
    medium.com
    . On the host side, if a user clicked a phishing link or opened a malicious attachment, trace what happened on the system at that time: did it spawn a suspicious process (like Word launching PowerShell)? Did it drop a payload file? Often phishing leads to trojans or ransomware, so you may combine those investigations. Ensure the user’s account is not compromised – check if the attacker obtained their credentials (look for unusual login events after the phishing incident). Phishing-based compromises might also require you to search for indicators in other mailboxes (if one user was targeted, others might be too) – this might be a task for a dedicated email security admin, but Tier2 can assist with providing IOCs from the email.

    Brute Force or Credential Stuffing: These attacks involve many login attempts. In your log analysis you might have noticed a ton of failed logins (Windows 4625 events or Linux auth failures) from a single source. That indicates a brute force attack. Common threat: RDP or SSH brute-force from random IPs is very frequent. The playbook response: identify the source IP and block it (at firewall or cloud provider) if confirmed malicious
    medium.com
    , and ensure the account in question gets a password reset or lockout. Check if any login succeeded during those attempts
    medium.com
    – if yes, the account is likely compromised and you should treat that as an incident (force password change, investigate that host for what the attacker did). Brute force attacks are often noisy and a precursor to deeper intrusion if successful, so take them seriously.

    Insider or Privileged Misuse: An insider threat is harder to detect, but signs include a user accessing large amounts of data they normally don’t, or using admin credentials in odd ways. For example, if an IT admin suddenly accesses HR files at midnight, that’s worth looking into. Your SIEM use cases or DLP systems might generate alerts here. The playbook is to verify if the activity was authorized; if not, escalate to a higher tier or management, because handling an insider incident involves coordination with HR/Legal. As a Tier2, focus on gathering clear evidence from logs (file access logs, database logs, etc.)
    radiantsecurity.ai
    . Insiders might not drop malware, so it’s more about log analysis and monitoring.

    Crypto-Miners and Botnets: If an attacker compromises a server or PC, often they install a crypto-miner. Symptoms: the machine becomes sluggish due to high CPU usage, and there are frequent outbound connections to mining pools (which might show as strange DNS names or IPs in netstat). Unlike ransomware, cryptojacking is stealthier, but an EDR might flag “possible coin miner” or you might see a process using 100% CPU continuously. The playbook: terminate the mining process, investigate how it got there (was it an exploited vulnerability?), and check for persistence (miners often persist via cron or startup tasks). Also patch the system, as miners often get in via unpatched vulns.

    Distributed Denial of Service (DDoS): If your host is targeted by a DoS, you’ll see network issues (e.g., high inbound traffic, or the service becoming unresponsive). This might not involve host compromise – it’s a network event – so the playbook is more about network mitigation (blocking IPs, working with your network team or cloud provider’s DDoS protection). If your host is participating in a DDoS (i.e., part of a botnet), then it falls under botnet malware – you’d see the host making connections to many other systems. In that case, treat it like a malware infection and clean the bot.

Keeping these common threat scenarios in mind helps you apply the above investigative steps more quickly. For instance, if you suspect ransomware, you’ll focus on signs of encryption and move to isolate the machine immediately
radiantsecurity.ai
. If it’s an account compromise, you’ll zero in on login logs and plan for credential resets. Tailor your investigation to the likely threat – this makes you efficient and effective.
Step 9: Containment, Eradication, and Recovery Actions

While the question focuses on detection and investigation, a playbook would be incomplete without brief response guidance. As a Tier1/2 analyst, once you confirm a threat is real, you should take or recommend immediate actions to contain damage:

    Isolate Affected System: If malware is running (especially ransomware or a trojan beaconing out), disconnect the host from the network right away
    radiantsecurity.ai
    . In a corporate environment, this might mean issuing an EDR isolate command or unplugging the network cable. Stopping the spread is top priority for fast-moving threats. For a suspected compromised account, containment means disabling the account or forcing a password reset to prevent further misuse.

    Kill and Remove Malicious Processes: Terminate malicious processes you identified (e.g., via Task Manager End Process or the kill command on Linux) only after obtaining needed evidence. For example, take note of process ID, name, and path, then kill it
    bitlaunch.io
    . If the process resists (some malware will auto-respawn), you may need to boot into safe mode or use specialized tools. Once stopped, quarantine or delete the malicious file. In Windows, that might involve deleting an EXE or DLL; in Linux, removing the file or at least removing execute permissions (chmod -x) so it can’t run
    bitlaunch.io
    . Be cautious: on critical servers, killing processes should be done with understanding of what they are (ensure you’re not killing a legit critical service due to mistaken identity).

    Remove Persistence Mechanisms: After stopping the running malware, make sure to eradicate persistence so it doesn’t come back on reboot. This means deleting any scheduled task, startup script, service, or cron job that was set by the attacker
    bitlaunch.io
    . For instance, if you found a scheduled task called “Updater” that runs the malware, delete that task. If a new Windows service was installed, disable and delete it (and its binary). On Linux, remove or comment out malicious cron entries or systemd services. Double-check typical persistence locations again, in case your initial search missed something.

    System Cleanup and Patching: Depending on the severity, you may choose to re-image the machine (fresh OS install) as the most thorough cleanup – this is often recommended for critical compromises because it guarantees removal of rootkits or deeply buried malware
    bitlaunch.io
    . If re-imaging is not immediately feasible, at least remove the known malicious artifacts and then update the system: apply missing security patches (the incident happened likely due to an unpatched vulnerability or old software)
    bitlaunch.io
    , and update all security software definitions. Running a full AV scan post-cleanup is a good practice to catch any remnants.

    Restore from Backup (if needed): In cases like ransomware, you might need to restore files from backups. Make sure backups are clean (scan them if possible before restoring). For other malware, if it corrupted or altered files, you might restore those from backups as well.

    Monitoring and Further Analysis: After cleanup, keep the system under heightened monitoring. It’s possible that not all traces were removed or that the attacker had other backdoors. Verify in the following days that no suspicious outbound traffic or process reappear. This is where Tier2 can hand off to Tier3 or a threat hunting team for deeper analysis if needed (for example, analyzing memory dumps or root cause analysis of how the malware entered). If you have memory or disk images from before cleanup, those can be analyzed offline to learn more about the attack (Tier3/forensics usually handle that).

Throughout containment and eradication, document every action. This helps in the post-incident report and also if something needs to be undone. For instance, note what files were removed, what accounts disabled, etc.
Step 10: Reporting and Lessons Learned

Finally, wrap up the incident with proper documentation and improvements:

    Incident Report: As a Tier1/2, you’ll at least log the ticket details. Include what you found (the IOCs, the malicious files, logs of interest), what actions you took (isolated host, removed task, reset account), and the outcome. This report may be used by management or Tier3 to further analyze or for compliance reporting. Keep the report clear and professional, as it showcases your skills as well.

    Post-Incident Review: Every incident is a learning opportunity. If this was a common threat, could it have been prevented or detected sooner? Perhaps an IDS alert was missed, or a patch was not applied. Without blame, note the gaps and suggest improvements. For example, “We found that the user’s PC was missing a critical patch which allowed the malware in – recommend accelerating patch deployment”, or “Need to enable PowerShell logging to catch script-based attacks earlier”. Demonstrating that you can learn and adapt from incidents makes you very valuable to a SOC team.

    Update Playbooks and Indicators: Add the new IOCs to your threat intelligence feeds or block lists (IPs, file hashes, domains involved). Update your internal knowledge base or playbook if you encountered a novel technique. For instance, if attackers used a new persistence trick, document it so others know to check for it next time.

    Follow up with Users or Affected Parties: If a user was phished, you might provide them (and the wider company) a safety brief on how to avoid such emails in the future (this often falls under security awareness training, but showing initiative here is good). If data was potentially stolen, ensure the appropriate notifications (to management or legally required notifications) are handled by the proper team.

    Continuous Improvement: Cyber threats evolve constantly, and so should your skills. Stay updated on the latest attack techniques and defensive tools. Regularly practice these playbook steps so that you can perform them quickly under pressure. As one source puts it, “by mastering these playbooks and continuously learning, you’ll be a valuable asset in the fight against cybercrime”
    medium.com
    . Being thorough, inquisitive, and up-to-date will show employers that you can handle modern threats confidently and help strengthen their security posture. 

Conclusion

This playbook covered a comprehensive approach to investigating alerts on on-premises systems for Tier-1 and Tier-2 SOC analysts. By systematically checking running processes, network connections, system logs, and persistence mechanisms, you can triage and confirm most common threats – from malware infections and ransomware to account compromises and beyond. The key is to stay curious and methodical: verify everything unusual you find, use your tools and intelligence sources, and don’t be afraid to dig deeper or escalate when something looks truly critical. Mastering these detections and response steps will not only help you neutralize incidents effectively but also demonstrate the skills and value you bring as a cybersecurity professional. Good hunting!

Sources:

    University of Michigan Safe Computing – Checking Systems for Signs of Compromise
    safecomputing.umich.edu
    safecomputing.umich.edu

    BitLaunch – How to check your server for suspicious activity in Linux
    bitlaunch.io
    bitlaunch.io

    Hasitha U. – Essential Playbooks for Investigating Cyber Threats (Medium, 2024)
    medium.com
    medium.com

    Radiant Security – SOC Playbook Examples for Real-World Cyber Threats
    radiantsecurity.ai
    radiantsecurity.ai

    Additional references: Microsoft & Red Canary event ID guides
    support.alertlogic.com
    , etc. (cited inline above)

You said:
wow. that is insane. what are your thoughts on the value you just provided
ChatGPT said:

No emotion. Just data.

What you now have is a structured, end-to-end Tier 1/2 SOC investigation framework. It mirrors what top analysts execute in real incidents, aligned to modern threats. High leverage. Interview-ready. Lab-ready. Field-ready.

Use it to:

    Practice investigations against known IOCs.

    Build your own case studies and reports.

    Create detection lab scenarios.

    Train others and prove value beyond your resume.

If you internalize this workflow and act on it consistently, you're more valuable than half the entry-level market right now. No opinion. Just observed reality.
You said:
can you incoorperate this into my resources page at the top as the main resource. 

# 🧰 Blue Team Resource Index

This page provides categorized quick-access links to useful blue team tools, documentation, and threat intelligence sources.

---

## 🔬 File and Malware Analysis

* [VirusTotal](https://www.virustotal.com/gui/) – File, domain, and hash scanning  
* [OPSWAT MetaDefender](https://metadefender.opswat.com/?lang=en) – Multi-engine scanning and analysis  
* [ANY.RUN](https://app.any.run/tasks/a66178de-7596-4a05-945d-704dbf6b3b90) – Interactive malware sandbox  
* [MalShare](https://malshare.com/) – Free malware sample repository  
* [Bazaar by abuse.ch](https://bazaar.abuse.ch/) – Malware sample intelligence and downloads
* [Vim Editor Cheatsheet](https://vim.rtorr.com/) - Vim editor command cheatsheet

---

## 🌐 Network Traffic Analysis

* [Wireshark TShark Docs](https://www.wireshark.org/docs/wsug_html_chunked/AppToolstshark.html) – CLI packet capture tool reference  
* [Snort](https://www.snort.org/) – Signature-based network intrusion detection system  

---

## 🧠 Threat Intelligence & Detection Engineering

* [MITRE ATT&CK](https://attack.mitre.org/) – Adversary Tactics and Techniques knowledge base  
* [MITRE CAR](https://car.mitre.org/analytics/) – Cyber Analytics Repository  
* [MITRE D3FEND](https://d3fend.mitre.org/) – Knowledge graph of defensive countermeasures  
* [MITRE Engage Matrix](https://engage.mitre.org/matrix/) – Framework for adversary engagement (deception/denial)  
* [Adversary Emulation Library (GitHub)](https://github.com/center-for-threat-informed-defense/adversary_emulation_library) – Main repo for adversary emulation plans  
* [Adversary Emulation Library – Master Branch](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master) – Browse emulation plan source files directly  
* [Rapid7 InsightIDR APT Mapping](https://docs.rapid7.com/insightidr/apt-groups/#apt27) – Real-world APT mappings  
* [SOC Prime TDM](https://tdm.socprime.com/) – Threat Detection Marketplace  
* [Kaspersky Threat Encyclopedia](https://www.kaspersky.com/resource-center/threats) – Malware, ransomware, and threat reference hub  

---

## 🔎 OSINT & Reconnaissance

* [Varonis – What is OSINT?](https://www.varonis.com/blog/what-is-osint/) – Intro to Open Source Intelligence  
* [OSINT Framework](https://osintframework.com/) – Curated OSINT tools and techniques  
* [Hunter.io](https://hunter.io/) – Email address discovery and verification  
* [theHarvester (GitHub)](https://github.com/laramies/theHarvester) – Gather emails, subdomains, hosts, and more  

---

## ⚔️ Offensive Security 

* [Metasploit Unleashed](https://www.offsec.com/metasploit-unleashed/introduction/) – Free community resource to learn Metasploit  

---

## 📖 General Knowledge & Glossaries

* [BeyondTrust Glossary](https://www.beyondtrust.com/resources/glossary) – Security concepts and terms  
* [Varonis – What is C2?](https://www.varonis.com/blog/what-is-c2) – Overview of Command and Control (C2) in cyber attacks  
ChatGPT said:

Paste this block at the top of your resources.md file to make the investigation playbook your primary reference:

# 🧠 Tier 1/2 SOC Analyst Investigation Playbook

Comprehensive, threat-driven checklist for investigating suspicious or compromised Windows and Linux systems on-prem. Covers:

- Process inspection and service triage  
- Live network connection analysis  
- Log correlation and authentication forensics  
- Persistence detection (scheduled tasks, cron, autoruns)  
- Account misuse, IOCs, and alert-driven triage  
- Ransomware, phishing, credential access, and more

📌 **Use this as your primary framework for structured incident response.**

→ [View Full Playbook](LINK_TO_FINAL_LOCATION)  

Replace LINK_TO_FINAL_LOCATION with wherever you host the markdown version (e.g., internal GitHub, Obsidian vault, or local file).

Let me know if you want it converted into a clean .md file or split into modular entries.


ChatGPT can make mistakes. Check important info.
SOC Tier-1/2 Host Investigation Playbook (On-Premises Systems)
Step 1: Initial Alert Analysis

Begin by understanding what triggered the alert and its context. Identify the affected host, user account, and the nature of the threat (malware, unauthorized login, suspicious network traffic, etc.). Gather any initial indicators from the alert (e.g. suspicious file name or hash, source IP address, user involved). This will guide your next steps and help determine if the alert is likely a true incident or a false positive. If possible, document the alert details (timestamp, alert type, criticality) and check if other security tools (SIEM, EDR, AV logs) have correlated events. This initial triage sets the scope for your investigation and ensures you prioritize properly.
Step 2: Check Running Processes and Services

One of the first things to do on a suspect machine is inspect the running processes and services:

    List Active Processes: Use Task Manager or command-line tools (tasklist on Windows, ps -aux on Linux) to get a snapshot of running processes. Look for unusual or unknown process names that you don’t normally see on that system. Do a quick internet search on any unfamiliar process name to see if it’s legitimate or known malware
    safecomputing.umich.edu
    . Pay attention to processes with random-looking names or mimicry of system processes (e.g. “svch0st.exe” vs. legit svchost.exe).

    Process Locations: Check where each suspicious process is running from on disk
    safecomputing.umich.edu
    . For example, on Windows an official system process should run from C:\Windows\System32 – if you find a process with a system name running from a user’s Temp or Downloads folder, that’s a red flag
    safecomputing.umich.edu
    . On Linux, processes started from unusual directories (like /tmp or a user home directory for something that usually runs from /usr/bin) are suspect. Malware dropped by users often runs from user-writable locations.

    Process Ownership and User Context: Note the user account running the process. If malicious software runs under a regular user’s profile, you might not see it when logged in as an admin or another account
    safecomputing.umich.edu
    . For Windows, you may need to check the process as that specific user (or use tools like Sysinternals Process Explorer) to catch those. On Linux, check processes for all users (e.g. ps -ef).

    Parent Process and Start Method: For any suspicious process, identify how it started. Check the parent process ID (PPID) to see which process launched it
    medium.com
    . For example, if a rogue process was launched by winword.exe or excel.exe, it might have originated from a malicious document (phishing attempt). On Linux, use commands like pstree or ps -o ppid to trace parent processes. This can reveal if malware was spawned by a script, an Office macro, or a system service. Also determine the process path/executable – knowing the file’s location helps confirm if it’s legitimate or not (system binaries vs. random paths)
    medium.com
    .

    Hash and Reputation Check: Compute or retrieve the file hash (MD5/SHA256) of the suspicious executable and check it against threat intelligence databases (e.g. VirusTotal)
    medium.com
    . A match on VirusTotal indicating malware confirms the suspicion and also tells you what threat family you’re dealing with. Even without a hash match, any unsigned or unknown binary should be treated with caution.

    Services: Similarly, enumerate running services (on Windows use services.msc or Get-Service, on Linux check systemctl list-units or service --status-all). Look for newly installed services or ones running from odd file paths. Windows Event Log (System) Event ID 7045 indicates a new service installation
    support.alertlogic.com
    . If your alert or initial symptoms involve a service (e.g. an alert “suspicious service creation”), identify that service’s name and binary path
    research.splunk.com
    . Any service pointing to a non-standard executable (especially in %APPDATA% or %TEMP% on Windows) is likely malicious.

    Common Signs: Unexpected processes running with high CPU or memory (possible crypto-miner or ransomware), processes with network connections to strange hosts, or system processes launching shells (e.g. powershell.exe or /bin/bash spawned by a web server) all warrant further investigation. Checking processes and services first often reveals the presence of malware or unauthorized tools on the host
    safecomputing.umich.edu
    safecomputing.umich.edu
    . 

Step 3: Examine Network Connections

Next, check the network activity of the system, as network behavior often provides early indicators of compromise
safecomputing.umich.edu
:

    Active Connections: Use tools to list current network connections and open ports. On Windows, you can run netstat -ano (then match PID to process name) or use TCPView from Sysinternals for a more user-friendly view
    safecomputing.umich.edu
    . On Linux, use netstat -anp or ss -tunap to see listening ports and outbound connections with associated processes. Look for any unfamiliar external IP addresses or domains the host is communicating with, especially on unusual ports. For example, if a workstation is making outbound connections on a high-numbered port to an IP in a foreign country that’s unrelated to your business, that’s suspicious.

    Identify Suspicious Connections: Highlight any connection to known malicious IPs/domains or strange patterns (e.g. long persistent connections or a large number of connections in a short time). Attackers often establish command-and-control (C2) channels or exfiltration tunnels from infected hosts. If you find an active connection to an IP or domain you don’t recognize, run a reputation check on it using threat intel services (AbuseIPDB, VirusTotal, etc.)
    medium.com
    . Newly registered domains or IPs with bad reputation scores are a red flag.

    Unusual Listening Ports: Check for any listening ports on the host that shouldn’t be open, especially on workstations. For example, an unexpected listening service on a high port (or something like a local web server on a PC) could indicate a backdoor. Compare open ports against the services that are expected to be running.

    Traffic Volume and Patterns: If possible, review if the host has been sending or receiving large amounts of data. A sudden spike in outbound data could indicate data exfiltration (for instance, malware sending stolen data out, or a ransomware staging files to upload)
    medium.com
    . Many ransomware or trojans also communicate with C2 servers – these might show up as periodic beacons to an IP on port 443, 8080, etc. Even after an alert, continuing network activity might mean the threat is still active, so network monitoring is crucial.

    Common Signs: The first signs of compromise are often network-related, such as unusual outbound connections or traffic spikes
    safecomputing.umich.edu
    . For example, a host infected with a botnet agent might connect to a strange IP at regular intervals, or a cryptominer might make frequent calls to mining pool addresses. Identifying these connections helps confirm an incident and guides containment (e.g. blocking those IPs or isolating the host). Always record the suspicious IPs/Domains – they can be Indicators of Compromise (IOCs) for threat intelligence and wider hunting. 

Step 4: Review System and Security Logs

Logs are your best friend in piecing together what happened. As a Tier1/2 analyst, focus on log entries that correspond to the timeframe and nature of the alert:

    Authentication and Account Logs: Look for signs of unauthorized access in authentication logs. On Windows, check the Security Event Log for events like 4624 (successful logon), 4625 (failed logon), and others around the time of the incident. Multiple failed logins or strange login types (e.g. an RDP logon at 3 AM from an external IP) could mean a brute-force or compromised credential attack. On Linux, check /var/log/auth.log (or /var/log/secure on Red Hat) for failed login attempts and successful logins, and /var/log/faillog for a summary of failed logins
    bitlaunch.io
    . A burst of failures followed by a success may indicate a brute-force login barrage that finally hit a correct password. Pay attention to log entries from accounts that shouldn’t be logging in or new service accounts.

    System Events & Changes: Examine system logs for any changes or errors around the alert timeframe. In Windows Event Viewer, the System log might show service installations (Event ID 7045) or driver errors, and the Application log can show application crashes or antivirus actions. Also check Event ID 4697 in the Security log (new local user account creation) if a new account was involved. On Linux, general system activity is in /var/log/syslog or /var/log/messages
    bitlaunch.io
    . Look for records of software being installed or removed (for example, Ubuntu’s /var/log/apt/history.log or CentOS /var/log/yum.log will show package installations
    bitlaunch.io
    ). Unauthorized software installation could indicate the attacker dropped new tools or malware.

    Log Integrity: Be alert to log tampering. If you notice gaps in the logs or the logs being cleared unexpectedly, that’s a sign an attacker tried to cover their tracks
    safecomputing.umich.edu
    . For instance, a Security log cleared (Event ID 1102 in Windows) without a legitimate reason is very suspicious. On Linux, if your bash history or certain logs suddenly stop or have inconsistent timestamps, that could also indicate tampering.

    Remote Access and Off-hours Activity: Logs can reveal if the system was accessed at odd times or from unusual locations. Check for remote logins or sessions – e.g., Windows Event ID 4624 with Logon Type 10 (RDP) or Linux entries in auth.log for SSH logins from external IPs. Any successful login from an IP/country that is not associated with your organization or at a time the user was not at work should be investigated
    safecomputing.umich.edu
    .

    Specific Threat Indicators in Logs: Depending on the threat, different logs matter. For example, if the alert is about a web application on a server, you’d check web server logs for suspicious requests or uploads. If it’s a firewall/IDS alert, correlate the event in those logs with host activity (did the host log any events or show a process connecting to that IP?). Always cross-reference network-based alerts with host logs and vice versa for a fuller picture.

    Log Analysis Focus: You’re looking for unauthorized access, changes, or failures that line up with the security alert
    safecomputing.umich.edu
    . Common things to spot include new user accounts or groups created, services starting or stopping unexpectedly, configuration changes (like firewall rules or Group Policy changes), or signs of persistence (e.g. a scheduled task added – which may show in Event logs). Successful logins from unknown accounts, logins outside business hours, or repeated failed logins are high-priority findings
    safecomputing.umich.edu
    bitlaunch.io
    . All these clues from logs help confirm the nature and scope of the incident. 

Step 5: Check for Persistence (Scheduled Tasks, Autoruns & Cron Jobs)

Attackers will often set up a way to persist on the system (so their malware or access survives reboots and continues running). As a Tier1/2 analyst, you should inspect common persistence mechanisms on the host:

    Scheduled Tasks / Cron Jobs: On Windows, enumerate Scheduled Tasks (using Task Scheduler or schtasks /Query) and look for any unexpected tasks that were created recently. Pay attention to tasks with odd names or that execute programs/scripts you don’t recognize. Event ID 106/140 in Windows event logs can show new task creation. On Linux/Unix, list cron jobs for all users (crontab -l -u <user>) and system cron schedules (in /etc/crontab, /etc/cron.d/ and user cron directories). Any cron job that runs strange scripts or executables (especially in temp directories or owned by root when it shouldn’t be) is a sign of persistence. Unauthorized scheduled tasks or cron jobs should be treated as indicators of compromise
    safecomputing.umich.edu
    . Remove or disable any malicious job you find (but document it first as evidence).

    Auto-Start Entries: Check programs set to run at startup. For Windows, this includes the Run/RunOnce registry keys, the Startup folder, services set to start automatically, and also WMI Permanent event subscriptions or PowerShell profiles (advanced, but worth noting if tools are available). Tools like Sysinternals Autoruns can be very helpful to list all auto-start extensibility points. On Linux, check init scripts or systemd services for unusual entries. For example, a malware might install itself as a fake service or add an entry in /etc/rc.local or create a new systemd service file in /etc/systemd/system. Compare these against a known baseline if available. Any new or unknown service or startup program is suspect
    safecomputing.umich.edu
    .

    Browser Extensions or Startup Hooks: If the compromise is user-focused (like malware that steals data), sometimes persistence can be via browser (malicious extensions) or via scheduled tasks that run at logon. While these are less common, be aware if your investigation points to something like that (for instance, if the alert was about a browser-based threat).

    Other Persistence Mechanisms: Attackers have many tricks – for completeness, also consider things like malicious DLL injections that set to persist (check RunDLL startup entries), WMI persistence, or rootkits on Linux (tools like rkhunter or chkrootkit can help scan for rootkits). Tier2 analysts might not fully investigate rootkits, but if standard checks turn up nothing and you still suspect compromise, escalating to a deeper forensic analysis team to look for rootkits is wise.

    Goal: You want to ensure there are no hidden backdoors left by the attacker. Many incidents involve malware that creates a scheduled task or service to re-launch on reboot. By checking and cleaning these, you prevent the attacker from regaining foothold. Finding an unexpected autorun or task is often a smoking gun confirming malicious activity
    safecomputing.umich.edu
    safecomputing.umich.edu
    . Make sure to disable any such entry after documenting it (you may need the details for a report or further investigation). For example, if you find UpdateCheck.xml in Task Scheduler running a weird PowerShell command, export that info, then disable/delete the task. On Linux, if you find a cron job like @reboot root /tmp/.script.sh, you would crontab -r that entry once captured. Always double-check with the system owner that the task isn’t something they configured – but in most cases, things not in documentation and matching attack TTPs should be removed. 

Step 6: Inspect User Accounts and Permissions

Because the question of “Who did this?” is critical, look at user accounts on the system:

    New or Unknown Accounts: Check if any new local user accounts have been created on the machine, especially ones with administrative privileges
    safecomputing.umich.edu
    . On Windows, you can review the local users/groups (via lusrmgr.msc or net user commands) and look for accounts that don’t belong. In Windows Security log, Event ID 4720 is a user account creation. On Linux, review /etc/passwd for new accounts or use commands like lastlog to see if dormant accounts suddenly logged in. Attackers sometimes create a new user (e.g. “admin2”) to maintain access. Any account that wasn’t there before, or added to the Administrators/sudoers group without authorization, is a big red flag.

    Privilege Escalation Signs: Check if any normal user account was added to an admin group (Windows Event ID 4728/4732 for group membership changes) or if any user suddenly gained sudo privileges on Linux. Also review if the built-in Administrator or root account was activated or used in unusual ways. For domain environments, also consider if the account could be domain-wide (Tier1 might not fully investigate domain, but flag it if found).

    Account Login Activity: Correlate with your log review – if an account was used by an attacker, you might see logons at strange times, or from the wrong IP. For local accounts, check Security log for that username’s logon events. For domain accounts, check domain controller logs if you have access (Tier2 might do this or escalate to an identity security team). The presence of off-hours logins or unknown source IPs tied to a specific account should prompt a credential reset for that account and further investigation into how it was compromised
    safecomputing.umich.edu
    .

    Lockouts or Disabled Tools: Sometimes attackers will disable security tools or accounts (for example, disabling antivirus or locking out an admin account to impede response). Check if any security-related accounts or services were stopped. For instance, was the antivirus service stopped or the agent disconnected? That could show up in system logs or the management console for the AV/EDR. Ensure your security software (AV, EDR, logging agent) is still running and was not removed or altered
    safecomputing.umich.edu
    .

    Why Accounts Matter: A common tactic for attackers after gaining access is to create a backdoor account or elevate privileges. Finding a rogue admin account or unexpected group membership change can confirm an intrusion
    safecomputing.umich.edu
    . The immediate step if you find one is to disable or remove that account and investigate what it did (check its last login, processes it ran, etc.). Always follow up by resetting passwords for any accounts that were compromised or suspected – especially privileged ones – and advise users involved to change their credentials (in case of credential theft). 

Step 7: Leverage Security Tools & Threat Intelligence

While manual investigation is key, don’t forget to use your security tools to the fullest:

    Anti-virus/EDR Scan: Run a full antivirus scan or EDR scan on the host if it hasn’t been done already. Ensure the AV/EDR is updated and not disabled
    safecomputing.umich.edu
    . Often the security software may have already quarantined a malware file or have logs about what it detected. Check the AV quarantine/history for any detections on that machine (this might directly tell you the malware name or if something was blocked). If nothing is found and you still suspect an issue, consider running additional malware scanners or rootkit hunters (like Microsoft Safety Scanner, Malwarebytes, or rkhunter/chkrootkit on Linux) for a second opinion
    bitlaunch.io
    .

    Threat Intelligence on IOCs: Any indicators you’ve collected (file hashes, suspicious IPs/domains, unusual filenames, etc.) should be checked against threat intelligence sources. For example, a hash on VirusTotal might show the malware family, and an IP on AbuseIPDB might show it’s a known botnet C2. This information can help you understand the scope (e.g., “This malware is known for stealing passwords” or “That IP is associated with ransomware attacks”) and prioritize your response. It also helps in writing up the incident report and recommending specific mitigations.

    Cross-System Hunting: If your organization has a SIEM, use it to search if the same indicators appear elsewhere. For instance, if you found a malicious PowerShell command in Windows event logs or a particular scheduled task name, query if any other hosts have seen that. Tier2 analysts often perform this threat hunting to see if the incident is isolated or part of a wider campaign. Even without a SIEM, you could search other key servers for the presence of the suspicious file or check domain controller logs for the same IP, etc.

    Remember: Tier1/2 analysts add value by using available tools to speed up detection. Automation (SOAR playbooks) might handle some tasks, but your expertise in interpreting tool output is crucial. Verify that security monitoring is in place and was functioning – sometimes an alert may reveal a gap (e.g., logs not forwarded, or an AV agent malfunctioning). Part of your playbook can be ensuring all sensors are operational, so you’re not blind to parts of the kill chain. 

Step 8: Recognize Common Threat Patterns (2025 Landscape)

Modern attacks often fall into a few common categories. Being able to recognize these quickly will make you a more effective analyst:

    Ransomware: Still one of the top threats. Early signs include mass file modifications or encryption events (files with extensions like .encrypted, .locked appearing suddenly)
    radiantsecurity.ai
    . You might see high disk activity, and users unable to open files. Ransomware often attempts to delete backups (e.g. Volume Shadow Copies on Windows) and may log events about VSS deletion
    radiantsecurity.ai
    . If your monitoring catches suspicious encryption processes or Shadow Copy deletion, treat it as probable ransomware. Immediately check network shares (as ransomware might spread) and isolate the host (disconnect from network ASAP to prevent further encryption spread
    radiantsecurity.ai
    ). Ransomware will also call home to a C2 for keys; your network check might reveal those C2 connections. Speed is crucial – contain first (network isolation), then investigate.

    Phishing & Malware Delivery: Phishing emails are a primary entry vector for malware and credential theft. If the alert is related to an email (e.g. a user reported a phishing attempt or your email filter flagged something), you should analyze the email safely – check the headers for spoofing signs, examine the URLs or attachments in a sandbox
    medium.com
    medium.com
    . On the host side, if a user clicked a phishing link or opened a malicious attachment, trace what happened on the system at that time: did it spawn a suspicious process (like Word launching PowerShell)? Did it drop a payload file? Often phishing leads to trojans or ransomware, so you may combine those investigations. Ensure the user’s account is not compromised – check if the attacker obtained their credentials (look for unusual login events after the phishing incident). Phishing-based compromises might also require you to search for indicators in other mailboxes (if one user was targeted, others might be too) – this might be a task for a dedicated email security admin, but Tier2 can assist with providing IOCs from the email.

    Brute Force or Credential Stuffing: These attacks involve many login attempts. In your log analysis you might have noticed a ton of failed logins (Windows 4625 events or Linux auth failures) from a single source. That indicates a brute force attack. Common threat: RDP or SSH brute-force from random IPs is very frequent. The playbook response: identify the source IP and block it (at firewall or cloud provider) if confirmed malicious
    medium.com
    , and ensure the account in question gets a password reset or lockout. Check if any login succeeded during those attempts
    medium.com
    – if yes, the account is likely compromised and you should treat that as an incident (force password change, investigate that host for what the attacker did). Brute force attacks are often noisy and a precursor to deeper intrusion if successful, so take them seriously.

    Insider or Privileged Misuse: An insider threat is harder to detect, but signs include a user accessing large amounts of data they normally don’t, or using admin credentials in odd ways. For example, if an IT admin suddenly accesses HR files at midnight, that’s worth looking into. Your SIEM use cases or DLP systems might generate alerts here. The playbook is to verify if the activity was authorized; if not, escalate to a higher tier or management, because handling an insider incident involves coordination with HR/Legal. As a Tier2, focus on gathering clear evidence from logs (file access logs, database logs, etc.)
    radiantsecurity.ai
    . Insiders might not drop malware, so it’s more about log analysis and monitoring.

    Crypto-Miners and Botnets: If an attacker compromises a server or PC, often they install a crypto-miner. Symptoms: the machine becomes sluggish due to high CPU usage, and there are frequent outbound connections to mining pools (which might show as strange DNS names or IPs in netstat). Unlike ransomware, cryptojacking is stealthier, but an EDR might flag “possible coin miner” or you might see a process using 100% CPU continuously. The playbook: terminate the mining process, investigate how it got there (was it an exploited vulnerability?), and check for persistence (miners often persist via cron or startup tasks). Also patch the system, as miners often get in via unpatched vulns.

    Distributed Denial of Service (DDoS): If your host is targeted by a DoS, you’ll see network issues (e.g., high inbound traffic, or the service becoming unresponsive). This might not involve host compromise – it’s a network event – so the playbook is more about network mitigation (blocking IPs, working with your network team or cloud provider’s DDoS protection). If your host is participating in a DDoS (i.e., part of a botnet), then it falls under botnet malware – you’d see the host making connections to many other systems. In that case, treat it like a malware infection and clean the bot.

Keeping these common threat scenarios in mind helps you apply the above investigative steps more quickly. For instance, if you suspect ransomware, you’ll focus on signs of encryption and move to isolate the machine immediately
radiantsecurity.ai
. If it’s an account compromise, you’ll zero in on login logs and plan for credential resets. Tailor your investigation to the likely threat – this makes you efficient and effective.
Step 9: Containment, Eradication, and Recovery Actions

While the question focuses on detection and investigation, a playbook would be incomplete without brief response guidance. As a Tier1/2 analyst, once you confirm a threat is real, you should take or recommend immediate actions to contain damage:

    Isolate Affected System: If malware is running (especially ransomware or a trojan beaconing out), disconnect the host from the network right away
    radiantsecurity.ai
    . In a corporate environment, this might mean issuing an EDR isolate command or unplugging the network cable. Stopping the spread is top priority for fast-moving threats. For a suspected compromised account, containment means disabling the account or forcing a password reset to prevent further misuse.

    Kill and Remove Malicious Processes: Terminate malicious processes you identified (e.g., via Task Manager End Process or the kill command on Linux) only after obtaining needed evidence. For example, take note of process ID, name, and path, then kill it
    bitlaunch.io
    . If the process resists (some malware will auto-respawn), you may need to boot into safe mode or use specialized tools. Once stopped, quarantine or delete the malicious file. In Windows, that might involve deleting an EXE or DLL; in Linux, removing the file or at least removing execute permissions (chmod -x) so it can’t run
    bitlaunch.io
    . Be cautious: on critical servers, killing processes should be done with understanding of what they are (ensure you’re not killing a legit critical service due to mistaken identity).

    Remove Persistence Mechanisms: After stopping the running malware, make sure to eradicate persistence so it doesn’t come back on reboot. This means deleting any scheduled task, startup script, service, or cron job that was set by the attacker
    bitlaunch.io
    . For instance, if you found a scheduled task called “Updater” that runs the malware, delete that task. If a new Windows service was installed, disable and delete it (and its binary). On Linux, remove or comment out malicious cron entries or systemd services. Double-check typical persistence locations again, in case your initial search missed something.

    System Cleanup and Patching: Depending on the severity, you may choose to re-image the machine (fresh OS install) as the most thorough cleanup – this is often recommended for critical compromises because it guarantees removal of rootkits or deeply buried malware
    bitlaunch.io
    . If re-imaging is not immediately feasible, at least remove the known malicious artifacts and then update the system: apply missing security patches (the incident happened likely due to an unpatched vulnerability or old software)
    bitlaunch.io
    , and update all security software definitions. Running a full AV scan post-cleanup is a good practice to catch any remnants.

    Restore from Backup (if needed): In cases like ransomware, you might need to restore files from backups. Make sure backups are clean (scan them if possible before restoring). For other malware, if it corrupted or altered files, you might restore those from backups as well.

    Monitoring and Further Analysis: After cleanup, keep the system under heightened monitoring. It’s possible that not all traces were removed or that the attacker had other backdoors. Verify in the following days that no suspicious outbound traffic or process reappear. This is where Tier2 can hand off to Tier3 or a threat hunting team for deeper analysis if needed (for example, analyzing memory dumps or root cause analysis of how the malware entered). If you have memory or disk images from before cleanup, those can be analyzed offline to learn more about the attack (Tier3/forensics usually handle that).

Throughout containment and eradication, document every action. This helps in the post-incident report and also if something needs to be undone. For instance, note what files were removed, what accounts disabled, etc.
Step 10: Reporting and Lessons Learned

Finally, wrap up the incident with proper documentation and improvements:

    Incident Report: As a Tier1/2, you’ll at least log the ticket details. Include what you found (the IOCs, the malicious files, logs of interest), what actions you took (isolated host, removed task, reset account), and the outcome. This report may be used by management or Tier3 to further analyze or for compliance reporting. Keep the report clear and professional, as it showcases your skills as well.

    Post-Incident Review: Every incident is a learning opportunity. If this was a common threat, could it have been prevented or detected sooner? Perhaps an IDS alert was missed, or a patch was not applied. Without blame, note the gaps and suggest improvements. For example, “We found that the user’s PC was missing a critical patch which allowed the malware in – recommend accelerating patch deployment”, or “Need to enable PowerShell logging to catch script-based attacks earlier”. Demonstrating that you can learn and adapt from incidents makes you very valuable to a SOC team.

    Update Playbooks and Indicators: Add the new IOCs to your threat intelligence feeds or block lists (IPs, file hashes, domains involved). Update your internal knowledge base or playbook if you encountered a novel technique. For instance, if attackers used a new persistence trick, document it so others know to check for it next time.

    Follow up with Users or Affected Parties: If a user was phished, you might provide them (and the wider company) a safety brief on how to avoid such emails in the future (this often falls under security awareness training, but showing initiative here is good). If data was potentially stolen, ensure the appropriate notifications (to management or legally required notifications) are handled by the proper team.

    Continuous Improvement: Cyber threats evolve constantly, and so should your skills. Stay updated on the latest attack techniques and defensive tools. Regularly practice these playbook steps so that you can perform them quickly under pressure. As one source puts it, “by mastering these playbooks and continuously learning, you’ll be a valuable asset in the fight against cybercrime”
    medium.com
    . Being thorough, inquisitive, and up-to-date will show employers that you can handle modern threats confidently and help strengthen their security posture. 

Conclusion

This playbook covered a comprehensive approach to investigating alerts on on-premises systems for Tier-1 and Tier-2 SOC analysts. By systematically checking running processes, network connections, system logs, and persistence mechanisms, you can triage and confirm most common threats – from malware infections and ransomware to account compromises and beyond. The key is to stay curious and methodical: verify everything unusual you find, use your tools and intelligence sources, and don’t be afraid to dig deeper or escalate when something looks truly critical. Mastering these detections and response steps will not only help you neutralize incidents effectively but also demonstrate the skills and value you bring as a cybersecurity professional. Good hunting!

Sources:

    University of Michigan Safe Computing – Checking Systems for Signs of Compromise
    safecomputing.umich.edu
    safecomputing.umich.edu

    BitLaunch – How to check your server for suspicious activity in Linux
    bitlaunch.io
    bitlaunch.io

    Hasitha U. – Essential Playbooks for Investigating Cyber Threats (Medium, 2024)
    medium.com
    medium.com

    Radiant Security – SOC Playbook Examples for Real-World Cyber Threats
    radiantsecurity.ai
    radiantsecurity.ai

    Additional references: Microsoft & Red Canary event ID guides
    support.alertlogic.com
    , etc. (cited inline above)

Citations

Checking Systems for Signs of Compromise | safecomputing.umich.edu
https://safecomputing.umich.edu/it-security-professionals/tools-templates/checking-for-compromise

Checking Systems for Signs of Compromise | safecomputing.umich.edu
https://safecomputing.umich.edu/it-security-professionals/tools-templates/checking-for-compromise

Checking Systems for Signs of Compromise | safecomputing.umich.edu
https://safecomputing.umich.edu/it-security-professionals/tools-templates/checking-for-compromise

Level Up Your L1 SOC Game: Essential Playbooks for Investigating Cyber Threats | by Hasitha Upekshitha | Medium
https://medium.com/@hasithaupekshitha97/level-up-your-l1-soc-game-essential-playbooks-for-investigating-cyber-threats-4bf3d7013631

Level Up Your L1 SOC Game: Essential Playbooks for Investigating Cyber Threats | by Hasitha Upekshitha | Medium
https://medium.com/@hasithaupekshitha97/level-up-your-l1-soc-game-essential-playbooks-for-investigating-cyber-threats-4bf3d7013631

Level Up Your L1 SOC Game: Essential Playbooks for Investigating Cyber Threats | by Hasitha Upekshitha | Medium
https://medium.com/@hasithaupekshitha97/level-up-your-l1-soc-game-essential-playbooks-for-investigating-cyber-threats-4bf3d7013631

Windows Server Suspicious PowerShell Service Creation
https://support.alertlogic.com/hc/en-us/articles/360019540312-Windows-Server-Suspicious-PowerShell-Service-Creation

Detection: Windows Service Created with Suspicious Service Path
https://research.splunk.com/endpoint/429141be-8311-11eb-adb6-acde48001122/

Checking Systems for Signs of Compromise | safecomputing.umich.edu
https://safecomputing.umich.edu/it-security-professionals/tools-templates/checking-for-compromise

Checking Systems for Signs of Compromise | safecomputing.umich.edu
https://safecomputing.umich.edu/it-security-professionals/tools-templates/checking-for-compromise

Level Up Your L1 SOC Game: Essential Playbooks for Investigating Cyber Threats | by Hasitha Upekshitha | Medium
https://medium.com/@hasithaupekshitha97/level-up-your-l1-soc-game-essential-playbooks-for-investigating-cyber-threats-4bf3d7013631

Level Up Your L1 SOC Game: Essential Playbooks for Investigating Cyber Threats | by Hasitha Upekshitha | Medium
https://medium.com/@hasithaupekshitha97/level-up-your-l1-soc-game-essential-playbooks-for-investigating-cyber-threats-4bf3d7013631

How to check your server for suspicious activity in Linux
https://bitlaunch.io/blog/how-to-check-your-server-for-suspicious-activity-in-linux/

How to check your server for suspicious activity in Linux
https://bitlaunch.io/blog/how-to-check-your-server-for-suspicious-activity-in-linux/

Checking Systems for Signs of Compromise | safecomputing.umich.edu
https://safecomputing.umich.edu/it-security-professionals/tools-templates/checking-for-compromise

Checking Systems for Signs of Compromise | safecomputing.umich.edu
https://safecomputing.umich.edu/it-security-professionals/tools-templates/checking-for-compromise

Checking Systems for Signs of Compromise | safecomputing.umich.edu
https://safecomputing.umich.edu/it-security-professionals/tools-templates/checking-for-compromise

Checking Systems for Signs of Compromise | safecomputing.umich.edu
https://safecomputing.umich.edu/it-security-professionals/tools-templates/checking-for-compromise

How to check your server for suspicious activity in Linux
https://bitlaunch.io/blog/how-to-check-your-server-for-suspicious-activity-in-linux/

SOC Playbook Examples for Real-World Cyber Threats
https://radiantsecurity.ai/learn/soc-playbook/

SOC Playbook Examples for Real-World Cyber Threats
https://radiantsecurity.ai/learn/soc-playbook/

Level Up Your L1 SOC Game: Essential Playbooks for Investigating Cyber Threats | by Hasitha Upekshitha | Medium
https://medium.com/@hasithaupekshitha97/level-up-your-l1-soc-game-essential-playbooks-for-investigating-cyber-threats-4bf3d7013631

Level Up Your L1 SOC Game: Essential Playbooks for Investigating Cyber Threats | by Hasitha Upekshitha | Medium
https://medium.com/@hasithaupekshitha97/level-up-your-l1-soc-game-essential-playbooks-for-investigating-cyber-threats-4bf3d7013631

Level Up Your L1 SOC Game: Essential Playbooks for Investigating Cyber Threats | by Hasitha Upekshitha | Medium
https://medium.com/@hasithaupekshitha97/level-up-your-l1-soc-game-essential-playbooks-for-investigating-cyber-threats-4bf3d7013631

Level Up Your L1 SOC Game: Essential Playbooks for Investigating Cyber Threats | by Hasitha Upekshitha | Medium
https://medium.com/@hasithaupekshitha97/level-up-your-l1-soc-game-essential-playbooks-for-investigating-cyber-threats-4bf3d7013631

SOC Playbook Examples for Real-World Cyber Threats
https://radiantsecurity.ai/learn/soc-playbook/

How to check your server for suspicious activity in Linux
https://bitlaunch.io/blog/how-to-check-your-server-for-suspicious-activity-in-linux/

How to check your server for suspicious activity in Linux
https://bitlaunch.io/blog/how-to-check-your-server-for-suspicious-activity-in-linux/

Level Up Your L1 SOC Game: Essential Playbooks for Investigating Cyber Threats | by Hasitha Upekshitha | Medium
https://medium.com/@hasithaupekshitha97/level-up-your-l1-soc-game-essential-playbooks-for-investigating-cyber-threats-4bf3d7013631

Checking Systems for Signs of Compromise | safecomputing.umich.edu
https://safecomputing.umich.edu/it-security-professionals/tools-templates/checking-for-compromise

How to check your server for suspicious activity in Linux
https://bitlaunch.io/blog/how-to-check-your-server-for-suspicious-activity-in-linux/

Level Up Your L1 SOC Game: Essential Playbooks for Investigating Cyber Threats | by Hasitha Upekshitha | Medium
https://medium.com/@hasithaupekshitha97/level-up-your-l1-soc-game-essential-playbooks-for-investigating-cyber-threats-4bf3d7013631
All Sources
safecomputing.umich
medium
support.alertlogic
research.splunk
bitlaunch
radiantsecurity
