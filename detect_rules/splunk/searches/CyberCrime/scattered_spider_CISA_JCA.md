### Scattered Spider Threat Intelligence Report
---

Scattered Spider is a sophisticated, financially motivated cybercriminal group known for its advanced social engineering tactics, primarily targeting large organizations and their IT help desks for data extortion and ransomware deployment. Recent updates indicate an evolution in their TTPs, including more refined social engineering, the use of new malware variants like RattyRAT and DragonForce ransomware, and a focus on exfiltrating data from cloud data platforms like Snowflake.

Scattered Spider has recently incorporated DragonForce ransomware into their operations, alongside their usual data exfiltration for extortion, and is actively targeting cloud data platforms like Snowflake for rapid, large-volume data exfiltration. They have also refined their social engineering to pose as employees to trick IT/helpdesk staff into providing sensitive information or transferring MFA to their devices, and are using new legitimate tools like AnyDesk and Teleport.sh, and new malware like RattyRAT.

### Actionable Threat Data
---

Monitor for suspicious activity related to remote access tools (e.g., AnyDesk, Teleport.sh, TeamViewer, Splashtop, ScreenConnect, Pulseway, Level.io, Fleetdeck.io, Ngrok, Tactical.RMM, Tailscale) being installed or executed, especially from unusual user accounts or outside of approved IT processes.

Implement robust logging and alerting for MFA fatigue attacks (repeated MFA notification prompts) and SIM swap attempts, as these are primary initial access
vectors for Scattered Spider.

Detect and investigate attempts to access or exfiltrate data from cloud storage services (e.g., Amazon S3, MEGA[.]NZ) and cloud data platforms like Snowflake, particularly when originating from newly created or suspicious accounts.

Look for the creation of new user identities or social media profiles within your environment, as Scattered Spider uses these for persistence and to backstop newly created identities.

Monitor for the presence and activity of new malware variants like RattyRAT (Java-based remote access trojan) and indicators of DragonForce ransomware deployment, especially on VMware ESXi servers.

### Suspicious Remote Access Tool Usage
---
```sql
--_comment="This detection rule identifies the execution of legitimate remote access tools that have been associated with the Scattered Spider threat group. Monitoring for these tools is crucial as they are often used for initial access, persistence, and lateral movement."
--_comment="Tuning: This query is designed to be a starting point. To reduce false positives, it is highly recommended to filter for executions by non-IT personnel or from systems outside of your standard administrative subnets. Update the 'user_allowlist' and 'parent_process_allowlist' macros or replace them with a lookup file of authorized users/processes."
tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("AnyDesk.exe", "TeamViewer.exe", "ngrok.exe", "TacticalRMM.exe", "tailscale.exe", "tailscaled.exe", "tsh.exe") OR Processes.process_name LIKE "Splashtop%" OR Processes.process_name LIKE "ScreenConnect.Client%" OR Processes.process_name LIKE "ConnectWiseControl.Client%" OR Processes.process_name LIKE "Pulseway%" OR Processes.process_name LIKE "level%" OR Processes.process_name LIKE "fleetdeck%") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
--_comment="Filter out known legitimate users and parent processes to reduce noise. Populate the 'user_allowlist' and 'parent_process_allowlist' macros accordingly."
| where NOT (`user_allowlist`) AND NOT (`parent_process_allowlist`)
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `scattered_spider_suspicious_remote_access_tool_usage_filter`
```

### MFA Fatigue/SIM Swap Attempts
---
```sql
--_comment="This detection identifies a high number of MFA failures followed by a success for a single user account, a technique known as MFA Fatigue or Push Spamming."
--_comment="This is a known TTP of threat groups like Scattered Spider (T1621)."
| tstats `security_content_summariesonly` count from datamodel=Authentication where Authentication.user!="-" AND Authentication.user!="unknown" by _time, Authentication.user, Authentication.action, Authentication.src, Authentication.app
  span=1m
| `drop_dm_object_name(Authentication)`
--_comment="Group events into 15-minute windows to analyze activity over a short period."
| bucket _time span=15m
--_comment="Count failed and successful authentications for each user within each 15-minute window. Also collect the source IPs and applications involved."
| stats sum(eval(if(action="failure",count,0))) as failure_count,
        sum(eval(if(action="success",count,0))) as success_count,
        values(src) as src,
        values(app) as app,
        min(_time) as firstTime,
        max(_time) as lastTime
        by _time, user
--_comment="The threshold for failure_count may need tuning. A high number of failures followed by a success is a strong indicator of MFA fatigue."
| where failure_count > 10 AND success_count > 0
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `mfa_fatigue_followed_by_successful_logon_filter`
```

### Cloud Data Exfiltration
---
```sql
--_comment="This detection rule identifies potential large-scale data exfiltration to known cloud storage and data platforms, a TTP associated with the Scattered Spider threat group."
--_comment="Data sources for this could be firewall logs, proxy logs, or cloud provider flow logs, all mapped to the Network_Traffic data model."
| tstats `security_content_summariesonly` sum(All_Traffic.bytes_out) as total_bytes_out from datamodel=Network_Traffic where All_Traffic.direction="outbound" by _time, All_Traffic.src, All_Traffic.user, All_Traffic.dest_host span=1h
| `drop_dm_object_name("All_Traffic")`
--_comment="Filter for traffic to specific cloud services known to be used by Scattered Spider for exfiltration."
| where like(dest_host, "%mega.nz") OR like(dest_host, "%s3.amazonaws.com") OR like(dest_host, "%.snowflakecomputing.com")
--_comment="Calculate the total data exfiltrated in Gigabytes (GB). The threshold value (e.g., 1 GB) is a starting point and should be tuned based on your organization's baseline network traffic."
| eval total_gb_out = round(total_bytes_out / 1024 / 1024 / 1024, 2)
| where total_gb_out > 1
--_comment="To further reduce false positives, consider joining this data with a lookup of newly created or otherwise suspicious user accounts."
| `security_content_ctime(_time)`
| `large_volume_exfiltration_to_cloud_storage_filter`
```

### New User Identity Creation
---
```sql
--_comment="This detection identifies the creation of new user accounts by users or from systems that are not on an allowlist of authorized administrators or provisioning servers. This activity can be indicative of a threat actor creating accounts for persistence (T1136), a TTP associated with groups like Scattered Spider."
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change where All_Changes.action="created" AND All_Changes.object_category="user_account" by All_Changes.user, All_Changes.dest, All_Changes.object
| `drop_dm_object_name("All_Changes")`
| rename object as new_user_created, user as creating_user, dest as source_system
--_comment="Filter out legitimate account creation activity. It is critical to populate the allowlist macros with the user accounts (e.g., service accounts, IT admins) and hostnames (e.g., domain controllers, HR systems) that are authorized to create new user accounts in your environment."
| where NOT (match(creating_user, `identity_provisioning_users_allowlist`) OR match(source_system, `identity_provisioning_systems_allowlist`))
--_comment="Further tuning could involve filtering for accounts created outside of business hours or accounts with non-standard naming conventions."
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `anomalous_user_account_creation_filter`
```

### RattyRAT Malware Activity
---
```sql
--_comment="This detection rule identifies the potential execution of RattyRAT, a Java-based remote access trojan used by the Scattered Spider threat group. This rule looks for the execution of a Java process launching a JAR file with 'ratty' in the name."
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="java.exe" OR Processes.process_name="javaw.exe") AND Processes.process="*-jar*" by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
--_comment="Filter for command-line arguments that are indicative of RattyRAT. The term 'ratty' is based on the malware's name."
| where like(process, "%ratty%.jar")
--_comment="Tuning: This detection is specific to the name 'RattyRAT'. To broaden detection for other suspicious Java executions, consider looking for JAR files executed from unusual locations (e.g., C:\\Users\\%, C:\\Windows\\Temp\\%) or spawned by non-standard parent processes (e.g., winword.exe, outlook.exe)."
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `rattyrat_malware_activity_filter`
```

### DragonForce Ransomware Deployment
---
```sql
--_comment="This detection rule identifies the execution of commands on a VMware ESXi host to forcibly terminate running virtual machines. This is a common precursor to ransomware, like DragonForce used by Scattered Spider, which needs to stop VMs before encrypting their virtual disk files (VMDKs)."
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.os="VMware ESXi" OR match(Processes.dest, /(?i)esxi/)) AND Processes.process_name="esxcli" AND Processes.process="*vm process kill*" by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
--_comment="The 'esxcli vm process kill' command is highly indicative of malicious activity against virtual machines. While administrators may use this command, it is typically rare and should be investigated."
--_comment="Tuning: To reduce potential false positives, consider creating an allowlist of authorized VMware administrator accounts or correlating this activity with other suspicious behaviors, such as file creation in /tmp or unusual network connections."
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `scattered_spider_dragonforce_ransomware_esxi_activity_filter`
```