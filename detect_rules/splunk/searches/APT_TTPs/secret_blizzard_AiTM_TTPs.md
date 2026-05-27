### Secret Blizzard's AiTM Campaign Against Diplomats
---

Secret Blizzard, a Russian state-backed actor, is conducting a cyberespionage campaign targeting foreign embassies in Moscow using an Adversary-in-the-Middle (AiTM) position at the ISP level to deploy custom ApolloShadow malware. This campaign aims to maintain persistence and collect intelligence from diplomatic entities by installing malicious root certificates and creating a new administrative user.

This campaign marks the first confirmed instance of Secret Blizzard operating at the Internet Service Provider (ISP) level, indicating a significant escalation in their capabilities to intercept and manipulate network traffic for espionage. This ISP-level access, likely facilitated by Russia's domestic intercept systems like SORM, allows them to deploy malware via captive portals and perform TLS/SSL stripping, making their attacks highly effective and difficult to detect.

### Actionable Threat Data
---

Monitor for network traffic redirection to unexpected captive portals, especially those that initiate after a system connectivity probe to `msftconnecttest.com/` redirect.

Detect the execution of `CertificateDB.exe` or any suspicious executables masquerading as antivirus installers, particularly when prompting for root certificate installation or UAC elevation.

Look for the creation of new administrative users with unusual names, such as "`UpdatusUser`", and monitor for changes to network profile settings (e.g., setting networks to "Private") or firewall rules that enable network discovery and file sharing.

Identify DNS queries for `timestamp.digicert.com` that resolve to an attacker-controlled IP address, as this domain is legitimately used but abused by `ApolloShadow` for C2 communication.

Implement detections for the presence of the ApolloShadow malware (SHA256: `13fafb1ae2d5de024e68f2e2fc820bc79ef0690c40dbfd70246bcc394c52ea20`) or communication with the actor-controlled domain `kav-certificates[.]info` and IP address `45.61.149[.]109`.

### AiTM Captive Portal Redirect
---
```sql
(index=* sourcetype=*)
    `-- comment: Specify relevant indexes and sourcetypes for performance, e.g., (index=proxy OR index=edr)`
(url="*msftconnecttest.com/redirect*") OR (file_name="*.exe")
    `-- comment: Filter for the two key events: the captive portal check and an executable file creation.`

| transaction host maxspan=2m startswith=(url="*msftconnecttest.com/redirect*")
    `-- comment: Correlate events on the same host within a 2-minute window, starting with the redirect.`

| where isnotnull(url) AND isnotnull(file_name)
    `-- comment: Ensure the transaction is complete, containing both the redirect and the file download.`

| table _time, host, user, url, file_name, file_path, file_hash
| rename host as endpoint, url as redirect_url, file_name as downloaded_file, file_path as download_path, file_hash as sha256
```

### ApolloShadow UAC Prompt for Privilege Escalation
---
```sql
`cim_endpoint`
    `-- comment: This macro uses the Endpoint data model. You can replace it with your specific index and sourcetype, e.g., (index=main sourcetype=wineventlog:security) or (index=sysmon sourcetype=xmlwineventlog:microsoft-windows-sysmon/operational).`
| search (process_name="CertificateDB.exe" OR process="*\\CertificateDB.exe")
    `-- comment: Search for the specific executable name used by ApolloShadow to trigger the UAC prompt.`
| stats
    count
    min(_time) as firstTime
    max(_time) as lastTime
    values(process_command_line) as cmd
    values(parent_process_name) as parent_process
    by dest, user, process_name
    `-- comment: Aggregate results by host, user, and process to reduce alert volume.`
| rename dest as endpoint, process_name as process
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### Suspicious Root Certificate Installation via Certutil
---
```sql
`cim_endpoint`
    `-- comment: This macro uses the Endpoint data model. You can replace it with your specific index and sourcetype, e.g., (index=main sourcetype=wineventlog:security) or (index=sysmon sourcetype=xmlwineventlog:microsoft-windows-sysmon/operational).`
| search (process_name="certutil.exe" OR process="*\\certutil.exe")
    `-- comment: Filter for the execution of the certutil.exe utility.`
| search (process_command_line="*-addstore*root*" OR process_command_line="*-addstore*ca*")
    `-- comment: Look for command-line arguments indicating a certificate is being added to the sensitive 'root' or 'ca' stores.`
| stats
    count
    min(_time) as firstTime
    max(_time) as lastTime
    values(process_command_line) as cmd
    values(parent_process_name) as parent_process
    by dest, user, process_name
    `-- comment: Aggregate results to reduce alert volume and summarize activity.`
| rename dest as endpoint, process_name as process
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### ApolloShadow New Admin User Creation
---
```sql
`cim_change`
    `-- comment: This macro uses the Change data model. For raw logs, search for (index=wineventlog sourcetype=wineventlog:security EventCode=4720 TargetUserName="UpdatusUser").`
| search action="created" object_category="user" user="UpdatusUser"
    `-- comment: Filter for user creation events where the username is the specific 'UpdatusUser' indicator.`
| stats
    count
    min(_time) as firstTime
    max(_time) as lastTime
    values(user) as created_user
    values(src_user) as creating_user
    by dest
    `-- comment: Aggregate results by endpoint to summarize the activity.`
| rename dest as endpoint
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### ApolloShadow C2 Domain
---
```sql
`cim_network_traffic`
    `-- comment: This macro uses the Network Traffic data model. For raw logs, search for the domain in relevant fields like URL or destination host.`
| search dest_host IN ("kav-certificates.info")
    `-- comment: Filter for known ApolloShadow C2 domains.`
| stats
    count
    min(_time) as firstTime
    max(_time) as lastTime
    values(dest_port) as dest_port
    values(user) as user
    by src_ip, dest_host
    `-- comment: Aggregate results by source IP and destination domain to summarize the activity.`
| rename src_ip as endpoint_ip, dest_host as c2_domain
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### ApolloShadow C2 IP
---
```sql
`cim_network_traffic`
    `-- comment: This macro uses the Network Traffic data model. For raw logs, search for the IP in relevant destination fields.`
| search dest_ip IN ("45.61.149.109")
    `-- comment: Filter for known ApolloShadow C2 IP addresses.`
| stats
    count
    min(_time) as firstTime
    max(_time) as lastTime
    values(dest_port) as dest_port
    values(user) as user
    by src_ip, dest_ip
    `-- comment: Aggregate results by source and destination IP to summarize the activity.`
| rename src_ip as endpoint_ip, dest_ip as c2_ip
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### ApolloShadow Malware Hash
---
```sql
`cim_endpoint`
    `-- comment: This macro uses the Endpoint data model. For raw logs, search for the hash in relevant fields like file_hash, sha256, etc.`
| search file_hash="13fafb1ae2d5de024e68f2e2fc820bc79ef0690c40dbfd70246bcc394c52ea20"
    `-- comment: Filter for the known SHA256 hash of the ApolloShadow malware.`
| stats
    count
    min(_time) as firstTime
    max(_time) as lastTime
    values(file_name) as file_name
    values(file_path) as file_path
    by dest, user
    `-- comment: Aggregate results by host and user to summarize the findings.`
| rename dest as endpoint
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### CertificateDB.exe Presence
---
```sql
`cim_endpoint`
    `-- comment: This macro uses the Endpoint data model. You can replace it with your specific index and sourcetype.`
| search (process_name="CertificateDB.exe" OR file_name="CertificateDB.exe" OR process="*\\CertificateDB.exe")
    `-- comment: Search for the specific file or process name used by ApolloShadow.`
| stats
    count
    min(_time) as firstTime
    max(_time) as lastTime
    values(process_command_line) as cmd
    values(parent_process_name) as parent_process
    values(file_path) as file_path
    by dest, user, process_name, file_name
    `-- comment: Aggregate results by host, user, and artifact name to reduce alert volume.`
| rename dest as endpoint
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```