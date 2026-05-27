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
EventType = "Network" AND NetworkUrl CONTAINS "msftconnecttest.com/redirect"
| JOIN (
    EventType = "File" AND FileFullName ENDSWITH ".exe" AND EventAction = "download"
) ON SiteId
WHERE FileCreatedAt BETWEEN NetworkCreatedAt AND (NetworkCreatedAt + 2m)
SELECT
    Timestamp = FileCreatedAt,
    DeviceId = SiteId,
    FileName = FileFullName,
    FolderPath = FilePath,
    FileSHA256 = FileSha256,
    InitiatingProcessCommandLine = ProcessCmd,
    RedirectTimestamp = NetworkCreatedAt,
    RedirectUrl = NetworkUrl
```

### ApolloShadow UAC Prompt for Privilege Escalation
---
```sql
EventType = "Security" AND EventAction = "uac_prompt_launched" AND FileFullName ICONTAINS "CertificateDB.exe"
SELECT
    Timestamp = EventCreated,
    DeviceId = SiteId,
    DeviceName = AgentName,
    ActionType = EventAction,
    FileName = FileFullName,
    FolderPath = FilePath,
    InitiatingProcessAccountName = User,
    InitiatingProcessFileName = ProcessName,
    InitiatingProcessCommandLine = ProcessCmd
```

### Suspicious Root Certificate Installation via Certutil
---
```sql
EventType = "Process" AND EventCreated > NOW() - 1d
AND ProcessName ICONTAINS "certutil.exe"
AND ProcessCmd CONTAINS ALL ("-addstore", "-f")
AND (ProcessCmd CONTAINS " root " OR ProcessCmd CONTAINS " ca ")
AND (ProcessCmd CONTAINS "-Enterprise" OR ProcessCmd MATCHES REGEX "(?i)\\\\(users|temp|appdata|downloads)\\\\[^\\s]+\\.(crt|cer|tmp)")
SELECT
    firstTime = MIN(EventCreated),
    lastTime = MAX(EventCreated),
    eventCount = COUNT(*),
    cmd = COLLECT_SET(ProcessCmd, 10),
    parent_process = COLLECT_SET(ParentProcessName, 10),
    user = COLLECT_SET(User, 10)
GROUP BY
    endpoint = AgentName,
    DeviceId = SiteId
```

### ApolloShadow New Admin User Creation
---
```sql
EventType = "Security" AND EventCreated > NOW() - 1d
AND EventAction = "user_account_created"
AND User ICONTAINS "UpdatusUser"
SELECT
    firstTime = MIN(EventCreated),
    lastTime = MAX(EventCreated),
    eventCount = COUNT(*),
    initiating_process = COLLECT_SET(ProcessName, 10),
    cmd = COLLECT_SET(ProcessCmd, 10)
GROUP BY
    endpoint = AgentName,
    DeviceId = SiteId,
    created_user = User
```

### ApolloShadow C2 Domain
---
```sql
EventType = "Network" AND EventCreated > NOW() - 1d
AND NetworkUrl IN ("kav-certificates.info")
SELECT
    firstTime = MIN(EventCreated),
    lastTime = MAX(EventCreated),
    eventCount = COUNT(*),
    c2_ip = COLLECT_SET(DstIP, 10),
    remote_port = COLLECT_SET(DstPort, 10),
    initiating_process = COLLECT_SET(ProcessName, 10)
GROUP BY
    endpoint = AgentName,
    DeviceId = SiteId,
    c2_domain = NetworkUrl
```

### ApolloShadow C2 IP
---
```sql
EventType = "Network" AND EventCreated > NOW() - 1d
AND EventAction = "connection_success"
AND DstIP IN ("45.61.149.109")
SELECT
    firstTime = MIN(EventCreated),
    lastTime = MAX(EventCreated),
    eventCount = COUNT(*),
    remote_port = COLLECT_SET(DstPort, 10),
    initiating_process = COLLECT_SET(ProcessName, 10)
GROUP BY
    endpoint = AgentName,
    DeviceId = SiteId,
    c2_ip = DstIP
```

### ApolloShadow Malware Hash
---
```sql
(EventType = "File" OR EventType = "Process") AND EventCreated > NOW() - 1d
AND FileSha256 ICONTAINS "13fafb1ae2d5de024e68f2e2fc820bc79ef0690c40dbfd70246bcc394c52ea20"
SELECT
    firstTime = MIN(EventCreated),
    lastTime = MAX(EventCreated),
    eventCount = COUNT(*),
    file_name = COLLECT_SET(FileFullName, 10),
    file_path = COLLECT_SET(FilePath, 10),
    parent_process = COLLECT_SET(ParentProcessName, 10)
GROUP BY
    endpoint = AgentName,
    DeviceId = SiteId,
    sha256 = FileSha256
```

### CertificateDB.exe Presence
---
```sql
(EventType = "Process" OR EventType = "File") AND EventCreated > NOW() - 1d
AND (FileFullName ICONTAINS "CertificateDB.exe" OR ProcessCmd CONTAINS "CertificateDB.exe")
EVAL
    User = User
    Parent = COALESCE(ParentProcessName, ProcessName)
SELECT
    firstTime = MIN(EventCreated),
    lastTime = MAX(EventCreated),
    eventCount = COUNT(*),
    cmd = COLLECT_SET(ProcessCmd, 10),
    parent_process = COLLECT_SET(Parent, 10),
    file_path = COLLECT_SET(FilePath, 10)
GROUP BY
    endpoint = AgentName,
    user = User,
    process_name = FileFullName
```