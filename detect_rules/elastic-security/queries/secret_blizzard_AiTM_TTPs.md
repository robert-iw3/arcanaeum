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
FROM * // optimize search by narrowing to index or data-streams
WHERE
  network.destination.domain LIKE "*msftconnecttest.com/redirect*"
  AND file.name ENDSWITH ".exe"
  AND event.action == "download"
  AND network.device.id == file.device.id
  AND file.created BETWEEN network.created AND (network.created + 2m)
EVAL
  Timestamp = file.created,
  DeviceId = file.device.id,
  FileName = file.name,
  FolderPath = file.directory,
  SHA256 = file.hash.sha256,
  InitiatingProcessCommandLine = process.command_line,
  RedirectTimestamp = network.created,
  RedirectUrl = network.destination.domain
```

### ApolloShadow UAC Prompt for Privilege Escalation
---
```sql
FROM *
WHERE
  event.action == "uac_prompt_launched"
  AND file.name ILIKE "CertificateDB.exe"
EVAL
  Timestamp = event.created,
  DeviceId = device.id,
  DeviceName = device.name,
  ActionType = event.action,
  FileName = file.name,
  FolderPath = file.directory,
  InitiatingProcessAccountName = user.name,
  InitiatingProcessFileName = process.name,
  InitiatingProcessCommandLine = process.command_line
```

### Suspicious Root Certificate Installation via Certutil
---
```sql
FROM *
WHERE
  event.created > NOW() - 1d
  AND process.name ILIKE "certutil.exe"
  AND process.command_line CONTAINS ALL ("-addstore", "-f")
  AND (process.command_line CONTAINS " root " OR process.command_line CONTAINS " ca ")
  AND (process.command_line CONTAINS "-Enterprise" OR process.command_line MATCHES REGEX "(?i)\\\\(users|temp|appdata|downloads)\\\\[^\\s]+\\.(crt|cer|tmp)")
STATS
  startTime = MIN(event.created),
  endTime = MAX(event.created),
  eventCount = COUNT(*),
  CommandLine = ARRAY_AGG(DISTINCT process.command_line, 10),
  ParentProcess = ARRAY_AGG(DISTINCT process.parent.name, 10),
  User = ARRAY_AGG(DISTINCT user.name, 10)
BY
  endpoint = device.name,
  DeviceId = device.id
```

### ApolloShadow New Admin User Creation
---
```sql
FROM *
WHERE
  event.created > NOW() - 1d
  AND event.action == "user_account_created"
  AND user.target.name ILIKE "UpdatusUser"
STATS
  startTime = MIN(event.created),
  endTime = MAX(event.created),
  eventCount = COUNT(*),
  InitiatingProcess = ARRAY_AGG(DISTINCT process.name, 10),
  CommandLine = ARRAY_AGG(DISTINCT process.command_line, 10)
BY
  endpoint = device.name,
  DeviceId = device.id,
  created_user = user.target.name
```

### ApolloShadow C2 Domain
---
```sql
FROM *
WHERE
  event.created > NOW() - 1d
  AND destination.domain IN ("kav-certificates.info")
STATS
  startTime = MIN(event.created),
  endTime = MAX(event.created),
  eventCount = COUNT(*),
  RemoteIP = ARRAY_AGG(DISTINCT destination.ip, 10),
  RemotePort = ARRAY_AGG(DISTINCT destination.port, 10),
  InitiatingProcess = ARRAY_AGG(DISTINCT process.name, 10)
BY
  endpoint = device.name,
  DeviceId = device.id,
  c2_domain = destination.domain
```

### ApolloShadow C2 IP
---
```sql
FROM *
WHERE
  event.created > NOW() - 1d
  AND event.action == "connection_success"
  AND destination.ip IN ("45.61.149.109")
STATS
  startTime = MIN(event.created),
  endTime = MAX(event.created),
  eventCount = COUNT(*),
  RemotePort = ARRAY_AGG(DISTINCT destination.port, 10),
  InitiatingProcess = ARRAY_AGG(DISTINCT process.name, 10)
BY
  endpoint = device.name,
  DeviceId = device.id,
  c2_ip = destination.ip
```

### ApolloShadow Malware Hash
---
```sql
FROM *
WHERE
  event.created > NOW() - 1d
  AND file.hash.sha256 ILIKE "13fafb1ae2d5de024e68f2e2fc820bc79ef0690c40dbfd70246bcc394c52ea20"
STATS
  startTime = MIN(event.created),
  endTime = MAX(event.created),
  eventCount = COUNT(*),
  FileName = ARRAY_AGG(DISTINCT file.name, 10),
  FilePath = ARRAY_AGG(DISTINCT file.directory, 10),
  ParentProcess = ARRAY_AGG(DISTINCT process.parent.name, 10)
BY
  endpoint = device.name,
  DeviceId = device.id,
  sha256 = file.hash.sha256
```

### CertificateDB.exe Presence
---
```sql
FROM *
WHERE
  event.created > NOW() - 1d
  AND (file.name ILIKE "CertificateDB.exe" OR process.command_line CONTAINS "CertificateDB.exe")
EVAL
  User = COALESCE(process.user.name, user.name),
  Parent = COALESCE(process.parent.name, process.name)
STATS
  startTime = MIN(event.created),
  endTime = MAX(event.created),
  eventCount = COUNT(*),
  CommandLine = ARRAY_AGG(DISTINCT process.command_line, 10),
  ParentProcess = ARRAY_AGG(DISTINCT Parent, 10),
  FilePath = ARRAY_AGG(DISTINCT file.directory, 10)
BY
  endpoint = device.name,
  user = User,
  process_name = file.name
```