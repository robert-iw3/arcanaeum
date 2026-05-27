### Plague: A Newly Discovered PAM-Based Backdoor for Linux
---

"Plague" is a recently identified, stealthy Linux backdoor implemented as a malicious Pluggable Authentication Module (PAM) that allows attackers to bypass system authentication and gain persistent SSH access. This threat is particularly difficult to detect due to its deep integration into the authentication stack, evasion of traditional antivirus engines, and sophisticated obfuscation techniques.

Recent analysis of Plague samples reveals evolving string obfuscation techniques, including the adoption of more complex KSA and PRGA routines, and a new DRBG layer, indicating active development and adaptation by the threat actors to evade analysis and detection. The use of anti-debug checks and environment tampering to erase forensic traces further highlights the increasing sophistication of this PAM-based backdoor.

### Actionable Threat Data
---

T1556.003 - Pluggable Authentication Modules: Monitor for unauthorized modifications to PAM configuration files (e.g., `/etc/pam.d/*`) and shared objects under `/lib/security/` (e.g., `libselinux.so.8`, `pam_unix.so`).

T1070.004 - Indicator Removal: File Deletion: Detect attempts to unset environment variables like `SSH_CONNECTION` and `SSH_CLIENT`, and redirection of `HISTFILE` to `/dev/null`, which are tactics used by Plague to erase session artifacts and command history.

T1027 - Obfuscated Files or Information: Look for ELF binaries that contain the strings "`decrypt_phrase`" and "`init_phrases`", which are indicative of Plague's string deobfuscation routines.

T1036.005 - Masquerading: Match Legitimate Name: Monitor for the presence of suspicious files named `libselinux.so.8` or `libse.so` in unexpected directories, as Plague samples often masquerade as legitimate system libraries.

T1098 - Account Manipulation: Investigate successful SSH logins that occur without corresponding authentication logs or that use hardcoded backdoor passwords (e.g., "`Mvi4Odm6tld7`", "`IpV57KNK32Ih`", "`changeme`").

### Suspicious PAM File or Library Modification
---

Crowdstrike Query Language CQL:

```sql
SELECT
  MIN(Timestamp) AS firstTime,
  MAX(Timestamp) AS lastTime,
  ComputerName AS dest,
  UserName AS user,
  ProcessName,
  FilePath,
  FileName,
  EventType AS action,
  COUNT(*) AS count
FROM FileEvents
WHERE
  (FilePath LIKE '/etc/pam.d/%' OR FilePath IN ('/lib/security/%', '/usr/lib/security/%', '/lib64/security/%'))
  AND EventType IN ('FileCreated', 'FileModified')
  AND ProcessName NOT IN ('yum', 'apt', 'apt-get', 'dpkg', 'rpm', 'dnf', 'pacman', 'systemd', 'chkconfig', 'update-alternatives', 'authconfig')
GROUP BY
  ComputerName,
  UserName,
  ProcessName,
  FilePath,
  FileName,
  EventType
```

Falcon Query Language FQL:

```sql
SELECT
  MIN(timestamp) AS firstTime,
  MAX(timestamp) AS lastTime,
  event.ComputerName AS dest,
  event.UserName AS user,
  event.ProcessName,
  event.FilePath,
  event.FileName,
  event.event_simpleName AS action,
  COUNT(*) AS count
FROM events
WHERE
  event_platform = 'Linux'
  AND (event.FilePath LIKE '/etc/pam.d/%' OR event.FilePath IN ('/lib/security/%', '/usr/lib/security/%', '/lib64/security/%'))
  AND event.event_simpleName IN ('FileCreate', 'FileModify')
  AND event.ProcessName NOT IN ('yum', 'apt', 'apt-get', 'dpkg', 'rpm', 'dnf', 'pacman', 'systemd', 'chkconfig', 'update-alternatives', 'authconfig')
GROUP BY
  event.ComputerName,
  event.UserName,
  event.ProcessName,
  event.FilePath,
  event.FileName,
  event.event_simpleName
```

### Malicious PAM Module
---

Crowdstrike Query Language CQL:

```sql
SELECT
  MIN(Timestamp) AS firstTime,
  MAX(Timestamp) AS lastTime,
  ComputerName AS dest,
  UserName AS user,
  ProcessName,
  FileName,
  FilePath,
  SHA256Hash AS file_hash,
  COUNT(*) AS count
FROM FileEvents
WHERE
  (FilePath LIKE '%/lib/security/%' OR FilePath LIKE '%/lib64/security/%')
  AND ProcessName NOT IN ('yum', 'apt', 'apt-get', 'dpkg', 'rpm', 'dnf', 'unattended-upgrade')
  AND (
    FileName IN ('libselinux.so.8', 'libse.so', 'hijack')
    OR SHA256Hash IN (
      '85c66835657e3ee6a478a2e0b1fd3d87119bebadc43a16814c30eb94c53766bb',
      '7c3ada3f63a32f4727c62067d13e40bcb9aa9cbec8fb7e99a319931fc5a9332e',
      '9445da674e59ef27624cd5c8ffa0bd6c837de0d90dd2857cf28b16a08fd7dba6',
      '5e6041374f5b1e6c05393ea28468a91c41c38dc6b5a5230795a61c2b60ed14bc',
      '6d2d30d5295ad99018146c8e67ea12f4aaa2ca1a170ad287a579876bf03c2950',
      'e594bca43ade76bbaab2592e9eabeb8dca8a72ed27afd5e26d857659ec173261',
      '14b0c90a2eff6b94b9c5160875fcf29aff15dcfdfd3402d953441d9b0dca8b39'
    )
  )
GROUP BY
  ComputerName,
  UserName,
  ProcessName,
  FileName,
  FilePath,
  SHA256Hash
```

Falcon Query Language FQL:

```sql
SELECT
  MIN(timestamp) AS firstTime,
  MAX(timestamp) AS lastTime,
  event.ComputerName AS dest,
  event.UserName AS user,
  event.ProcessName,
  event.FileName,
  event.FilePath,
  event.SHA256Hash AS file_hash,
  COUNT(*) AS count
FROM events
WHERE
  event_platform = 'Linux'
  AND (event.FilePath LIKE '%/lib/security/%' OR event.FilePath LIKE '%/lib64/security/%')
  AND event.event_simpleName IN ('FileCreate', 'FileModify')
  AND event.ProcessName NOT IN ('yum', 'apt', 'apt-get', 'dpkg', 'rpm', 'dnf', 'unattended-upgrade')
  AND (
    event.FileName IN ('libselinux.so.8', 'libse.so', 'hijack')
    OR event.SHA256Hash IN (
      '85c66835657e3ee6a478a2e0b1fd3d87119bebadc43a16814c30eb94c53766bb',
      '7c3ada3f63a32f4727c62067d13e40bcb9aa9cbec8fb7e99a319931fc5a9332e',
      '9445da674e59ef27624cd5c8ffa0bd6c837de0d90dd2857cf28b16a08fd7dba6',
      '5e6041374f5b1e6c05393ea28468a91c41c38dc6b5a5230795a61c2b60ed14bc',
      '6d2d30d5295ad99018146c8e67ea12f4aaa2ca1a170ad287a579876bf03c2950',
      'e594bca43ade76bbaab2592e9eabeb8dca8a72ed27afd5e26d857659ec173261',
      '14b0c90a2eff6b94b9c5160875fcf29aff15dcfdfd3402d953441d9b0dca8b39'
    )
  )
GROUP BY
  event.ComputerName,
  event.UserName,
  event.ProcessName,
  event.FileName,
  event.FilePath,
  event.SHA256Hash
```

### Linux SSH Session Artifact Removal
---

Crowdstrike Query Language CQL:

```sql
SELECT
  MIN(Timestamp) AS firstTime,
  MAX(Timestamp) AS lastTime,
  ComputerName AS dest,
  UserName AS user,
  ParentProcessName,
  ProcessName,
  CommandLine AS process,
  ProcessId,
  ParentProcessId,
  COUNT(*) AS count
FROM ProcessEvents
WHERE
  (CommandLine LIKE '%unset SSH_CONNECTION%' OR
   CommandLine LIKE '%unset SSH_CLIENT%' OR
   CommandLine LIKE '%HISTFILE=/dev/null%')
  AND ParentProcessName NOT IN ('your_legit_script.sh', 'config_manager_process')
GROUP BY
  ComputerName,
  UserName,
  ParentProcessName,
  ProcessName,
  CommandLine,
  ProcessId,
  ParentProcessId
```

Falcon Query Language FQL:

```sql
SELECT
  MIN(timestamp) AS firstTime,
  MAX(timestamp) AS lastTime,
  event.ComputerName AS dest,
  event.UserName AS user,
  event.ParentProcessName,
  event.ProcessName,
  event.CommandLine AS process,
  event.ProcessId,
  event.ParentProcessId,
  COUNT(*) AS count
FROM events
WHERE
  event_platform = 'Linux'
  AND event.event_simpleName = 'ProcessRollup2'
  AND (event.CommandLine LIKE '%unset SSH_CONNECTION%' OR
       event.CommandLine LIKE '%unset SSH_CLIENT%' OR
       event.CommandLine LIKE '%HISTFILE=/dev/null%')
  AND event.ParentProcessName NOT IN ('your_legit_script.sh', 'config_manager_process')
GROUP BY
  event.ComputerName,
  event.UserName,
  event.ParentProcessName,
  event.ProcessName,
  event.CommandLine,
  event.ProcessId,
  event.ParentProcessId
```

### Plague Backdoor Masquerading as System Library
---

Crowdstrike Query Language CQL:

```sql
SELECT
  MIN(Timestamp) AS firstTime,
  MAX(Timestamp) AS lastTime,
  ComputerName AS dest,
  UserName AS user,
  ProcessName,
  FilePath,
  FileName,
  EventType AS action,
  COUNT(*) AS count
FROM FileEvents
WHERE
  FileName IN ('libselinux.so.8', 'libse.so')
  AND EventType IN ('FileCreated', 'FileModified')
  AND NOT (FilePath LIKE '/usr/lib/%' OR FilePath LIKE '/usr/lib64/%' OR FilePath LIKE '/lib/%' OR FilePath LIKE '/lib64/%')
GROUP BY
  ComputerName,
  UserName,
  ProcessName,
  FilePath,
  FileName,
  EventType
```

Falcon Query Language FQL:

```sql
SELECT
  MIN(timestamp) AS firstTime,
  MAX(timestamp) AS lastTime,
  event.ComputerName AS dest,
  event.UserName AS user,
  event.ProcessName,
  event.FilePath,
  event.FileName,
  event.event_simpleName AS action,
  COUNT(*) AS count
FROM events
WHERE
  event_platform = 'Linux'
  AND event.FileName IN ('libselinux.so.8', 'libse.so')
  AND event.event_simpleName IN ('FileCreate', 'FileModify')
  AND NOT (event.FilePath LIKE '/usr/lib/%' OR event.FilePath LIKE '/usr/lib64/%' OR event.FilePath LIKE '/lib/%' OR event.FilePath LIKE '/lib64/%')
GROUP BY
  event.ComputerName,
  event.UserName,
  event.ProcessName,
  event.FilePath,
  event.FileName,
  event.event_simpleName
```

### SSH Session without Corresponding Authentication Log
---

Crowdstrike Query Language CQL:

```sql
SELECT
  MIN(Timestamp) AS firstTime,
  MAX(Timestamp) AS lastTime,
  ComputerName AS dest,
  UserName AS user
FROM (
  SELECT
    Timestamp,
    ComputerName,
    UserName,
    'ssh_session_started' AS event_type,
    FLOOR(Timestamp / (2 * 60 * 1000)) AS time_bucket
  FROM ProcessEvents
  WHERE
    ParentProcessName = 'sshd'
    AND ProcessName IN ('bash', 'sh', 'zsh', 'csh', 'tcsh', 'ksh')
  UNION
  SELECT
    Timestamp,
    ComputerName,
    UserName,
    'ssh_auth_success' AS event_type,
    FLOOR(Timestamp / (2 * 60 * 1000)) AS time_bucket
  FROM AuthEvents
  WHERE
    ProcessName = 'sshd'
    AND EventType = 'AuthenticationSuccess'
)
GROUP BY
  time_bucket,
  ComputerName,
  UserName
HAVING
  COUNT(DISTINCT event_type) = 1
  AND 'ssh_session_started' IN event_type
```

Falcon Query Language FQL:

```sql
SELECT
  MIN(timestamp) AS firstTime,
  MAX(timestamp) AS lastTime,
  event.ComputerName AS dest,
  event.UserName AS user
FROM events
WHERE
  event_platform = 'Linux'
  AND (
    (event.event_simpleName = 'ProcessRollup2'
     AND event.ParentProcessName = 'sshd'
     AND event.ProcessName IN ('bash', 'sh', 'zsh', 'csh', 'tcsh', 'ksh'))
    OR
    (event.event_simpleName = 'UserLogin'
     AND event.ProcessName = 'sshd')
  )
GROUP BY
  FLOOR(timestamp / (2 * 60 * 1000)) AS time_bucket,
  event.ComputerName,
  event.UserName
HAVING
  COUNT(DISTINCT CASE
    WHEN event.event_simpleName = 'ProcessRollup2' THEN 'ssh_session_started'
    WHEN event.event_simpleName = 'UserLogin' THEN 'ssh_auth_success'
    ELSE NULL
  END) = 1
  AND 'ssh_session_started' IN (
    CASE
      WHEN event.event_simpleName = 'ProcessRollup2' THEN 'ssh_session_started'
      WHEN event.event_simpleName = 'UserLogin' THEN 'ssh_auth_success'
      ELSE NULL
    END
  )
```

### Authentication Bypass
---

Crowdstrike Query Language CQL:

```sql
SELECT
  MIN(Timestamp) AS firstTime,
  MAX(Timestamp) AS lastTime,
  ComputerName AS dest,
  UserName AS user,
  SourceIp AS src,
  ProcessName AS app,
  ARRAY_AGG(DISTINCT EventType) AS sourcetypes,
  COUNT(*) AS count
FROM AuthEvents
WHERE
  (RawEventData LIKE '%Mvi4Odm6tld7%' OR RawEventData LIKE '%IpV57KNK32Ih%')
  AND (
    EventType IN ('Authentication', 'NetworkConnection', 'IDSAlert')
    OR ProcessName = 'sshd'
    OR RawEventData LIKE '%login%'
    OR RawEventData LIKE '%pam%'
    OR RawEventData LIKE '%authentication%'
  )
GROUP BY
  ComputerName,
  UserName,
  SourceIp,
  ProcessName
```

Falcon Query Language FQL:

```sql
SELECT
  MIN(timestamp) AS firstTime,
  MAX(timestamp) AS lastTime,
  event.ComputerName AS dest,
  event.UserName AS user,
  event.SourceIp AS src,
  event.ProcessName AS app,
  ARRAY_AGG(DISTINCT event.event_simpleName) AS sourcetypes,
  COUNT(*) AS count
FROM events
WHERE
  event_platform = 'Linux'
  AND (event.RawEventData LIKE '%Mvi4Odm6tld7%' OR event.RawEventData LIKE '%IpV57KNK32Ih%')
  AND (
    event.event_simpleName IN ('UserLogin', 'NetworkConnect', 'IDSAlert')
    OR event.ProcessName = 'sshd'
    OR event.RawEventData LIKE '%login%'
    OR event.RawEventData LIKE '%pam%'
    OR event.RawEventData LIKE '%authentication%'
  )
GROUP BY
  event.ComputerName,
  event.UserName,
  event.SourceIp,
  event.ProcessName
```