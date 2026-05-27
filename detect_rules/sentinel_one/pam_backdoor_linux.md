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
```sql
SELECT
  MIN(eventTime) AS firstTime,
  MAX(eventTime) AS lastTime,
  AgentName AS dest,
  User AS user,
  ProcessName,
  filePath,
  FileFullName,
  eventType AS action,
  COUNT(*) AS count
FROM deepvisibility
WHERE
  (filePath LIKE '/etc/pam.d/%' OR filePath IN ('/lib/security/%', '/usr/lib/security/%', '/lib64/security/%'))
  AND eventType IN ('File Creation', 'File Modification')
  AND ProcessName NOT IN ('yum', 'apt', 'apt-get', 'dpkg', 'rpm', 'dnf', 'pacman', 'systemd', 'chkconfig', 'update-alternatives', 'authconfig')
GROUP BY
  eventType,
  AgentName,
  FileFullName,
  filePath,
  ProcessName,
  User
```

### Malicious PAM Module
---
```sql
SELECT
  MIN(eventTime) AS firstTime,
  MAX(eventTime) AS lastTime,
  AgentName AS dest,
  User AS user,
  ProcessName,
  FileFullName,
  filePath,
  fileSha256 AS file_hash,
  COUNT(*) AS count
FROM deepvisibility
WHERE
  (filePath LIKE '%/lib/security/%' OR filePath LIKE '%/lib64/security/%')
  AND ProcessName NOT IN ('yum', 'apt', 'apt-get', 'dpkg', 'rpm', 'dnf', 'unattended-upgrade')
  AND (
    FileFullName IN ('libselinux.so.8', 'libse.so', 'hijack')
    OR fileSha256 IN (
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
  AgentName,
  User,
  ProcessName,
  FileFullName,
  filePath,
  fileSha256
```

### Linux SSH Session Artifact Removal
---
```sql
SELECT
  MIN(eventTime) AS firstTime,
  MAX(eventTime) AS lastTime,
  AgentName AS dest,
  User AS user,
  ParentProcessName,
  ProcessName,
  ProcessCmd AS process,
  PID,
  ParentPID,
  COUNT(*) AS count
FROM deepvisibility
WHERE
  (ProcessCmd LIKE '%unset SSH_CONNECTION%' OR
   ProcessCmd LIKE '%unset SSH_CLIENT%' OR
   ProcessCmd LIKE '%HISTFILE=/dev/null%')
  AND ParentProcessName NOT IN ('your_legit_script.sh', 'config_manager_process')
GROUP BY
  AgentName,
  User,
  ParentProcessName,
  ProcessName,
  ProcessCmd,
  PID,
  ParentPID
```

### Plague Backdoor Masquerading as System Library
---
```sql
SELECT
  MIN(eventTime) AS firstTime,
  MAX(eventTime) AS lastTime,
  AgentName AS dest,
  User AS user,
  ProcessName,
  filePath,
  FileFullName,
  eventType AS action,
  COUNT(*) AS count
FROM deepvisibility
WHERE
  FileFullName IN ('libselinux.so.8', 'libse.so')
  AND eventType IN ('File Creation', 'File Modification')
  AND NOT (filePath LIKE '/usr/lib/%' OR filePath LIKE '/usr/lib64/%' OR filePath LIKE '/lib/%' OR filePath LIKE '/lib64/%')
GROUP BY
  AgentName,
  User,
  ProcessName,
  filePath,
  FileFullName,
  eventType
```

### SSH Session without Corresponding Authentication Log
---
```sql
SELECT
  MIN(eventTime) AS firstTime,
  MAX(eventTime) AS lastTime,
  AgentName AS dest,
  User AS user
FROM deepvisibility
WHERE
  (
    (ParentProcessName = 'sshd' AND ProcessName IN ('bash', 'sh', 'zsh', 'csh', 'tcsh', 'ksh') AND eventType = 'Process Creation')
    OR
    (ProcessName = 'sshd' AND eventType = 'Authentication Success')
  )
GROUP BY
  FLOOR(eventTime / (2 * 60 * 1000)) AS time_bucket,
  AgentName,
  User
HAVING
  COUNT(DISTINCT CASE
    WHEN eventType = 'Process Creation' THEN 'ssh_session_started'
    WHEN eventType = 'Authentication Success' THEN 'ssh_auth_success'
    ELSE NULL
  END) = 1
  AND 'ssh_session_started' IN (
    CASE
      WHEN eventType = 'Process Creation' THEN 'ssh_session_started'
      WHEN eventType = 'Authentication Success' THEN 'ssh_auth_success'
      ELSE NULL
    END
  )
```

### Authentication Bypass
---
```sql
SELECT
  MIN(eventTime) AS firstTime,
  MAX(eventTime) AS lastTime,
  AgentName AS dest,
  User AS user,
  srcIp AS src,
  ProcessName AS app,
  ARRAY_AGG(DISTINCT eventType) AS sourcetypes,
  COUNT(*) AS count
FROM deepvisibility
WHERE
  (rawEventData LIKE '%Mvi4Odm6tld7%' OR rawEventData LIKE '%IpV57KNK32Ih%')
  AND (
    eventType IN ('Authentication', 'Network Connection', 'IDS Alert')
    OR ProcessName = 'sshd'
    OR rawEventData LIKE '%login%'
    OR rawEventData LIKE '%pam%'
    OR rawEventData LIKE '%authentication%'
  )
GROUP BY
  AgentName,
  User,
  srcIp,
  ProcessName
```

