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
FROM * // replace with your linux endpoint index or data-stream
| WHERE
  (file.path LIKE "/etc/pam.d/*" OR file.path IN ("/lib/security/*", "/usr/lib/security/*", "/lib64/security/*"))
  AND event.action IN ("creation", "modification")
  AND process.name NOT IN ("yum", "apt", "apt-get", "dpkg", "rpm", "dnf", "pacman", "systemd", "chkconfig", "update-alternatives", "authconfig")
| STATS
  count = COUNT(*),
  firstTime = MIN(@timestamp),
  lastTime = MAX(@timestamp)
  BY
  event.action,
  host.name,
  file.name,
  file.path,
  process.name,
  user.name
| EVAL
  firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
  lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| KEEP
  firstTime,
  lastTime,
  host.name,
  user.name,
  process.name,
  file.path,
  file.name,
  event.action,
  count
```

### Malicious PAM Module
---
```sql
FROM *
| WHERE
  (file.path LIKE "*/lib/security/*" OR file.path LIKE "*/lib64/security/*")
  AND process.name NOT IN ("yum", "apt", "apt-get", "dpkg", "rpm", "dnf", "unattended-upgrade")
  AND (
    file.name IN ("libselinux.so.8", "libse.so", "hijack")
    OR file.hash.sha256 IN (
      "85c66835657e3ee6a478a2e0b1fd3d87119bebadc43a16814c30eb94c53766bb",
      "7c3ada3f63a32f4727c62067d13e40bcb9aa9cbec8fb7e99a319931fc5a9332e",
      "9445da674e59ef27624cd5c8ffa0bd6c837de0d90dd2857cf28b16a08fd7dba6",
      "5e6041374f5b1e6c05393ea28468a91c41c38dc6b5a5230795a61c2b60ed14bc",
      "6d2d30d5295ad99018146c8e67ea12f4aaa2ca1a170ad287a579876bf03c2950",
      "e594bca43ade76bbaab2592e9eabeb8dca8a72ed27afd5e26d857659ec173261",
      "14b0c90a2eff6b94b9c5160875fcf29aff15dcfdfd3402d953441d9b0dca8b39"
    )
  )
| STATS
  count = COUNT(*),
  firstTime = MIN(@timestamp),
  lastTime = MAX(@timestamp)
  BY
  host.name,
  user.name,
  process.name,
  file.name,
  file.path,
  file.hash.sha256
| EVAL
  firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
  lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| KEEP
  firstTime,
  lastTime,
  host.name,
  user.name,
  process.name,
  file.name,
  file.path,
  file.hash.sha256
```

### Linux SSH Session Artifact Removal
---
```sql
FROM *
| WHERE
  (process.command_line LIKE "*unset SSH_CONNECTION*" OR
   process.command_line LIKE "*unset SSH_CLIENT*" OR
   process.command_line LIKE "*HISTFILE=/dev/null*")
  AND process.parent.name NOT IN ("your_legit_script.sh", "config_manager_process")
| STATS
  count = COUNT(*),
  firstTime = MIN(@timestamp),
  lastTime = MAX(@timestamp)
  BY
  host.name,
  user.name,
  process.parent.name,
  process.name,
  process.command_line,
  process.pid,
  process.parent.pid
| EVAL
  firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
  lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| KEEP
  firstTime,
  lastTime,
  host.name,
  user.name,
  process.parent.name,
  process.name,
  process.command_line,
  process.pid,
  process.parent.pid,
  count
```

### Plague Backdoor Masquerading as System Library
---
```sql
FROM *
| WHERE
  file.name IN ("libselinux.so.8", "libse.so")
  AND event.action IN ("creation", "modification")
  AND NOT (file.path LIKE "/usr/lib/*" OR file.path LIKE "/usr/lib64/*" OR file.path LIKE "/lib/*" OR file.path LIKE "/lib64/*")
| STATS
  count = COUNT(*),
  firstTime = MIN(@timestamp),
  lastTime = MAX(@timestamp)
  BY
  host.name,
  user.name,
  process.name,
  file.path,
  file.name,
  event.action
| EVAL
  firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
  lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| KEEP
  firstTime,
  lastTime,
  host.name,
  user.name,
  process.name,
  file.path,
  file.name,
  event.action,
  count
```

### SSH Session without Corresponding Authentication Log
---
```sql
FROM * // logs-endpoint.events.process-*, logs-endpoint.events.auth-*
| WHERE
  (
    (event.dataset == "endpoint.events.process" AND process.parent.name == "sshd" AND process.name IN ("bash", "sh", "zsh", "csh", "tcsh", "ksh"))
    OR
    (event.dataset == "endpoint.events.auth" AND process.name == "sshd" AND event.action == "success")
  )
| EVAL
  event_type = CASE(
    event.dataset == "endpoint.events.process", "ssh_session_started",
    event.dataset == "endpoint.events.auth", "ssh_auth_success",
    NULL
  ),
  time_bucket = DATE_TRUNC(2 minutes, @timestamp)
| STATS
  event_types = ARRAY_AGG(DISTINCT event_type),
  firstTime = MIN(@timestamp),
  lastTime = MAX(@timestamp)
  BY time_bucket, host.name, user.name
| WHERE ARRAY_LENGTH(event_types) == 1 AND "ssh_session_started" IN event_types
| EVAL
  firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
  lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| KEEP
  firstTime, lastTime, host.name, user.name
```

### Authentication Bypass
---
```sql
FROM *
| WHERE
  (event.original LIKE "*Mvi4Odm6tld7*" OR event.original LIKE "*IpV57KNK32Ih*")
  AND (
    event.dataset IN ("linux.auth", "linux.secure", "suricata", "zeek.conn", "pan.traffic")
    OR process.name == "sshd"
    OR event.action IN ("login", "authentication")
    OR event.original LIKE "*pam*"
  )
| STATS
  count = COUNT(*),
  firstTime = MIN(@timestamp),
  lastTime = MAX(@timestamp),
  sourcetypes = ARRAY_AGG(DISTINCT event.dataset)
  BY host.name, user.name, source.ip, process.name
| EVAL
  firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
  lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| KEEP
  firstTime, lastTime, host.name, user.name, source.ip, process.name, sourcetypes, count
```

