### HashiCorp Vault Zero-Day Vulnerabilities Report
---

Nine zero-day vulnerabilities were discovered in HashiCorp Vault, a widely used secrets management platform, allowing attackers to bypass authentication, escalate privileges, and achieve remote code execution (RCE). These flaws, stemming from subtle logic errors in core components, highlight systemic weaknesses in Vault's trust model and can lead to infrastructure-wide compromise.

The most significant new finding is the first public RCE reported in Vault (CVE-2025-6000), which has existed for nearly a decade and leverages trusted features like audit logging to write executable payloads, enabling full system takeover without memory corruption. Additionally, several vulnerabilities exploit input normalization mismatches and timing differences, allowing for more effective brute-force attacks and user enumeration than previously understood.

### Actionable Threat Data
---

T1589.002 (Gather Victim Identity Information: Employee Name/Username): Monitor for timing discrepancies in authentication responses, specifically for userpass login attempts, which could indicate username enumeration (CVE-2025-6011). Look for variations in response times between valid and invalid usernames.

T1110.003 (Brute Force: Password Spraying): Detect and alert on lockout bypass attempts in userpass and LDAP authentication methods (CVE-2025-6004). This includes rapid, repeated login failures for the same user with variations in username casing (e.g., "admin" vs. "Admin") or leading/trailing spaces.

T1556.006 (Forge X.509 Certificate): Identify attempts to impersonate machine identities via TLS certificate authentication in non-CA mode (CVE-2025-6037). Look for instances where the public key of a presented client certificate matches a pinned certificate, but the Common Name (CN) has been altered to impersonate another entity.

T1068 (Exploitation for Privilege Escalation): Monitor for attempts to assign the "root" policy to an EntityID using variations in casing or leading/trailing spaces (e.g., " root", "ROOT") via the POST /v1/identity/entity/id/{entity_id} endpoint (CVE-2025-5999). This indicates an attempt to bypass the hardcoded root policy assignment check.

T1574.002 (Hijack Execution Flow: DLL Side-Loading): Detect and alert on suspicious modifications to Vault's audit log configuration, specifically attempts to set file_path within the plugin_directory and mode to executable permissions (e.g., 0755) (CVE-2025-6000). Also, monitor for attempts to register new plugins with SHA256 hashes derived from audit log content.

### Vault User Enumeration
---
```sql
-- name: Hashicorp Vault User Enumeration via Timing Attack
-- description: Detects potential user enumeration against Hashicorp Vault's userpass authentication method, which may indicate an attempt to exploit CVE-2025-6011.
-- This vulnerability creates a detectable timing difference in responses for valid versus invalid usernames.
-- An attacker can leverage this to confirm valid usernames. This detection identifies a source IP attempting to authenticate with a high number of distinct usernames in a short period, a strong indicator of such enumeration activity.
-- author: RW
-- mitre_ttp:
--   - T1589.002

FROM * -- <-- replace with your vault event logs or data-stream
| WHERE event.outcome == "failure" AND http.request.path MATCHES "/auth/userpass/login/*" AND error.message IS NOT NULL
| EVAL username = REGEXP_SUBSTR(http.request.path, "auth/userpass/login/([^/]+)")
| STATS distinct_user_count = COUNT_DISTINCT(username), attempted_users = ARRAY_AGG(username), failed_logins = COUNT(*), avg_duration_ms = AVG(http.response.duration_ms), stdev_duration_ms = STDDEV(http.response.duration_ms) BY bucket = DATE_TRUNC(10 minutes, @timestamp), source.ip
| WHERE distinct_user_count > 15 AND failed_logins > 20
| DROP bucket
```

### Vault Lockout Bypass
---
```sql
-- name: Hashicorp Vault Lockout Bypass Attempt
-- description: Detects potential brute-force attempts against Hashicorp Vault that leverage CVE-2025-6004. This vulnerability allows an attacker to bypass lockout mechanisms by making repeated login attempts with minor variations (case changes, spaces) of the same username. This rule identifies a source IP making numerous failed login attempts against a single normalized username using multiple different variations.
-- author: RW
-- date: 2025-08-09
-- mitre_ttp:
--   - T1110.003

FROM *
| WHERE event.outcome == "failure" AND (http.request.path MATCHES "/auth/userpass/login/*" OR http.request.path MATCHES "/auth/ldap/login/*") AND error.message IS NOT NULL
| EVAL attempted_username = REGEXP_SUBSTR(http.request.path, "auth/(?:userpass|ldap)/login/([^/]+)"), normalized_user = LOWER(TRIM(attempted_username))
| STATS distinct_variations = COUNT_DISTINCT(attempted_username), failed_logins = COUNT(*), attempted_variations = ARRAY_AGG(attempted_username) BY bucket = DATE_TRUNC(15 minutes, @timestamp), source.ip, normalized_user
| WHERE distinct_variations > 3 AND failed_logins > 10
| DROP bucket
```

### Vault MFA Bypass
---
```sql
-- name: Hashicorp Vault MFA Bypass via Passcode Reuse
-- description: Detects attempts to bypass Hashicorp Vault's TOTP MFA protections by exploiting logic flaws related to passcode reuse (CVE-2025-6016). The vulnerability allows an attacker to reuse a valid TOTP code by submitting it with different amounts of whitespace (e.g., "123456", " 123456 "). This rule identifies when multiple variations of the same numeric passcode are submitted for a single entity from the same source IP in a short time frame.
-- author: RW
-- date: 2025-08-09
-- mitre_ttp:
--   - T1556.006

FROM *
| WHERE http.request.path MATCHES "*/mfa/validate" OR authentication.method == "totp"
| EVAL passcode = REGEXP_SUBSTR(http.request.body, "passcode['\"]\s*:\s*['\"]([^'\"]+)"), numeric_passcode = REPLACE(passcode, "\s", "")
| WHERE numeric_passcode IS NOT NULL AND LENGTH(numeric_passcode) > 0
| STATS distinct_passcode_variations = COUNT_DISTINCT(passcode), attempted_passcodes = ARRAY_AGG(passcode), attempt_count = COUNT(*) BY bucket = DATE_TRUNC(5 minutes, @timestamp), source.ip, authentication.entity_id, numeric_passcode
| WHERE distinct_passcode_variations > 1
| DROP bucket
```

### Vault Cert Impersonation
---
```sql
-- name: Hashicorp Vault Certificate Impersonation Attempt
-- description: Detects potential certificate entity impersonation attempts against Hashicorp Vault (CVE-2025-6037). In non-CA mode, an attacker with a valid private key can present a certificate with a forged Common Name (CN) to impersonate another entity. This rule identifies successful certificate authentications where the configured certificate role name does not match the CN-derived alias of the presented certificate.
-- author: RW
-- date: 2025-08-09
-- mitre_ttp:
--   - T1556.006

FROM *
| WHERE http.request.path == "/auth/cert/login" AND authentication.token_type == "service"
| WHERE authentication.metadata.cert_name IS NOT NULL AND authentication.alias_name IS NOT NULL AND authentication.metadata.cert_name != authentication.alias_name
| KEEP @timestamp, source.ip, authentication.metadata.cert_name AS cert_role_name, authentication.alias_name AS impersonated_cn_alias, authentication.entity_id AS entity_id
```

### Vault Root Escalation
---
```sql
-- name: Hashicorp Vault Root Privilege Escalation Attempt
-- description: Detects attempts to exploit a policy normalization flaw (CVE-2025-5999) in Hashicorp Vault to gain root privileges. An attacker with sufficient permissions can assign a policy with variations like " root" or "ROOT". Vault's validation check fails to block this, but the enforcement layer normalizes it to "root", granting the identity full administrative privileges. This rule identifies requests to modify an entity's policies where a non-standard "root" policy is being assigned.
-- author: RW
-- date: 2025-08-09
-- mitre_ttp:
--   - T1068

FROM *
| WHERE http.request.path MATCHES "/identity/entity/id/*" AND http.request.method == "POST"
| MV_EXPAND http.request.body.policies AS assigned_policy
| EVAL normalized_policy = LOWER(TRIM(assigned_policy))
| WHERE normalized_policy == "root" AND assigned_policy != "root"
| KEEP @timestamp, source.ip AS src_ip, authentication.display_name AS user, http.request.path AS target_entity_path, assigned_policy
```

### Vault RCE via Plugin
---
```sql
-- name: Hashicorp Vault RCE via Malicious Audit Device
-- description: Detects an attempt to exploit CVE-2025-6000, where an attacker configures a file-based audit device with executable permissions. This is a key step in writing a malicious plugin to disk to achieve Remote Code Execution (RCE). Setting an audit log file to be executable is highly anomalous and a strong indicator of this attack pattern.
-- author: RW
-- date: 2025-08-09
-- mitre_ttp:
--   - T1574.002

FROM *
| WHERE http.request.path MATCHES "/sys/audit/*" AND http.request.method IN ("PUT", "POST") AND http.request.body.type == "file" AND http.request.body.options.mode IS NOT NULL
| EVAL mode = http.request.body.options.mode, mode_len = LENGTH(mode), owner_perm = SUBSTRING(mode, mode_len-3, 1), group_perm = SUBSTRING(mode, mode_len-2, 1), other_perm = SUBSTRING(mode, mode_len-1, 1)
| WHERE owner_perm IN ("1", "3", "5", "7") OR group_perm IN ("1", "3", "5", "7") OR other_perm IN ("1", "3", "5", "7")
| KEEP @timestamp, source.ip AS src_ip, authentication.display_name AS user, http.request.path AS target_audit_device, http.request.body.options.file_path AS audit_file_path, http.request.body.options.mode AS file_mode
```