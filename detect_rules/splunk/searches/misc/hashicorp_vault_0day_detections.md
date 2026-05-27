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

`vault` -- <-- vault event data source
"request.path"="auth/userpass/login/*" "error"!=""
-- comment: Filter for failed login attempts to the userpass authentication endpoint.
| rex field=request.path "auth/userpass/login/(?<username>[^/]+)"
-- comment: Extract the attempted username from the request path.
| bucket _time span=10m
-- comment: Group events into 10-minute windows to analyze bursts of activity.
| stats dc(username) as distinct_user_count, values(username) as attempted_users, count as failed_logins, avg(response.duration_ms) as avg_duration_ms, stdev(response.duration_ms) as stdev_duration_ms by _time, request.remote_address
-- comment: For each source IP, count distinct usernames, list them, and calculate statistics on response duration. A high standard deviation in duration may further indicate a mix of fast (invalid user) and slow (valid user) responses.
| where distinct_user_count > 15 AND failed_logins > 20
-- comment: Thresholds for alerting. These values should be tuned based on your environment's baseline activity. A high number of distinct users from one IP is a strong signal of enumeration.
| rename request.remote_address as src_ip
| fields - _time
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

`vault`
(request.path="auth/userpass/login/*" OR request.path="auth/ldap/login/*") "error"!=""
-- comment: Filter for failed logins to userpass or LDAP endpoints.
| rex field=request.path "auth/(?:userpass|ldap)/login/(?<attempted_username>[^/]+)"
-- comment: Extract the username from the request path.
| eval normalized_user = lower(trim(attempted_username))
-- comment: Normalize the username by trimming spaces and converting to lowercase to group variations of the same account.
| bucket _time span=15m
-- comment: Group events into 15-minute windows to analyze activity.
| stats dc(attempted_username) as distinct_variations, count as failed_logins, values(attempted_username) as attempted_variations by _time, request.remote_address, normalized_user
-- comment: For each source IP and normalized user, count the distinct variations attempted and total failures.
| where distinct_variations > 3 AND failed_logins > 10
-- comment: Alert when multiple variations of a username are used in numerous failed attempts. Thresholds may need tuning for your environment to reduce potential false positives from users with legitimate typing errors.
| rename request.remote_address as src_ip
| fields - _time
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

`vault`
(request.path="*/mfa/validate" OR auth.method_type=totp)
-- comment: Filter for Vault TOTP MFA validation events. The exact filter may need adjustment based on your Vault logging configuration.
| rex field=request.body "passcode[\"']\s*:\s*[\"'](?<passcode>[^\"']+)"
-- comment: Extract the submitted passcode from the request body. This regex is designed to handle JSON with potential variations in spacing.
| eval numeric_passcode = replace(passcode, "\s", "")
-- comment: Normalize the passcode by removing all whitespace to group attempts using the same numeric code.
| where isnull(numeric_passcode) OR len(numeric_passcode) > 0
-- comment: Ensure we are only analyzing events where a passcode was successfully extracted.
| bucket _time span=5m
-- comment: Group events into 5-minute windows to correlate related attempts.
| stats dc(passcode) as distinct_passcode_variations, values(passcode) as attempted_passcodes, count by _time, request.remote_address, auth.entity_id, numeric_passcode
-- comment: For each source IP, entity, and normalized passcode, count the number of distinct raw variations submitted.
| where distinct_passcode_variations > 1
-- comment: Alert when more than one variation of the same numeric passcode is used. This is a strong indicator of an attempt to bypass one-time-use protection via space padding. This threshold is sensitive; consider increasing to > 2 to reduce potential false positives from legitimate user errors.
| rename request.remote_address as src_ip, auth.entity_id as entity_id
| fields - _time
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

`vault`
request_path="auth/cert/login" auth_token_type="service"
-- comment: Filter for successful machine-to-machine certificate-based authentications. Field names may vary based on your Vault log parsing configuration.
| where isnotnull(auth_metadata_cert_name) AND isnotnull(auth_alias_name) AND auth_metadata_cert_name != auth_alias_name
-- comment: The core detection logic. It triggers when the configured certificate role name differs from the alias created from the presented certificate's Common Name. This is a strong indicator of impersonation.
| rename auth_metadata_cert_name as cert_role_name, auth_alias_name as impersonated_cn_alias, request_remote_address as src_ip, auth_entity_id as entity_id
-- comment: Rename fields for clarity in the alert.
| table _time, src_ip, cert_role_name, impersonated_cn_alias, entity_id
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

`vault`
request_path="/identity/entity/id/*" request_method="POST"
-- comment: Filter for POST requests to the identity entity modification endpoint. Field names for policies (e.g., request_data_policies{}) may vary based on log parsing.
| mvexpand request_data_policies{}
-- comment: Expand the list of policies being assigned in the request.
| rename request_data_policies{} as assigned_policy
| eval normalized_policy = lower(trim(assigned_policy))
-- comment: Normalize the policy name by trimming whitespace and converting to lowercase, mimicking Vault's vulnerable behavior.
| where normalized_policy == "root" AND assigned_policy != "root"
-- comment: The core detection logic. This triggers if a policy normalizes to "root" but was not originally the exact string "root", indicating a bypass attempt. This is a high-fidelity indicator of exploit activity.
| rename request_remote_address as src_ip, auth_display_name as user, request_path as target_entity_path
| table _time, src_ip, user, target_entity_path, assigned_policy
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

`vault`
request_path="/sys/audit/*" (request_method="PUT" OR request_method="POST") request_data_type="file" isnotnull(request_data_options_mode)
-- comment: Filter for requests that configure or modify a file-based audit device and have a file mode specified. Field names (e.g., request_data_*) may vary based on log parsing.
| eval mode = request_data_options_mode
| eval mode_len = len(mode)
| eval owner_perm = substr(mode, mode_len-2, 1)
| eval group_perm = substr(mode, mode_len-1, 1)
| eval other_perm = substr(mode, mode_len, 1)
-- comment: Extract the owner, group, and other permission digits from the file mode string.
| where (owner_perm IN ("1","3","5","7")) OR (group_perm IN ("1","3","5","7")) OR (other_perm IN ("1","3","5","7"))
-- comment: The core detection logic. Alert if any of the permission sets (owner, group, or other) have the execute bit set. This is highly suspicious for an audit log file. While this could be a legitimate but unusual administrative action, it warrants investigation.
| rename request_remote_address as src_ip, auth_display_name as user, request_path as target_audit_device, request_data_options_file_path as audit_file_path, request_data_options_mode as file_mode
-- comment: Rename fields for clarity in the alert.
| table _time, src_ip, user, target_audit_device, audit_file_path, file_mode
```