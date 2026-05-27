### COLDRIVER Campaign Leverages BAITSWITCH and SIMPLEFIX for Targeted Attacks
---

The Russia-linked APT group COLDRIVER has updated its arsenal with new malware, BAITSWITCH and SIMPLEFIX, in a multi-stage ClickFix campaign primarily targeting Russian civil society. This campaign utilizes social engineering to trick users into executing malicious commands, leading to the deployment of a downloader and a PowerShell-based backdoor for persistence, reconnaissance, and data exfiltration.

COLDRIVER has introduced two new lightweight malware families: BAITSWITCH, a downloader DLL, and SIMPLEFIX, a PowerShell backdoor, expanding their capabilities beyond credential phishing to include more sophisticated post-exploitation activities. Notably, the group continues to leverage the ClickFix social engineering technique, which they adopted in early 2025, demonstrating its continued effectiveness in their operations.

### Actionable Threat Data
---

Monitor for rundll32.exe executing DLLs from unusual network shares or paths, specifically looking for rundll32.exe \\<C2_DOMAIN>\check\machinerie.dll,verifyme or similar patterns.

Detect modifications to the HKCU\Environment\UserInitMprLogonScript registry key to establish persistence, especially when setting a PowerShell script to run at logon with hidden window styles.

Look for PowerShell scripts interacting with the registry keys HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{53121F47-8C52-44A7-89A5-5595BB2B32BE}\DefaultIcon\EnthusiastMode and QatItems for storing encrypted payloads.

Identify outbound network connections to captchanom[.]top and southprovesolutions[.]com, particularly those using a hardcoded user-agent string like Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edge/133.0.0.0.

Monitor for PowerShell processes executing commands that perform extensive system reconnaissance (whoami /all, ipconfig /all, systeminfo, net share, net session, netstat -ano, arp -a, net user) or enumerate specific file types in user directories (Documents, Downloads, Desktop, OneDrive).

### Combined Search Logic
---
```sql
-- Title: COLDRIVER Campaign Activity (BAITSWITCH/SIMPLEFIX)
-- Description: This detection rule identifies multiple Tactics, Techniques, and Procedures (TTPs) associated with a COLDRIVER campaign active in September 2025. The campaign utilizes a downloader named BAITSWITCH and a PowerShell backdoor named SIMPLEFIX. This rule combines several detection opportunities into a single query, including initial execution via rundll32, persistence through logon scripts, storing payloads in the registry, C2 communications, and PowerShell-based reconnaissance.
-- Author: RW
-- Date: 2025-09-27
-- References:
-- - https://www.zscaler.com/blogs/security-research/coldriver-updates-arsenal-baitswitch-and-simplefix
-- False Positive Sensitivity: Medium
-- Detection Comment Level: Medium

-- The base search should target process creation, registry modification, and network traffic logs. The field names used (e.g., process_name, process_command_line, dest_host, http_user_agent, registry_path) should be mapped to your environment's data models, such as the Splunk CIM.
(index=* sourcetype=*)

-- Use a WHERE clause with OR conditions to combine multiple detection patterns.
| where
    (
        -- Tactic 1: ClickFix rundll32.exe execution from a network share.
        (process_name="rundll32.exe" AND process_command_line LIKE "%\\\\%\\%.dll%")
    )
    OR
    (
        -- Tactic 2: Persistence via UserInitMprLogonScript registry key.
        (process_name="reg.exe" AND process_command_line LIKE "%add%HKCU\\Environment%UserInitMprLogonScript%")
        OR (registry_path="*\\Environment\\UserInitMprLogonScript" AND registry_value="*powershell*")
    )
    OR
    (
        -- Tactic 3: Storing encrypted payloads in the registry.
        (process_name="powershell.exe" AND (process_command_line LIKE "%EnthusiastMode%" OR process_command_line LIKE "%QatItems%") AND process_command_line LIKE "%{53121F47-8C52-44A7-89A5-5595BB2B32BE}%")
        OR (registry_path="*\\CLSID\\{53121F47-8C52-44A7-89A5-5595BB2B32BE}\\DefaultIcon*" AND (registry_key="EnthusiastMode" OR registry_key="QatItems"))
    )
    OR
    (
        -- Tactic 4: C2 Communication with specific User-Agent or domains.
        (dest_host IN ("captchanom.top", "southprovesolutions.com"))
        OR (http_user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edge/133.0.0.0")
    )
    OR
    (
        -- Tactic 5: Extensive PowerShell reconnaissance.
        (process_name="powershell.exe" AND (
            (process_command_line LIKE "%whoami /all%" AND process_command_line LIKE "%ipconfig /all%" AND process_command_line LIKE "%systeminfo%")
            OR (process_command_line LIKE "%EnumerateFiles%" AND process_command_line LIKE "%EnumerateDirectories%" AND (process_command_line LIKE "%.pdf%" OR process_command_line LIKE "%.doc%" OR process_command_line LIKE "%.xls%"))
        ))
    )

-- Create a field to identify which specific tactic was triggered.
| eval detection_tactic = case(
    (process_name="rundll32.exe" AND process_command_line LIKE "%\\\\%\\%.dll%"), "COLDRIVER - ClickFix Rundll32 Execution",
    (process_name="reg.exe" AND process_command_line LIKE "%add%HKCU\\Environment%UserInitMprLogonScript%") OR (registry_path="*\\Environment\\UserInitMprLogonScript"), "COLDRIVER - Persistence via UserInitMprLogonScript",
    (process_command_line LIKE "%{53121F47-8C52-44A7-89A5-5595BB2B32BE}%") OR (registry_path="*\\CLSID\\{53121F47-8C52-44A7-89A5-5595BB2B32BE}\\DefaultIcon*"), "COLDRIVER - Registry Payload Storage",
    (dest_host IN ("captchanom.top", "southprovesolutions.com")) OR (http_user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edge/133.0.0.0"), "COLDRIVER - C2 Communication",
    (process_name="powershell.exe" AND (process_command_line LIKE "%whoami /all%" OR process_command_line LIKE "%EnumerateFiles%")), "COLDRIVER - PowerShell Reconnaissance"
)

-- False Positive Tuning: The PowerShell reconnaissance logic is broad and may trigger on legitimate administrative activity. Consider adding exclusions for known administrative scripts or user accounts.
-- False Positive Tuning: The rundll32 execution from a network share can be legitimate in some environments. Filter by specific parent processes or users if this is noisy.

-- Group similar events and list key details for analysis.
| stats
    count
    values(process_command_line) as process_command_line
    values(parent_process) as parent_process
    values(registry_path) as registry_path
    values(registry_key) as registry_key
    values(registry_value) as registry_value
    values(dest_host) as c2_domain
    values(http_user_agent) as user_agent
    by _time, dest, user, detection_tactic

-- Provide a final, human-readable output.
| rename dest as host
| table _time, host, user, detection_tactic, parent_process, process_command_line, registry_path, registry_key, registry_value, c2_domain, user_agent, count
```