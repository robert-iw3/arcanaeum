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

FROM logs-*
| WHERE
  -- Tactic 1: ClickFix rundll32 Execution
  (event.category == "process" AND process.name == "rundll32.exe" AND REGEXP(process.command_line, "\\\\.*\\.dll"))
  OR
  -- Tactic 2: Persistence via UserInitMprLogonScript
  ((event.category == "process" AND process.name == "reg.exe" AND REGEXP(process.command_line, "add.*HKCU\\\\Environment\\\\UserInitMprLogonScript")) OR
   (event.category == "registry" AND REGEXP(registry.path, ".*\\\\Environment\\\\UserInitMprLogonScript") AND REGEXP(registry.data.strings, "powershell")))
  OR
  -- Tactic 3: Registry Payload Storage
  ((event.category == "process" AND process.name == "powershell.exe" AND REGEXP(process.command_line, "{53121F47-8C52-44A7-89A5-5595BB2B32BE}.*(EnthusiastMode|QatItems)")) OR
   (event.category == "registry" AND REGEXP(registry.path, ".*\\\\CLSID\\\\{53121F47-8C52-44A7-89A5-5595BB2B32BE}\\\\DefaultIcon.*") AND registry.key IN ("EnthusiastMode", "QatItems")))
  OR
  -- Tactic 4: C2 Communication
  (event.category == "network" AND (destination.domain IN ("captchanom.top", "southprovesolutions.com") OR
   http.request.user_agent == "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edge/133.0.0.0"))
  OR
  -- Tactic 5: PowerShell Reconnaissance
  (event.category == "process" AND process.name == "powershell.exe" AND
   ((REGEXP(process.command_line, "whoami /all") AND REGEXP(process.command_line, "ipconfig /all") AND REGEXP(process.command_line, "systeminfo")) OR
    REGEXP(process.command_line, "EnumerateFiles.*EnumerateDirectories.*(\\.pdf|\\.doc|\\.xls)")))
| EVAL detection_tactic = CASE(
    process.name == "rundll32.exe" AND REGEXP(process.command_line, "\\\\.*\\.dll"), "COLDRIVER - ClickFix Rundll32 Execution",
    (process.name == "reg.exe" AND REGEXP(process.command_line, "add.*HKCU\\\\Environment\\\\UserInitMprLogonScript")) OR REGEXP(registry.path, ".*\\\\Environment\\\\UserInitMprLogonScript"), "COLDRIVER - Persistence via UserInitMprLogonScript",
    REGEXP(process.command_line, "{53121F47-8C52-44A7-89A5-5595BB2B32BE}") OR REGEXP(registry.path, ".*\\\\CLSID\\\\{53121F47-8C52-44A7-89A5-5595BB2B32BE}\\\\DefaultIcon.*"), "COLDRIVER - Registry Payload Storage",
    destination.domain IN ("captchanom.top", "southprovesolutions.com") OR http.request.user_agent == "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edge/133.0.0.0", "COLDRIVER - C2 Communication",
    process.name == "powershell.exe" AND (REGEXP(process.command_line, "whoami /all") OR REGEXP(process.command_line, "EnumerateFiles")), "COLDRIVER - PowerShell Reconnaissance",
    "N/A"
  )
| WHERE detection_tactic != "N/A"
| STATS count = COUNT(*),
        process_command_line = MV_CONCAT(process.command_line),
        parent_process = MV_CONCAT(process.parent.name),
        registry_path = MV_CONCAT(registry.path),
        registry_key = MV_CONCAT(registry.key),
        registry_value = MV_CONCAT(registry.data.strings),
        c2_domain = MV_CONCAT(destination.domain),
        user_agent = MV_CONCAT(http.request.user_agent)
  BY @timestamp, host.name, user.name, detection_tactic
| RENAME host.name AS host, user.name AS user
| SORT @timestamp DESC
| KEEP @timestamp, host, user, detection_tactic, parent_process, process_command_line, registry_path, registry_key, registry_value, c2_domain, user_agent, count
```