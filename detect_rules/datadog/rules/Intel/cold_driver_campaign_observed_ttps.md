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

-- Tactic 1: ClickFix rundll32 Execution
source:windows AND @process.name:"rundll32.exe" AND @process.command_line:/\\\\.*\.dll/
| @detection_tactic:"COLDRIVER - ClickFix Rundll32 Execution"

-- Tactic 2: Persistence via UserInitMprLogonScript
(source:windows AND @process.name:"reg.exe" AND @process.command_line:/add.*HKCU\\Environment\\UserInitMprLogonScript/) OR
(source:windows AND @registry.path:/.*\\Environment\\UserInitMprLogonScript/ AND @registry.value:/powershell/)
| @detection_tactic:"COLDRIVER - Persistence via UserInitMprLogonScript"

-- Tactic 3: Registry Payload Storage
(source:windows AND @process.name:"powershell.exe" AND @process.command_line:/{53121F47-8C52-44A7-89A5-5595BB2B32BE}.*(EnthusiastMode|QatItems)/) OR
(source:windows AND @registry.path:/.*\\CLSID\\{53121F47-8C52-44A7-89A5-5595BB2B32BE}\\DefaultIcon.*/ AND @registry.key:("EnthusiastMode" "QatItems"))
| @detection_tactic:"COLDRIVER - Registry Payload Storage"

-- Tactic 4: C2 Communication
source:network AND (@destination.host:("captchanom.top" "southprovesolutions.com") OR
@http.user_agent:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edge/133.0.0.0")
| @detection_tactic:"COLDRIVER - C2 Communication"

-- Tactic 5: PowerShell Reconnaissance
source:windows AND @process.name:"powershell.exe" AND
((@process.command_line:/whoami \/all/ AND @process.command_line:/ipconfig \/all/ AND @process.command_line:/systeminfo/) OR
(@process.command_line:/EnumerateFiles.*EnumerateDirectories.*(\.pdf|\.doc|\.xls)/))
| @detection_tactic:"COLDRIVER - PowerShell Reconnaissance"
```