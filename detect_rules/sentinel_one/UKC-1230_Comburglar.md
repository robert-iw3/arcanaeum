### UKC-1230 "Comburglar" Persistence via COM Hijack# UKC-1230 "Comburglar" Persistence via COM Hijacking
---

The threat actor UKC-1230 establishes long-term persistence by modifying specific Windows Scheduled Tasks to execute malicious code via COM hijacking. This technique involves altering User_Feed_Synchronization tasks to use a ComHandler that points to a malicious surrogate DLL, which then establishes command-and-control (C2) communications.

The tactics, techniques, and indicators of compromise detailed in the initial report remain the most current intelligence. No new variants, targeted tasks, or C2 infrastructure associated with UKC-1230 or the c4f69d93110080cc2432c9cc3d2c58ab imphash have been publicly reported since the article's publication. The use of COM hijacking for persistence is a well-established, though less common, technique that proves difficult to detect as it abuses legitimate Windows functions.

### Actionable Threat Data
---

TTP: Look for modifications to the User_Feed_Synchronization-{GUID} scheduled task, specifically the replacement of the expected msfeedsync.exe command with a <ComHandler> action.

File Indicator: Hunt for the creation of DLL files that match a GUID file name pattern ({[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}}.dll) in directories such as C:\ProgramData\Microsoft\Windows\ and C:\Users\*\AppData\Local\Microsoft\Windows\.

Malware Indicator: The most reliable indicator for the malicious DLLs used in this campaign is the imphash c4f69d93110080cc2432c9cc3d2c58ab. Searching for this value is more effective than using individual file hashes.

Registry Modification: Monitor for the creation or modification of registry keys under HKEY_CLASSES_ROOT\CLSID\{GUID}\InprocServer32 where the default value points to a GUID-named DLL in an unusual path (e.g., C:\ProgramData).

Network Indicator: Block and alert on any network traffic to or from the techdataservice.us domain and its known subdomains or associated IP addresses.

### Layered Search
---

```sql
/*
 * Title: UKC-1230 Comburglar Multi-Indicator Detection
 * Author: RW
 * Date: 2026-01-11
 * Description: Detects multiple indicators associated with the UKC-1230 'Comburglar' malware. This includes the specific malware imphash, C2 DNS queries, creation of GUID-patterned DLLs for COM hijacking, and suspicious COM surrogate process execution patterns.
 * References: https://www.blackhillsinfosec.com/the-curious-case-of-the-comburglar/
 * MITRE ATT&CK: T1546.015 (Component Object Model Hijacking), T1053.005 (Scheduled Task), TA0011 (Command and Control), T1071.004 (Application Layer Protocol: DNS)
 * Tags: UKC-1230, Comburglar, Persistence, C2, COM Hijacking
 * FP Note: This rule combines high-fidelity IOCs (imphash, domain) with strong behavioral patterns. The behavioral clauses (GUID-DLL creation, dllhost execution) may have a slight chance of collision with legitimate software installers or system components that use similar patterns. Review the matched logic and process ancestry for any alerts.
 */
(
  src.process.image.imphash = "c4f69d93110080cc2432c9cc3d2c58ab"
  OR
  tgt.file.image.imphash = "c4f69d93110080cc2432c9cc3d2c58ab"
  OR
  (event.type = "DNS" AND event.dns.request contains "techdataservice.us")
  OR
  (
    event.type = "File Creation"
    AND tgt.file.path matches ".*\\\\\\{[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\\}\\.dll$"
    AND (
      tgt.file.path matches "^C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\.*"
      OR tgt.file.path matches "^C:\\\\Users\\\\.*\\\\AppData\\\\Local\\\\Microsoft\\\\Windows\\\\.*"
    )
  )
  OR
  (
    src.process.name = "dllhost.exe"
    AND src.process.parent.name = "svchost.exe"
    AND src.process.cmdline contains "/Processid:{"
  )
)
```