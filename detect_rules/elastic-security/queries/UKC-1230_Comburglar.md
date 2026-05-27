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
// Comburglar (UKC-1230) Persistence & Execution Detection
// Correlates GUID DLL drops, imphash/SHA256 matches, suspicious dllhost, registry mods, C2 to techdataservice.us
// MITRE: T1546.015 (COM Hijacking), T1053.005 (Scheduled Task), TA0011 (C2)
// References: Black Hills Infosec (Dec 2025) - no 2026 variants noted

FROM "winlogbeat-*", "endpoint-*", "logs-endpoint.events.*", "logs-windows.sysmon_operational-*"
| WHERE @timestamp >= NOW() - 30 days   // Tune for persistence (often 7+ months)

    AND (
        // High-Fidelity: Imphash/SHA256 matches (expanded from IOCs)
        (
            file.hash.imphash == "c4f69d93110080cc2432c9cc3d2c58ab"
            OR file.hash.sha256 IN (
                "407d179f920342312dd526abc8a194b2620d0b19a95032dd36eeb70ec3bf5d65",
                "1f529a76faea1e7fa56cbc24c66ddeb5a18d025af654c7e92635d9866e22819d",
                "3f5bc475d9394d352341b1f843b85cfb300e363dd27d4ca867e9e6d54317d881",
                "0073473b4baf3c29156597aab6d948fe7dc91972fdf350f88753e1e9e5217009",
                "3e9efef4121da751f36070a7ffed49eb1b1f72831651e8ecf47e45dd7602c05e",
                "498eaa0d4e5dfa6495a8c3308a3c02f38841809b0d3cab86448b559dbbe8e47c",
                "4a85f0d06561ea94150fd84a536993119ba62638e23b95cecac3e17fc21874cb",
                "1a783fcab9ae545dee58228b38dc9d4fa0c2d0dc35c23f4f5a9d01303ecabd72",
                "9ed58663f7a0bb91c0d9e058a376e78f6748fa4a88e69a0e4598312b3ba75a0c",
                "a68bcf09f8c83c67dfe0b17030367ebccf0905f4f531663c73b990202e2a13b0"
            )
        )

        OR

        // High-Fidelity: C2 DNS/Connections (expanded subdomains/IPs)
        (
            dns.question.name RLIKE "(?i).*(push|ch3|ch4|ch6|ch7|ch9|console|mdns|sync|telemetry)\\.techdataservice\\.us"
            OR destination.ip IN (
                "23.95.182.21", "38.180.143.167", "52.129.44.42",
                "87.121.61.185", "87.121.61.251", "88.99.163.99", "104.225.131.18"
            )
        )

        OR

        // Behavioral: GUID-named DLL creation in suspicious paths (Sysmon EventID 11)
        (
            event.code == "11"  // FileCreate
            AND file.path RLIKE "(?i)(C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\.*|C:\\\\Users\\\\.*\\\\AppData\\\\Local\\\\Microsoft\\\\Windows\\\\.*)"
            AND file.path RLIKE "(?i)\\\\\\{[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\\}\\.dll$"
        )

        OR

        // Behavioral: Suspicious COM Surrogate (dllhost.exe by svchost.exe; Sysmon EventID 1)
        (
            event.code == "1"  // ProcessCreate
            AND process.name == "dllhost.exe"
            AND process.parent.name == "svchost.exe"
            AND process.command_line RLIKE "(?i)/Processid:\\{.*\\}"
        )

        OR

        // New: Scheduled Task Modification (e.g., User_Feed_Synchronization with ComHandler; file or registry events)
        (
            (file.path RLIKE "(?i)C:\\\\Windows\\\\System32\\\\Tasks\\\\User_Feed_Synchronization-.*"
             AND file.content RLIKE "(?i)<ComHandler>.*<ClassId>\\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\}</ClassId>")
            OR (event.category == "registry" AND registry.path RLIKE "(?i)HKCR\\\\CLSID\\\\\\{[0-9a-fA-F]{8}-.*\\}\\\\InprocServer32"
                AND registry.data.strings RLIKE "(?i)\\\\\\{[0-9a-fA-F]{8}-.*\\}\\.dll")
        )
    )

| EVAL
    signal = CASE(
        file.hash.imphash == "c4f69d93110080cc2432c9cc3d2c58ab" OR file.hash.sha256 IN (...), "High-Fidelity: Imphash/SHA256 Match",
        dns.question.name RLIKE "(?i)techdataservice\\.us" OR destination.ip IN (...), "High-Fidelity: C2 DNS/Connection",
        event.code == "11" AND file.path RLIKE "(?i)\\{.*\\}\\.dll", "Behavioral: GUID-Named DLL Created",
        event.code == "1" AND process.name == "dllhost.exe" AND process.parent.name == "svchost.exe", "Behavioral: Suspicious COM Surrogate Execution",
        file.path RLIKE "(?i)User_Feed_Synchronization" OR registry.path RLIKE "(?i)HKCR\\\\CLSID", "Behavioral: Scheduled Task/Registry Modification",
        true, "Other"
    ),
    signal_weight = CASE(  // For risk scoring
        signal LIKE "High-Fidelity%", 4,
        true, 2
    )

// Time clustering: Group related events in 1-hour buckets
| EVAL time_bucket = DATE_TRUNC("hour", @timestamp)

| STATS
    distinct_signals     = COUNT_DISTINCT(signal),
    signals              = VALUES(signal),
    file_names           = VALUES(file.name),
    file_paths           = VALUES(file.path),
    file_hashes          = VALUES(COALESCE(file.hash.sha256, file.hash.imphash)),
    c2_queries           = VALUES(dns.question.name),
    c2_ips               = VALUES(destination.ip),
    registry_keys        = VALUES(registry.path),
    parent_cmds          = VALUES(process.parent.command_line)
  BY
    host.name, time_bucket

| WHERE (signals LIKE "High-Fidelity%") OR (distinct_signals >= 2 AND signals LIKE "Behavioral%")

| EVAL risk_score = SUM(signal_weight)  // New: >5 = medium, >8 = high

| WHERE risk_score > 5  // Tunable; combines with signal logic

| SORT risk_score DESC, distinct_signals DESC, time_bucket DESC

| RENAME host.name AS host

| KEEP
    host,
    time_bucket AS event_window,
    signals,
    distinct_signals,
    risk_score,
    file_names,
    file_paths,
    file_hashes,
    c2_queries,
    c2_ips,
    registry_keys,
    parent_cmds
```