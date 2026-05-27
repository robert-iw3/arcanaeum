### APT37 Activity: Rust Backdoor and Python Loader
---

APT37, a North Korean-aligned threat actor, continues to evolve its toolset, now incorporating a Rust-based backdoor (Rustonotto) and a Python-based loader that utilizes Process Doppelgänging for stealthy code injection, primarily targeting individuals connected to the North Korean regime or human rights activism. The group leverages spear-phishing with Windows shortcut or CHM files as initial infection vectors, leading to the deployment of various malware, including the surveillance tool FadeStealer.

A significant new finding is APT37's adoption of Rust for their Rustonotto backdoor, marking their first known use of the language for Windows targets, indicating a move towards modern languages for potential multi-platform attacks. Additionally, the use of Transactional NTFS (TxF) with Process Doppelgänging for FadeStealer deployment showcases an advanced technique for stealthy code injection and evasion.

### Actionable Threat Data
---

Monitor for the creation of scheduled tasks named MicrosoftUpdate that execute 3HNoWZd.exe from C:\ProgramData\.

Detect PowerShell execution that scans %temp% and the current working directory for specific Windows shortcut file sizes (e.g., 6,032,787 bytes) and extracts hex-encoded payloads.

Look for HTTP POST requests with the U= and R= parameters, or U= and _file= parameters, especially those containing Base64-encoded data, as these are indicative of Rustonotto, Chinotto, or FadeStealer C2 communication.

Identify the creation of files and directories under %TEMP%\VSTelems_Fade\ (e.g., NgenPdbk, NgenPdbc, NgenPdbm, VSTelems_FadeOut, VSTelems_FadeIn) which are used by FadeStealer for storing collected surveillance data.

Monitor for the creation of password-protected RAR archives with the hardcoded password NaeMhq[d]q or file names matching watch_YYYY_MM_DD-HH_MM_SS.rar, usb_YYYY_MM_DD-HH_MM_SS.rar, [DeviceName]_YYYY_MM_DD-HH_MM_SS.rar, or data_YYYY_MM_DD-HH_MM_SS.rar.

### Combine Analysis Search
---
```sql
-- Name: APT37 Rustonotto, Chinotto, and FadeStealer Activity
-- Author: RW
-- Date: 2025-09-08
-- Description: Detects various Tactics, Techniques, and Procedures (TTPs) associated with the APT37 threat actor, including the use of Rustonotto, Chinotto, and FadeStealer malware. This rule identifies specific file hashes, file paths, process command lines, registry modifications for persistence, and C2 communication patterns.
-- References: https://www.zscaler.com/blogs/security-research/apt37-targets-windows-rust-backdoor-and-python-loader
-- Tactics: Persistence, Execution, Defense Evasion, Collection, Command and Control, Exfiltration
-- Techniques: T1053.005, T1547.001, T1218.005, T1059.001, T1055.013, T1560.001, T1071.001, T1132.001, T1041
-- False Positives: The C2 communication pattern looking for 'U=' and 'R=' or '_file=' in a URL might be generic and could trigger on legitimate applications. Further tuning by destination IP, domain, or associated process may be required.

`comment("The following search combines multiple data sources. Adjust index and sourcetype values as needed for your environment.")`
(index=* sourcetype=xmlwineventlog:microsoft-windows-sysmon/operational) OR (index=* sourcetype IN (zscaler:nss:web, pan:traffic, suricata))
| `comment("Normalize common field names across different data sources")`
| eval timestamp=_time, event_code=coalesce(EventCode, signature_id), process_path=coalesce(Image, process_path), process_command_line=coalesce(CommandLine, process_command_line), parent_process_path=coalesce(ParentImage, parent_process_path), file_path=coalesce(TargetFilename, file_path), file_hash_md5=coalesce(md5, file_hash_md5), registry_path=coalesce(TargetObject, registry_path), registry_data=coalesce(Details, registry_data), dest_host=coalesce(host, dhost, dest_host), user=coalesce(User, user)

| `comment("Use a case statement to identify which specific TTP was observed")`
| eval rule_trigger = case(
    `comment("IOC match based on known malicious file hashes")`
    event_code IN ("1", "11") AND file_hash_md5 IN ("b9900bef33c6cc9911a5cd7eeda8e093", "7967156e138a66f3ee1bfce81836d8d0", "77a70e87429c4e552649235a9a2cf11a", "04b5e068e6f0079c2c205a42df8a3a84", "d2b34b8bfafd6b17b1cf931bb3fdd3db", "3d6b999d65c775c1d27c8efa615ee520", "89986806a298ffd6367cf43f36136311", "4caa44930e5587a0c9914bda9d240acc"), "File Hash IOC",

    `comment("File creation artifacts related to FadeStealer and other tools")`
    event_code="11" AND (file_path IN ("C:\\ProgramData\\3HNoWZd.exe", "C:\\ProgramData\\wonder.cab", "C:\\ProgramData\\tele_update.exe", "C:\\ProgramData\\tele.conf", "C:\\ProgramData\\tele.dat", "C:\\ProgramData\\Password.chm", "C:\\ProgramData\\1.html") OR match(file_path, "(?i)\\\\VSTelems_Fade\\\\(NgenPdbk|NgenPdbc|NgenPdbm|VSTelems_FadeOut|VSTelems_FadeIn)") OR match(file_path, "(?i)(watch_|usb_|data_).+\.rar$")), "Malicious File Artifact",

    `comment("Suspicious process executions for persistence and payload deployment")`
    event_code="1" AND (match(process_command_line, "(?i)schtasks.* /create .*MicrosoftUpdate.*3HNoWZd\.exe") OR (process_path LIKE "%\\mshta.exe" AND process_command_line LIKE "%http%") OR (parent_process_path LIKE "%\\cmd.exe" AND process_path LIKE "%\\expand.exe" AND process_command_line LIKE "%c:\\programdata\\wonder.cab%") OR (process_path="c:\\programdata\\tele_update.exe")), "Suspicious Process Execution",

    `comment("Registry modification for persistence via Run key")`
    event_code="13" AND (match(registry_path, "(?i)\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\OnedriveStandaloneUpdater") AND match(registry_data, "(?i)mshta.*http")), "Registry Run Key Persistence",

    `comment("C2 communication pattern observed in web proxy logs")`
    (url LIKE "%U=%" AND (url LIKE "%R=%" OR url LIKE "%_file=%")), "C2 Communication Pattern"
)
| where isnotnull(rule_trigger)
| `comment("Format the results for investigation")`
| table timestamp, dest_host, user, rule_trigger, process_path, process_command_line, parent_process_path, file_path, file_hash_md5, registry_path, registry_data, url
| `comment("Deduplicate similar events for cleaner alerting")`
| dedup timestamp, dest_host, rule_trigger, process_command_line
```