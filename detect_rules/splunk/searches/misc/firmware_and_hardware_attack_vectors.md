### Firmware and Hardware Attack Vectors: A Threat Intelligence Report
---

Firmware and hardware-level attacks are increasingly prevalent, allowing adversaries to gain fundamental control, subvert security, and achieve persistence undetected by traditional security solutions. These attacks pose significant risks, ranging from nation-state espionage to financially motivated ransomware campaigns, by targeting critical components like UEFI, network devices, and supply chains.

Recent developments highlight the commoditization of sophisticated firmware attacks, with new bootkits like BlackLotus bypassing Secure Boot and vulnerabilities like LogoFAIL and PixieFail demonstrating widespread impact across various vendors and systems. The emergence of threats like BadCam weaponizing Linux webcams further expands the attack surface to peripheral devices.

### Actionable Threat Data
---

Monitor for UEFI/BIOS firmware modifications and integrity compromises (T1542.001, T1542.003): Adversaries are increasingly targeting UEFI/BIOS for persistence and to subvert security controls, as seen with BlackLotus, MosaicRegressor, and LoJax. Look for unauthorized changes to firmware images, configurations, and boot processes.

Detect MBR and bootloader manipulation (T1542.002): Ransomware families like Thanos and EFILock, and even modules like TrickBoot, continue to target the Master Boot Record (MBR) and bootloaders to disable systems or establish persistence. Monitor for unexpected modifications to the MBR or EFI System Partition (ESP) files.

Identify exploitation attempts against known firmware vulnerabilities (CVEs): Actively scan for and patch systems vulnerable to recently disclosed flaws such as CVE-2024-0762 (Phoenix SecureCore UEFI), CVE-2022-21894 (BlackLotus bypass), LogoFAIL (UEFI image parsers), and PixieFail (UEFI IPv6 network stack).

Implement supply chain integrity verification for hardware and software (T1195): Attacks like SUNBURST and ShadowHammer demonstrate the risk of compromised updates and components. Establish processes to verify the integrity of newly acquired devices and software throughout their lifecycle, including firmware.

Monitor network and VPN device firmware for compromise (T1542.001): State-sponsored actors and ransomware groups frequently target the firmware of network infrastructure (e.g., VPNs, firewalls, routers) for initial access and persistence. Look for unusual network traffic patterns, unauthorized firmware updates, or unexpected configurations on these devices.

### UEFI/BIOS Firmware Mod
---
```sql
-- Rule Title: UEFI/BIOS Firmware Modification Attempt
-- Author: RW
-- Date: 2025-08-10
-- Description: Detects attempts to modify system boot configuration or create suspicious files in the EFI System Partition (ESP). Such behavior is associated with UEFI bootkits like BlackLotus, LoJax, and MosaicRegressor, which modify the boot process for persistence.
-- MITRE TTPs: T1542.001, T1542.003

-- Part 1: Detects suspicious modification of boot configuration using bcdedit.exe
`tstats` count from datamodel=Endpoint.Processes where (Processes.process_name="bcdedit.exe" AND Processes.process="*/set*" AND Processes.process="*path*") by _time Processes.dest Processes.user Processes.process Processes.parent_process_name
| `drop_dm_object_name("Processes")`
-- Medium FP Risk: Extracts the new boot path from the command line.
| rex field=process "(?i)\spath\s+(?<new_boot_path>[^ ]+)"
| where isnotnull(new_boot_path)
-- FP Tuning: Filter out known legitimate boot paths. Add others specific to your environment.
| where NOT match(new_boot_path, "(?i)(\\\\Windows\\\\system32\\\\winload\.(efi|exe)|\\\\EFI\\\\Microsoft\\\\Boot\\\\bootmgfw\.efi)")
| rename dest as host, process as process_cmd, parent_process_name as process_name
| eval rule_name="Suspicious BCDEDIT Boot Path Modification", file_path=new_boot_path, file_name=replace(new_boot_path, "^.*\\\\", "")
| table _time, rule_name, host, user, process_name, process_cmd, file_name, file_path

| append [
    -- Part 2: Detects suspicious file creation in the EFI System Partition (ESP)
    `tstats` count from datamodel=Endpoint.Filesystem where (Filesystem.action="created" AND Filesystem.file_path="*\\EFI\\*" AND Filesystem.file_path="*\\Boot\\*" AND Filesystem.file_name="*.efi") by _time Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path
    | `drop_dm_object_name("Filesystem")`
    -- FP Tuning: Windows updates and installers legitimately write to the ESP.
    -- This list of legitimate processes may need to be expanded based on your environment.
    | where NOT (process_name IN ("bcdboot.exe", "TiWorker.exe", "TrustedInstaller.exe", "svchost.exe", "setup.exe", "dism.exe", "wuauclt.exe", "msiexec.exe", "bootim.exe"))
    | rename dest as host, file_name as file_name, file_path as file_path
    | eval rule_name="Suspicious EFI File Creation", process_cmd="N/A"
    | table _time, rule_name, host, user, process_name, process_cmd, file_name, file_path
]
```

### MBR/Bootloader Manipulation
---
```sql
-- Rule Title: MBR/Bootloader Manipulation Detected
-- Author: RW
-- Date: 2025-08-10
-- Description: Detects attempts to modify the Master Boot Record (MBR) or create suspicious files in the EFI System Partition (ESP). This behavior is associated with bootkits and ransomware like Thanos, EFILock, and TrickBoot, which target the pre-boot environment for persistence or to render a system unbootable.
-- MITRE TTPs: T1542.002

-- Part 1: Detects MBR modification using the bootsect.exe utility.
`tstats` count from datamodel=Endpoint.Processes where (Processes.process_name="bootsect.exe" AND Processes.process="*/mbr*") by _time Processes.dest Processes.user Processes.process Processes.parent_process_name
| `drop_dm_object_name("Processes")`
-- FP Tuning: Legitimate use of bootsect.exe for MBR modification is rare outside of system imaging or recovery scenarios.
| rename dest as host, process as process_cmd, parent_process_name as parent_process
| eval rule_name="MBR Modification with bootsect.exe", file_name="N/A", file_path="N/A"
| table _time, rule_name, host, user, parent_process, process_cmd, file_name, file_path

| append [
    -- Part 2: Detects suspicious file creation in the EFI System Partition (ESP).
    `tstats` count from datamodel=Endpoint.Filesystem where (Filesystem.action="created" AND Filesystem.file_path="*\\EFI\\*" AND Filesystem.file_name="*.efi") by _time Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path
    | `drop_dm_object_name("Filesystem")`
    -- FP Tuning: Windows updates, installers, and recovery tools legitimately write to the ESP.
    -- This list of legitimate processes may need to be expanded based on your environment's software.
    | where NOT (process_name IN ("bcdboot.exe", "TiWorker.exe", "TrustedInstaller.exe", "svchost.exe", "setup.exe", "dism.exe", "wuauclt.exe", "msiexec.exe", "bootim.exe"))
    | rename dest as host
    | eval rule_name="Suspicious EFI File Creation in Boot Partition", parent_process=process_name, process_cmd="N/A"
    | table _time, rule_name, host, user, parent_process, process_cmd, file_name, file_path
]
```

### Firmware Vulnerability Exploitation
---
```sql
-- Rule Title: Firmware Vulnerability Exploitation Attempt
-- Author: RW
-- Date: 2025-08-10
-- Description: Detects preparatory actions for firmware vulnerability exploitation, such as those seen with BlackLotus (CVE-2022-21894) and LogoFAIL. This includes suspicious modification of boot configuration data (BCD) and the creation of unusual executable or image files in the EFI System Partition (ESP).
-- MITRE TTPs: T1542.001, T1542.003

-- Part 1: Detects suspicious modification of boot configuration, a technique used by BlackLotus.
`tstats` count from datamodel=Endpoint.Processes where (Processes.process_name="bcdedit.exe" AND Processes.process="*/set*" AND Processes.process="*path*") by _time Processes.dest Processes.user Processes.process Processes.parent_process_name
| `drop_dm_object_name("Processes")`
-- Medium FP Risk: Extracts the new boot path from the command line.
| rex field=process "(?i)\spath\s+(?<new_boot_path>[^ ]+)"
| where isnotnull(new_boot_path)
-- FP Tuning: Filter out known legitimate boot paths. Add others specific to your environment.
| where NOT match(new_boot_path, "(?i)(\\\\Windows\\\\system32\\\\winload\.(efi|exe)|\\\\EFI\\\\Microsoft\\\\Boot\\\\bootmgfw\.efi)")
| rename dest as host, process as process_cmd, parent_process_name as parent_process
| eval rule_name="Suspicious Boot Configuration Modification (BlackLotus)", file_path=new_boot_path, file_name=replace(new_boot_path, "^.*\\\\", "")
| table _time, rule_name, host, user, parent_process, process_cmd, file_name, file_path

| append [
    -- Part 2: Detects suspicious file creation in the EFI System Partition (ESP).
    `tstats` count from datamodel=Endpoint.Filesystem where (Filesystem.action="created" AND Filesystem.file_path="*\\EFI\\*") AND (Filesystem.file_name="*.efi" OR Filesystem.file_name="*.bmp" OR Filesystem.file_name="*.jpg" OR Filesystem.file_name="*.jpeg" OR Filesystem.file_name="*.gif" OR Filesystem.file_name="*.png") by _time Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path
    | `drop_dm_object_name("Filesystem")`
    -- FP Tuning: Legitimate processes from OS updates, installers, or OEM tools may write to the ESP.
    -- This exclusion list may need to be expanded based on your environment.
    | where NOT (process_name IN ("bcdboot.exe", "TiWorker.exe", "TrustedInstaller.exe", "svchost.exe", "setup.exe", "dism.exe", "wuauclt.exe", "msiexec.exe", "bootim.exe", "fwupd.exe", "DellCommandUpdate.exe", "LenovoVantage.exe", "HPImageAssistant.exe"))
    | rename dest as host
    | eval rule_name=case(
        match(file_name, "(?i)\.efi$"), "Suspicious EFI File Creation (Bootkit)",
        match(file_name, "(?i)\.(bmp|jpg|jpeg|gif|png)$"), "Suspicious Image File Creation in EFI Partition (LogoFAIL)",
        1=1, "Suspicious File Creation in EFI Partition"
        ),
        parent_process=process_name,
        process_cmd="N/A"
    | table _time, rule_name, host, user, parent_process, process_cmd, file_name, file_path
]
```

### Supply Chain Integrity Compromise
---
```sql
-- Rule Title: Suspicious Child Process of Software Update Executable
-- Author: RW
-- Date: 2025-08-10
-- Description: Detects when a known software update process spawns a suspicious child process, such as a command shell or scripting engine. This behavior can be an indicator of a supply chain attack, where a legitimate and signed updater is trojanized to execute malicious code, as seen in attacks like SUNBURST and ShadowHammer.
-- MITRE TTPs: T1195

| tstats count from datamodel=Endpoint.Processes where
    -- Identify a known updater process as the parent.
    (Processes.parent_process_name IN (
        "SolarWinds.BusinessLayerHost.exe",
        "AsusLiveUpdate.exe",
        "LiveUpdate.exe",
        "DellCommandUpdate.exe",
        "LenovoVantage.exe",
        "HPImageAssistant.exe",
        "AdobeARM.exe",
        "GoogleUpdate.exe",
        "Update.exe"
    ))
    -- Check if the child process is a suspicious shell or script engine.
    AND (Processes.process_name IN (
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "rundll32.exe",
        "cscript.exe",
        "wscript.exe",
        "mshta.exe",
        "bitsadmin.exe"
    ))
    by _time span=1h Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name("Processes")`
-- FP Tuning: Some legitimate installers use command scripts. If legitimate activity is flagged,
-- consider adding command-line exclusions for known good scripts to reduce noise.
-- For example: `| search NOT (process="*my-legit-install-script.cmd*")`
| rename dest as host, process as process_cmd
| fields _time, host, user, parent_process_name, process_name, process_cmd, count
```

### Network/VPN Firmware Compromise
---
```sql
-- Rule Title: Potential Network Device Compromise Attempt
-- Author: RW
-- Date: 2025-08-10
-- Description: Detects suspicious network connections from endpoints to the management or file transfer interfaces of network devices (e.g., routers, firewalls, VPNs). This activity could indicate an attempt to exploit a vulnerability, install malicious firmware, or exfiltrate configuration data, as seen in attacks by state-sponsored actors and ransomware groups.
-- MITRE TTPs: T1542.001

-- --- Lookup Configuration ---
-- FP Tuning: Create and populate the following lookups with assets from your environment.
-- `network_devices.csv`: A lookup file with a column named 'ip' containing your core network infrastructure IP addresses (e.g., routers, firewalls, VPNs).
-- `admin_workstations.csv`: A lookup file with a column named 'ip' containing known administrative workstation or jump server IPs.

`tstats` summariesonly=t count from datamodel=Endpoint.Network_Traffic where All_Traffic.dest_port IN (21, 22, 23, 69, 80, 161, 443, 514, 8080, 8443) by _time span=1h All_Traffic.dest All_Traffic.user All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.process_name All_Traffic.process All_Traffic.dest_port
| `drop_dm_object_name("All_Traffic")`

-- Filter for traffic where the destination is a known network device.
| lookup network_devices.csv ip as dest_ip OUTPUT ip as is_network_device
| where isnotnull(is_network_device)

-- Exclude traffic originating from known administrative workstations to reduce false positives.
| lookup admin_workstations.csv ip as src_ip OUTPUT ip as is_admin_workstation
| where isnull(is_admin_workstation)

-- FP Tuning: Exclude common web browsers accessing standard web ports, but still alert on other processes.
| where NOT (process_name IN ("msedge.exe", "chrome.exe", "firefox.exe") AND dest_port IN (80, 443, 8080, 8443))

-- Aggregate results to create a single alert per source/destination pair over the time window.
| stats earliest(_time) as start_time, latest(_time) as end_time, values(dest_port) as ports_contacted, values(process_name) as processes_used, values(process) as command_lines, sum(count) as event_count by dest, user, src_ip, dest_ip

-- Rename fields for clarity and consistency.
| rename dest as host, src_ip as src, dest_ip as dest_network_device
| convert ctime(start_time), ctime(end_time)

-- Final table of results.
| table start_time, end_time, host, user, src, dest_network_device, ports_contacted, processes_used, command_lines, event_count
```