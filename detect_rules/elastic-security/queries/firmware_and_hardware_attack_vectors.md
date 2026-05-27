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
FROM *
| WHERE event.category == "process" AND process.name == "bcdedit.exe" AND process.command_line ILIKE "*set*path*"
  AND NOT process.command_line ILIKE "*path*(\\Windows\\system32\\winload.(efi|exe)|\\EFI\\Microsoft\\Boot\\bootmgfw.efi)*"
| EVAL new_boot_path = REGEXP_SUBSTR(process.command_line, "(?i)\\spath\\s+([^ ]+)", 1)
| WHERE new_boot_path IS NOT NULL
| EVAL rule_name = "Suspicious BCDEDIT Boot Path Modification",
       file_name = REGEXP_REPLACE(new_boot_path, "^.*\\\\", ""),
       file_path = new_boot_path
| KEEP @timestamp, rule_name, host.name, user.name, process.parent.name, process.command_line, file_name, file_path
```
```sql
-- Part 2: Detects suspicious file creation in the EFI System Partition (ESP)
FROM *
| WHERE event.category == "file" AND event.action == "created"
  AND file.path ILIKE "*\\EFI\\*\\Boot\\*.efi"
  AND NOT process.name IN ("bcdboot.exe", "TiWorker.exe", "TrustedInstaller.exe", "svchost.exe", "setup.exe", "dism.exe", "wuauclt.exe", "msiexec.exe", "bootim.exe")
| EVAL rule_name = "Suspicious EFI File Creation", process_cmd = "N/A"
| KEEP @timestamp, rule_name, host.name, user.name, process.name, process_cmd, file.name, file.path
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
FROM *
| WHERE event.category == "process" AND process.name == "bootsect.exe" AND process.command_line ILIKE "*/mbr*"
| EVAL rule_name = "MBR Modification with bootsect.exe", file_name = "N/A", file_path = "N/A"
| KEEP @timestamp, rule_name, host.name, user.name, process.parent.name, process.command_line, file_name, file_path
```
```sql
-- Part 2: Detects suspicious file creation in the EFI System Partition (ESP).
FROM *
| WHERE event.category == "file" AND event.action == "created" AND file.path ILIKE "*\\EFI\\*.efi"
  AND NOT process.name IN ("bcdboot.exe", "TiWorker.exe", "TrustedInstaller.exe", "svchost.exe", "setup.exe", "dism.exe", "wuauclt.exe", "msiexec.exe", "bootim.exe")
| EVAL rule_name = "Suspicious EFI File Creation in Boot Partition", process_cmd = "N/A", parent_process = process.name
| KEEP @timestamp, rule_name, host.name, user.name, parent_process, process_cmd, file.name, file.path
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
FROM *
| WHERE event.category == "process" AND process.name == "bcdedit.exe" AND process.command_line ILIKE "*set*path*"
  AND NOT process.command_line ILIKE "*path*(\\Windows\\system32\\winload.(efi|exe)|\\EFI\\Microsoft\\Boot\\bootmgfw.efi)*"
| EVAL new_boot_path = REGEXP_SUBSTR(process.command_line, "(?i)\\spath\\s+([^ ]+)", 1)
| WHERE new_boot_path IS NOT NULL
| EVAL rule_name = "Suspicious Boot Configuration Modification (BlackLotus)",
       file_name = REGEXP_REPLACE(new_boot_path, "^.*\\\\", ""),
       file_path = new_boot_path
| KEEP @timestamp, rule_name, host.name, user.name, process.parent.name, process.command_line, file_name, file_path
```
```sql
-- Part 2: Detects suspicious file creation in the EFI System Partition (ESP).
FROM *
| WHERE event.category == "file" AND event.action == "created"
  AND file.path ILIKE "*\\EFI\\*" AND file.name ILIKE "*.efi|*.bmp|*.jpg|*.jpeg|*.gif|*.png"
  AND NOT process.name IN ("bcdboot.exe", "TiWorker.exe", "TrustedInstaller.exe", "svchost.exe", "setup.exe", "dism.exe", "wuauclt.exe", "msiexec.exe", "bootim.exe", "fwupd.exe", "DellCommandUpdate.exe", "LenovoVantage.exe", "HPImageAssistant.exe")
| EVAL rule_name = CASE(
    file.name ILIKE "*.efi", "Suspicious EFI File Creation (Bootkit)",
    file.name ILIKE "*.bmp|*.jpg|*.jpeg|*.gif|*.png", "Suspicious Image File Creation in EFI Partition (LogoFAIL)",
    TRUE, "Suspicious File Creation in EFI Partition"
  ), process_cmd = "N/A", parent_process = process.name
| KEEP @timestamp, rule_name, host.name, user.name, parent_process, process_cmd, file.name, file.path
```

### Supply Chain Integrity Compromise
---
```sql
-- Rule Title: Suspicious Child Process of Software Update Executable
-- Author: RW
-- Date: 2025-08-10
-- Description: Detects when a known software update process spawns a suspicious child process, such as a command shell or scripting engine. This behavior can be an indicator of a supply chain attack, where a legitimate and signed updater is trojanized to execute malicious code, as seen in attacks like SUNBURST and ShadowHammer.
-- MITRE TTPs: T1195

FROM *
| WHERE event.category == "process"
  AND process.name IN ("powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "cscript.exe", "wscript.exe", "mshta.exe", "bitsadmin.exe")
  AND process.parent.name IN ("SolarWinds.BusinessLayerHost.exe", "AsusLiveUpdate.exe", "LiveUpdate.exe", "DellCommandUpdate.exe", "LenovoVantage.exe", "HPImageAssistant.exe", "AdobeARM.exe", "GoogleUpdate.exe", "Update.exe")
| STATS count = COUNT(*) BY @timestamp BUCKET 1h, host.name, user.name, process.parent.name, process.name, process.command_line
| EVAL rule_name = "Suspicious Child Process from Updater"
| KEEP @timestamp, rule_name, host.name, user.name, process.parent.name, process.name, process.command_line, count
| RENAME host.name AS host, process.parent.name AS parent_process_name, process.name AS process_name, process.command_line AS process_cmd
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

FROM *
| WHERE event.category == "network" AND destination.port IN (21, 22, 23, 69, 80, 161, 443, 514, 8080, 8443)
| LOOKUP network_devices ON destination.ip OUTPUT ip AS is_network_device
| WHERE is_network_device IS NOT NULL
| LOOKUP admin_workstations ON source.ip OUTPUT ip AS is_admin_workstation
| WHERE is_admin_workstation IS NULL
| WHERE NOT (process.name IN ("msedge.exe", "chrome.exe", "firefox.exe") AND destination.port IN (80, 443, 8080, 8443))
| STATS event_count = COUNT(*), start_time = MIN(@timestamp), end_time = MAX(@timestamp), ports_contacted = ARRAY_AGG(destination.port), processes_used = ARRAY_AGG(process.name), command_lines = ARRAY_AGG(process.command_line)
  BY BUCKET(@timestamp, 1h), host.name, user.name, source.ip, destination.ip
| EVAL start_time = TO_STRING(start_time, "yyyy-MM-dd HH:mm:ss"), end_time = TO_STRING(end_time, "yyyy-MM-dd HH:mm:ss")
| KEEP start_time, end_time, host.name, user.name, source.ip, destination.ip, ports_contacted, processes_used, command_lines, event_count
| RENAME host.name AS host, source.ip AS src, destination.ip AS dest_network_device
```