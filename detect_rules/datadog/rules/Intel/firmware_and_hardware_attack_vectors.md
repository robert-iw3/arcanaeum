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
source:endpoint process.name:bcdedit.exe "set" "path"
-source:endpoint "path \\Windows\\system32\\winload.(efi|exe)" "path \\EFI\\Microsoft\\Boot\\bootmgfw.efi"
| parse regex "path\\s+(?<new_boot_path>[^\\s]+)" in process.command_line
| where new_boot_path is not null
| group by @timestamp, host.name, user.name, process.command_line, process.parent.name
| select @timestamp, "Suspicious BCDEDIT Boot Path Modification" as rule_name, host.name as host, user.name as user, process.parent.name as process_name, process.command_line as process_cmd, replace(new_boot_path, "^.*\\\\", "") as file_name, new_boot_path as file_path
```
```sql
-- Part 2: Detects suspicious file creation in the EFI System Partition (ESP)
source:endpoint file.action:created file.path:"*\\EFI\\*\\Boot\\*.efi"
-source:endpoint process.name:(bcdboot.exe TiWorker.exe TrustedInstaller.exe svchost.exe setup.exe dism.exe wuauclt.exe msiexec.exe bootim.exe)
| group by @timestamp, host.name, user.name, process.name, file.name, file.path
| select @timestamp, "Suspicious EFI File Creation" as rule_name, host.name as host, user.name as user, process.name as process_name, "N/A" as process_cmd, file.name as file_name, file.path as file_path
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
source:endpoint process.name:bootsect.exe "/mbr"
| group by @timestamp, host.name, user.name, process.command_line, process.parent.name
| select @timestamp, "MBR Modification with bootsect.exe" as rule_name, host.name as host, user.name as user, process.parent.name as parent_process, process.command_line as process_cmd, "N/A" as file_name, "N/A" as file_path
```
```sql
-- Part 2: Detects suspicious file creation in the EFI System Partition (ESP).
source:endpoint file.action:created file.path:"*\\EFI\\*.efi"
-source:endpoint process.name:(bcdboot.exe TiWorker.exe TrustedInstaller.exe svchost.exe setup.exe dism.exe wuauclt.exe msiexec.exe bootim.exe)
| group by @timestamp, host.name, user.name, process.name, file.name, file.path
| select @timestamp, "Suspicious EFI File Creation in Boot Partition" as rule_name, host.name as host, user.name as user, process.name as parent_process, "N/A" as process_cmd, file.name as file_name, file.path as file_path
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
source:endpoint process.name:bcdedit.exe "set" "path"
-source:endpoint "path \\Windows\\system32\\winload.(efi|exe)" "path \\EFI\\Microsoft\\Boot\\bootmgfw.efi"
| parse regex "path\\s+(?<new_boot_path>[^\\s]+)" in process.command_line
| where new_boot_path is not null
| group by @timestamp, host.name, user.name, process.command_line, process.parent.name
| select @timestamp, "Suspicious Boot Configuration Modification (BlackLotus)" as rule_name, host.name as host, user.name as user, process.parent.name as parent_process, process.command_line as process_cmd, replace(new_boot_path, "^.*\\\\", "") as file_name, new_boot_path as file_path
```
```sql
-- Part 2: Detects suspicious file creation in the EFI System Partition (ESP).
source:endpoint file.action:created file.path:"*\\EFI\\*" file.name:("*.efi" "*.bmp" "*.jpg" "*.jpeg" "*.gif" "*.png")
-source:endpoint process.name:(bcdboot.exe TiWorker.exe TrustedInstaller.exe svchost.exe setup.exe dism.exe wuauclt.exe msiexec.exe bootim.exe fwupd.exe DellCommandUpdate.exe LenovoVantage.exe HPImageAssistant.exe)
| group by @timestamp, host.name, user.name, process.name, file.name, file.path
| select @timestamp,
        case(
          file.name matches "*.efi", "Suspicious EFI File Creation (Bootkit)",
          file.name matches "*.bmp" OR file.name matches "*.jpg" OR file.name matches "*.jpeg" OR file.name matches "*.gif" OR file.name matches "*.png", "Suspicious Image File Creation in EFI Partition (LogoFAIL)",
          true, "Suspicious File Creation in EFI Partition"
        ) as rule_name,
        host.name as host, user.name as user, process.name as parent_process, "N/A" as process_cmd, file.name as file_name, file.path as file_path
```

### Supply Chain Integrity Compromise
---
```sql
-- Rule Title: Suspicious Child Process of Software Update Executable
-- Author: RW
-- Date: 2025-08-10
-- Description: Detects when a known software update process spawns a suspicious child process, such as a command shell or scripting engine. This behavior can be an indicator of a supply chain attack, where a legitimate and signed updater is trojanized to execute malicious code, as seen in attacks like SUNBURST and ShadowHammer.
-- MITRE TTPs: T1195

source:endpoint process.name:(powershell.exe pwsh.exe cmd.exe rundll32.exe cscript.exe wscript.exe mshta.exe bitsadmin.exe)
process.parent.name:(SolarWinds.BusinessLayerHost.exe AsusLiveUpdate.exe LiveUpdate.exe DellCommandUpdate.exe LenovoVantage.exe HPImageAssistant.exe AdobeARM.exe GoogleUpdate.exe Update.exe)
| group by @timestamp, host.name, user.name, process.parent.name, process.name, process.command_line timebucket:1h
| select @timestamp, host.name as host, user.name as user, process.parent.name as parent_process_name, process.name as process_name, process.command_line as process_cmd, count
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

source:network dest.port:(21 22 23 69 80 161 443 514 8080 8443)
| lookup network_devices ip=dest.ip OUTPUT ip AS is_network_device
| where is_network_device IS NOT NULL
| lookup admin_workstations ip=src.ip OUTPUT ip AS is_admin_workstation
| where is_admin_workstation IS NULL
| where NOT (process.name IN (msedge.exe chrome.exe firefox.exe) AND dest.port IN (80 443 8080 8443))
| group by @timestamp timebucket:1h, host.name, user.name, src.ip, dest.ip, dest.port, process.name, process.command_line
| select min(@timestamp) AS start_time, max(@timestamp) AS end_time, host.name AS host, user.name AS user, src.ip AS src, dest.ip AS dest_network_device, values(dest.port) AS ports_contacted, values(process.name) AS processes_used, values(process.command_line) AS command_lines, count AS event_count
| formatTime(start_time, "YYYY-MM-DD HH:mm:ss"), formatTime(end_time, "YYYY-MM-DD HH:mm:ss")
```