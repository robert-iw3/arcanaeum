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

-- Part 1: Detects MBR modification using the bootsect.exe utility.
EventType=Process AND ProcessName="bcdedit.exe" AND CommandLine REGEXP "(?i)\\bset\\b.*\\bpath\\b"
AND NOT CommandLine REGEXP "(?i)\\bpath\\s+(\\Windows\\system32\\winload\.(efi|exe)|\\EFI\\Microsoft\\Boot\\bootmgfw\.efi)"
| SELECT Time, ComputerName, UserName, CommandLine, ParentProcessName,
       "Suspicious BCDEDIT Boot Path Modification" AS RuleName,
       REGEXP_EXTRACT(CommandLine, "(?i)\\spath\\s+([^ ]+)", 1) AS FilePath,
       REGEXP_REPLACE(REGEXP_EXTRACT(CommandLine, "(?i)\\spath\\s+([^ ]+)", 1), "^.*\\\\", "") AS FileName
| FIELDS Time, RuleName, ComputerName, UserName, ParentProcessName, CommandLine, FileName, FilePath
```
```sql
-- Part 2: Detects suspicious file creation in the EFI System Partition (ESP).
EventType=File AND FileAction=Created AND FilePath REGEXP "(?i)\\bEFI\\.*Boot\\.*\.efi$"
AND NOT ProcessName IN ("bcdboot.exe", "TiWorker.exe", "TrustedInstaller.exe", "svchost.exe", "setup.exe", "dism.exe", "wuauclt.exe", "msiexec.exe", "bootim.exe")
| SELECT Time, ComputerName, UserName, ProcessName, FileName, FilePath,
       "Suspicious EFI File Creation" AS RuleName, "N/A" AS ProcessCmd
| FIELDS Time, RuleName, ComputerName, UserName, ProcessName, ProcessCmd, FileName, FilePath
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
EventType=Process AND ProcessName="bootsect.exe" AND CommandLine REGEXP "(?i)\\b/mbr\\b"
| SELECT Time, ComputerName, UserName, CommandLine, ParentProcessName,
       "MBR Modification with bootsect.exe" AS RuleName,
       "N/A" AS FileName, "N/A" AS FilePath
| FIELDS Time, RuleName, ComputerName, UserName, ParentProcessName, CommandLine, FileName, FilePath
```
```sql
-- Part 2: Detects suspicious file creation in the EFI System Partition (ESP).
EventType=File AND FileAction=Created AND FilePath REGEXP "(?i)\\bEFI\\.*\.efi$"
AND NOT ProcessName IN ("bcdboot.exe", "TiWorker.exe", "TrustedInstaller.exe", "svchost.exe", "setup.exe", "dism.exe", "wuauclt.exe", "msiexec.exe", "bootim.exe")
| SELECT Time, ComputerName, UserName, ProcessName, FileName, FilePath,
       "Suspicious EFI File Creation in Boot Partition" AS RuleName, "N/A" AS ProcessCmd
| FIELDS Time, RuleName, ComputerName, UserName, ProcessName, ProcessCmd, FileName, FilePath
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
EventType=Process AND ProcessName="bcdedit.exe" AND CommandLine REGEXP "(?i)\\bset\\b.*\\bpath\\b"
AND NOT CommandLine REGEXP "(?i)\\bpath\\s+(\\Windows\\system32\\winload\.(efi|exe)|\\EFI\\Microsoft\\Boot\\bootmgfw\.efi)"
| SELECT Time, ComputerName, UserName, CommandLine, ParentProcessName,
       "Suspicious Boot Configuration Modification (BlackLotus)" AS RuleName,
       REGEXP_EXTRACT(CommandLine, "(?i)\\spath\\s+([^ ]+)", 1) AS FilePath,
       REGEXP_REPLACE(REGEXP_EXTRACT(CommandLine, "(?i)\\spath\\s+([^ ]+)", 1), "^.*\\\\", "") AS FileName
| FIELDS Time, RuleName, ComputerName, UserName, ParentProcessName, CommandLine, FileName, FilePath
```
```sql
-- Part 2: Detects suspicious file creation in the EFI System Partition (ESP).
EventType=File AND FileAction=Created AND FilePath REGEXP "(?i)\\bEFI\\.*\.(efi|bmp|jpg|jpeg|gif|png)$"
AND NOT ProcessName IN ("bcdboot.exe", "TiWorker.exe", "TrustedInstaller.exe", "svchost.exe", "setup.exe", "dism.exe", "wuauclt.exe", "msiexec.exe", "bootim.exe", "fwupd.exe", "DellCommandUpdate.exe", "LenovoVantage.exe", "HPImageAssistant.exe")
| SELECT Time, ComputerName, UserName, ProcessName, FileName, FilePath,
       CASE
         WHEN FileName REGEXP "(?i)\.efi$" THEN "Suspicious EFI File Creation (Bootkit)"
         WHEN FileName REGEXP "(?i)\.(bmp|jpg|jpeg|gif|png)$" THEN "Suspicious Image File Creation in EFI Partition (LogoFAIL)"
         ELSE "Suspicious File Creation in EFI Partition"
       END AS RuleName,
       "N/A" AS ProcessCmd
| FIELDS Time, RuleName, ComputerName, UserName, ProcessName, ProcessCmd, FileName, FilePath
```

### Supply Chain Integrity Compromise
---
```sql
-- Rule Title: Suspicious Child Process of Software Update Executable
-- Author: RW
-- Date: 2025-08-10
-- Description: Detects when a known software update process spawns a suspicious child process, such as a command shell or scripting engine. This behavior can be an indicator of a supply chain attack, where a legitimate and signed updater is trojanized to execute malicious code, as seen in attacks like SUNBURST and ShadowHammer.
-- MITRE TTPs: T1195

EventType=Process
AND ProcessName IN ("powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "cscript.exe", "wscript.exe", "mshta.exe", "bitsadmin.exe")
AND ParentProcessName IN ("SolarWinds.BusinessLayerHost.exe", "AsusLiveUpdate.exe", "LiveUpdate.exe", "DellCommandUpdate.exe", "LenovoVantage.exe", "HPImageAssistant.exe", "AdobeARM.exe", "GoogleUpdate.exe", "Update.exe")
| SELECT Time, ComputerName, UserName, ParentProcessName, ProcessName, CommandLine, COUNT(*) AS count
| GROUP BY Time BUCKET 1h, ComputerName, UserName, ParentProcessName, ProcessName, CommandLine
| SELECT Time, "Suspicious Child Process from Updater" AS RuleName, ComputerName AS host, UserName AS user, ParentProcessName AS parent_process_name, ProcessName AS process_name, CommandLine AS process_cmd, count
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

EventType=Network AND DestPort IN (21, 22, 23, 69, 80, 161, 443, 514, 8080, 8443)
| LOOKUP network_devices DestIPAddress AS ip OUTPUT ip AS is_network_device
| WHERE is_network_device IS NOT NULL
| LOOKUP admin_workstations SrcIPAddress AS ip OUTPUT ip AS is_admin_workstation
| WHERE is_admin_workstation IS NULL
| WHERE NOT (ProcessName IN ("msedge.exe", "chrome.exe", "firefox.exe") AND DestPort IN (80, 443, 8080, 8443))
| SELECT MIN(Time) AS start_time, MAX(Time) AS end_time, ComputerName, UserName, SrcIPAddress, DestIPAddress,
       GROUP_CONCAT(DestPort) AS ports_contacted, GROUP_CONCAT(ProcessName) AS processes_used, GROUP_CONCAT(CommandLine) AS command_lines, COUNT(*) AS event_count
| GROUP BY Time BUCKET 1h, ComputerName, UserName, SrcIPAddress, DestIPAddress
| SELECT STRFTIME(start_time, "%Y-%m-%d %H:%M:%S") AS start_time, STRFTIME(end_time, "%Y-%m-%d %H:%M:%S") AS end_time,
       ComputerName AS host, UserName AS user, SrcIPAddress AS src, DestIPAddress AS dest_network_device,
       ports_contacted, processes_used, command_lines, event_count
```