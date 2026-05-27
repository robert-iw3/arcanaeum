### Crypto24 Ransomware Group: Stealthy Attacks and Evasion Techniques
---

The Crypto24 ransomware group conducts highly coordinated, multi-stage attacks utilizing a blend of legitimate tools and custom malware to achieve stealthy infiltration, lateral movement, and data exfiltration. This group focuses on high-profile organizations across financial services, manufacturing, entertainment, and technology sectors in Asia, Europe, and the USA, often operating during off-peak hours to evade detection.

Crypto24's use of a customized RealBlindingEDR variant, which specifically targets and disables a wide range of security solutions by manipulating driver callbacks, represents a significant evolution in ransomware evasion techniques. This highlights the group's deep technical expertise and ability to develop purpose-built tools to circumvent modern defenses.

### Actionable Threat Data
---

Monitor for the creation of new user accounts, especially those with generic names, and their addition to privileged groups like "Administrators" or "Remote Desktop Users" using net.exe commands.

Detect the execution of sc.exe to create new services with suspicious binPath values, particularly those masquerading as legitimate Windows services (e.g., svchost.exe -k WinMainSvc for keyloggers or svchost.exe -k MSRuntime for ransomware).

Look for the presence and execution of files named AVB.exe, AVMon.exe, or similar in temporary directories (%USERPROFILE%\AppData\Local\Temp\Low\, %PROGRAMDATA%\update\) as these are associated with the RealBlindingEDR tool used for EDR bypass.

Identify attempts to modify the fDenyTSConnections registry key or add firewall rules to allow RDP connections using reg.exe and netsh.exe, as well as modifications to termsrv.dll to enable multiple RDP sessions.

Create detections for the execution of gpscript.exe with command-line arguments that include paths to uninstallers for security products (e.g., XBCUninstaller.exe), indicating an attempt to disable endpoint protection.

### Search
---
```sql
-- Name: Crypto24 Ransomware Group TTPs
-- Author: RW
-- Date: 2025-08-15
-- Description: This rule detects a variety of Tactics, Techniques, and Procedures (TTPs) associated with the Crypto24 ransomware group. It combines several detection logics into a single query to identify suspicious account creation, malicious service installation, EDR evasion tools, RDP enablement, and the uninstallation of security products via GPO.
-- Data Sources: This query is written for Sysmon (Event Codes 1 and 11) but can be adapted for any CIM-compliant EDR data source.
-- False Positive Sensitivity: Medium. This is a high-level rollup query. Each sub-detection has its own false positive considerations. Legitimate administrative activity may trigger parts of this rule. Tune by excluding known administrative accounts, tools, or scripts.
-- References: https://www.trendmicro.com/en_us/research/25/h/crypto24-ransomware-stealth-attacks.html

search (index=* (sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational OR sourcetype=sysmon))
| rename host as DeviceName
| eval TTP=case(
    -- TTP 1: Suspicious Account Creation and Elevation
    (EventCode=1 AND (ProcessName="net.exe" OR ProcessName="net1.exe") AND match(CommandLine, "(?i)user\s+\S+\s+/add") AND NOT match(CommandLine, "(?i)localgroup")), "Suspicious Account Creation",
    (EventCode=1 AND (ProcessName="net.exe" OR ProcessName="net1.exe") AND match(CommandLine, "(?i)localgroup\s+\"(administrators|remote desktop users)\"") AND match(CommandLine, "(?i)/add")), "Suspicious Account Elevation",

    -- TTP 2: Malicious Service Creation for Keylogger/Ransomware
    (EventCode=1 AND ProcessName="sc.exe" AND match(CommandLine, "(?i)create") AND match(CommandLine, "(?i)svchost.exe") AND (match(CommandLine, "(?i)-k WinMainSvc") OR match(CommandLine, "(?i)-k MSRuntime"))), "Malicious Service Creation (Keylogger/Ransomware)",

    -- TTP 3: RealBlindingEDR Evasion Tool
    (EventCode=1 AND ProcessName IN ("AVB.exe", "AVMon.exe", "avb.exe") AND (match(Image, "(?i)AppData\\Local\\Temp\\Low") OR match(Image, "(?i)ProgramData\\update"))), "EDR Evasion Tool Execution (RealBlindingEDR)",
    (EventCode=11 AND (match(TargetFilename, "(?i)AppData\\Local\\Temp\\Low") OR match(TargetFilename, "(?i)ProgramData\\update")) AND (match(TargetFilename, "(?i)\\AVB.exe") OR match(TargetFilename, "(?i)\\AVMon.exe") OR match(TargetFilename, "(?i)\\avb.exe"))), "EDR Evasion Tool Creation (RealBlindingEDR)",

    -- TTP 4: RDP Enabled via Command Line
    (EventCode=1 AND ProcessName="reg.exe" AND match(CommandLine, "(?i)add") AND match(CommandLine, "(?i)fDenyTSConnections") AND match(CommandLine, "(?i)/d\s+0") AND match(CommandLine, "(?i)System\\CurrentControlSet\\Control\\Terminal Server")), "RDP Enabled via Registry",
    (EventCode=1 AND ProcessName="netsh.exe" AND match(CommandLine, "(?i)advfirewall") AND match(CommandLine, "(?i)localport=3389") AND match(CommandLine, "(?i)action=allow")), "RDP Firewall Rule Added",
    (EventCode=1 AND ProcessName IN ("takeown.exe", "icacls.exe") AND match(CommandLine, "(?i)termsrv.dll")), "Termsrv.dll Tampering",

    -- TTP 5: Security Product Uninstaller via GPO
    (EventCode=1 AND ProcessName="gpscript.exe" AND (match(CommandLine, "(?i)XBCUninstaller.exe") OR match(CommandLine, "(?i)VisionOne_removal") OR match(CommandLine, "(?i)uninstaller") OR match(CommandLine, "(?i)remover") OR match(CommandLine, "(?i)removal"))), "Security Product Uninstaller via GPO"
)
| where isnotnull(TTP)
| eval Evidence=case(
    EventCode=11, "File created: " + TargetFilename,
    isnotnull(CommandLine), CommandLine
    )
| table _time, DeviceName, TTP, Evidence, User, ParentProcessName, CommandLine
```