### UAC-0057 Activity Targeting Ukraine and Poland
---

UAC-0057, also known as UNC1151, FrostyNeighbor, or Ghostwriter, is a cyber espionage actor with reported ties to the Belarusian government. This group has been actively targeting organizations and individuals in Ukraine and Poland since at least April 2025, utilizing malicious archives containing weaponized XLS spreadsheets to collect system information and deploy further implants.

Recent activity shows UAC-0057 has evolved its toolset by incorporating Slack for some command and control (C2) communications and transitioning to new top-level domains like .icu and .online for its infrastructure, indicating an adaptation to evade detection. Additionally, some campaigns have been observed delivering Cobalt Strike Beacons as a final payload, expanding their post-exploitation capabilities.

### Actionable Threat Data
---

Initial Access & Execution: UAC-0057 consistently uses spearphishing emails with malicious XLS spreadsheets containing VBA macros, often obfuscated with MacroPack, to drop and load DLLs.

        Monitor for the creation of .lnk files in %APPDATA%\Microsoft\Windows\ that execute regsvr32.exe or expand.exe to load DLLs from temporary or program data directories.

        Look for rundll32.exe executing DLLs with specific export functions, such as TS_STATUS_INFO_get0_status or #1.

Persistence: The threat actor establishes persistence through various methods, including adding entries to the HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ registry key and creating scheduled tasks.

        Alert on new or modified registry entries under HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ that point to unusual file paths or DLLs.

        Monitor for the creation of new scheduled tasks that execute DLLs or other suspicious binaries at user logon.

Defense Evasion: UAC-0057 employs obfuscation techniques like ConfuserEx for their C# and C++ DLL implants and utilizes legitimate services like Slack for C2 communication.

        Analyze network traffic for connections to Slack webhook URLs (hooks.slack.com/services/) from non-Slack applications or unusual processes.

        Implement YARA rules to identify ConfuserEx obfuscated .NET assemblies and UPX packed executables.
Command and Control: The group uses C2 domains that impersonate legitimate websites and often serve image files, with the actual payload appended or embedded. They also use hxxps://ip-info.ff.avast[.]com/v1/info for external IP address discovery.

        Monitor network connections to newly registered .icu and .online domains, especially those mimicking legitimate brands.

        Look for HTTP POST requests with unusual User-Agent strings (e.g., Mozilla/5.0 (iPhone; CPU iPhone OS 18_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/133.0.6943.84 Mobile/15E148 Safari/604.1) to image file extensions (.jpg, .gif, etc.) on C2 domains.

System Information Discovery: Implants collect extensive system information, including OS details, hostname, CPU name, username, install dates, and antivirus product names.

        Alert on processes making WMI queries for system information (e.g., Win32_OperatingSystem, Win32_Processor, Win32_Product, Win32_ComputerSystemProduct) followed by outbound network connections to suspicious domains.

### Combined Analysis Search
---
```sql
-- Name: UAC-0057 (Ghostwriter) Activity
-- Description: This rule detects various TTPs and IOCs associated with UAC-0057 (aka Ghostwriter, UNC1151) campaigns targeting Ukraine and Poland.
-- It covers suspicious file creation, persistence mechanisms, command execution, and network C2 patterns.
-- Data sources: Sysmon (Event IDs 1, 3, 11, 13), Proxy/Firewall logs
-- False Positive Sensitivity: Medium. Some network patterns, like connections to Slack, may require tuning based on your environment's baseline activity.
-- Author: RW

name: UAC-0057 Ghostwriter Activity
type: signal_correlation
cases:
  - name: File Creation by Hash
    status: high
    query: "@event_type:file AND @file.hash:(f6fec3722a8c98c29c5de10969b8f70962dbb47ba53dcbcd4a3bbc63996d258d OR deaa3f807de097c3bfff37a41e97af5091b2df0e3a6d01a11a206732f9c6e49c OR aac430127c438224ec61a6c02ea59eb3308eb54297daac985a7b26a75485e55f OR 06380c593d122fc4987e9d4559a9573a74803455809e89dd04d476870a427cbe OR 082877e6f8b28f6cf96d3498067b0c404351847444ebc9b886054f96d85d55d4 OR 082903a8bec2b0ef7c7df3e75871e70c996edcca70802d100c7f68414811c804 OR 69636ddc0b263c93f10b00000c230434febbd49ecdddf5af6448449ea3a85175 OR a2a2f0281eed6ec758130d2f2b2b5d4f578ac90605f7e16a07428316c9f6424e OR 8a057d88a391a89489697634580e43dbb14ef8ab1720cb9971acc418b1a43564 OR 707a24070bd99ba545a4b8bab6a056500763a1ce7289305654eaa3132c7cbd36 OR 5fa19aa32776b6ab45a99a851746fbe189f7a668daf82f3965225c1a2f8b9d36 OR 3b5980c758bd61abaa4422692620104a81eefbf151361a1d8afe8e89bf38579d OR c7e44bba26c9a57d8d0fa64a140d58f89d42fd95638b8e09bc0d2020424b640e OR 7c77d1ba7046a4b47aec8ec0f2a5f55c73073a026793ca986af22bbf38dc948c OR 559ee2fad8d16ecaa7be398022aa7aa1adbd8f8f882a34d934be9f90f6dcb90b)"
  - name: File Creation by Path
    status: medium
    query: "@event_type:file AND @file.path:(*\\Temp\\DefenderProtectionScope.log OR *\\Microsoft\\System\\ProtectedCertSystem.dll OR *\\Serv\\0x00bac729fe.log OR *\\Microsoft\\Windows\\Protection\\ overview.lnk OR *\\Temp\\sdw9gobh0n OR *\\Microsoft\\Windows\\Protection\\ overview\\ past.lnk OR *\\Logs\\sdw9gobh0n.log OR *\\SDXHelp\\SDXHelp.dll OR *\\Runtime\\RuntimeBroker.dll OR *\\MSDE\\mrasp86.dll OR *\\DiagnosticComponents\\DiagnosticComponents.dll OR *\\ProgramData\\OfficeRuntimeBroker.xlam OR *\\ProgramData\\OfficeRuntimeBroker.lnk OR *\\ProgramData\\~OfficeRuntimeBroker.dat OR *\\ProgramData\\ssh\\ssh.pif.pif.pif OR *\\ProgramData\\~DF20BC61C6277A354A.dat)"
  - name: Persistence via Run Key
    status: medium
    query: "@event_type:registry AND @registry.path:*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run AND @registry.value_data:(SytemProtectionService OR MicrosoftDefender OR SytemProtectService OR \"Audio Driver\")"
  - name: Suspicious Rundll32 Execution
    status: high
    query: "@event_type:process AND @process.name:rundll32.exe AND (@process.cmdline:*,#1 OR @process.cmdline:*,TS_STATUS_INFO_get0_status OR @process.cmdline:*shell32.dll,ShellExec_RunDLL)"
  - name: Suspicious Expand.exe Execution
    status: high
    query: "@event_type:process AND @process.parent_name:excel.exe AND @process.name:expand.exe AND @process.cmdline:*.xlam AND @process.cmdline:*.dat AND @process.cmdline:*ProgramData*"
  - name: Network C2 Domain IOC
    status: high
    query: "@event_type:(network OR dns) AND (@network.destination.domain:(sweetgeorgiayarns.online OR kitchengardenseeds.icu OR punandjokes.icu OR taskandpurpose.icu OR medpagetoday.icu OR pesthacks.icu OR curseforge.icu) OR @dns.query:(sweetgeorgiayarns.online OR kitchengardenseeds.icu OR punandjokes.icu OR taskandpurpose.icu OR medpagetoday.icu OR pesthacks.icu OR curseforge.icu))"
  - name: Network C2 User-Agent IOC
    status: high
    query: "@event_type:network AND @http.user_agent:(\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36\" OR \"Mozilla/5.0 (iPhone; CPU iPhone OS 18_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/133.0.6943.84 Mobile/15E148 Safari/604.1\") AND @network.destination.domain:(sweetgeorgiayarns.online OR kitchengardenseeds.icu OR punandjokes.icu OR taskandpurpose.icu OR medpagetoday.icu OR pesthacks.icu OR curseforge.icu)"
  - name: Network C2 via Slack Webhook
    status: high
    query: "@event_type:network AND @url:*hooks.slack.com/services/* -@process.name:(slack.exe OR chrome.exe OR firefox.exe OR msedge.exe OR iexplore.exe)"
signal_correlation:
  rule_id: uac0057_correlation
  group_by_fields:
    - @host
    - @usr
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "UAC-0057 Activity: {distinct_count} detection(s) on host {@host} by user {@usr}: {case_names}"
severity: high
```