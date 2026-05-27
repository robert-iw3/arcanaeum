### North Korean XORIndex Malware Campaign
---

North Korean threat actors are actively distributing a new malware loader, XORIndex, via 67 malicious npm packages as part of the ongoing "Contagious Interview" operation. This campaign primarily targets developers by leveraging malicious npm packages that execute a postinstall script to deploy the XORIndex loader, ultimately leading to the delivery of BeaverTail and InvisibleFerret backdoors for data exfiltration and system control.


The introduction of XORIndex Loader, alongside the continued use of HexEval Loader, demonstrates the threat actors' commitment to diversifying their malware portfolio and employing enhanced obfuscation techniques like XOR-encoded strings and multi-endpoint C2 rotation to evade detection. This evolution signifies a more sophisticated and resilient approach to software supply chain attacks, making detection more challenging.

Actionable Threat Data

    Monitor for the execution of postinstall scripts in npm packages, especially those from newly installed or less reputable sources, as this is the initial execution vector for XORIndex.

    Implement network detections for connections to Vercel infrastructure from developer machines, specifically looking for unusual or unauthorized communication patterns to /api/ipcheck paths, which are used for C2 communication by XORIndex.

    Look for the presence and execution of JavaScript payloads using eval() after npm package installations, as this is a common technique used by XORIndex to execute subsequent stages of the attack, including BeaverTail and InvisibleFerret.

    Create detections for the creation or modification of files related to cryptocurrency wallet directories and browser extension paths, as BeaverTail actively scans and exfiltrates data from these locations.

    Monitor for the download and execution of Python scripts or the Python interpreter itself in unexpected contexts, as InvisibleFerret is a Python-based backdoor often downloaded and executed by BeaverTail.

### Suspicious Process Spawned by NPM Post-Installation
---
```sql
# Date: 2025-07-22
# References:
# - https://www.bleepingcomputer.com/news/security/north-korean-xorindex-malware-hidden-in-67-malicious-npm-packages/
#
# Description:
# Detects the Node Package Manager (npm) spawning suspicious child processes like shells,
# downloaders, or scripting engines. This behavior is indicative of a malicious
# 'postinstall' script being executed after an npm package installation, a technique
# used by threat actors to deliver malware like the XORIndex loader.
#
# Data Source:
# This rule is designed for process execution logs that are compliant with the Splunk
# Common Information Model (CIM), typically from sources like Sysmon (Event ID 1),
# CrowdStrike, Carbon Black, or OS native logs.
#
# False Positives:
# Legitimate npm packages may use 'postinstall' scripts that call shells (sh, bash)
# or python for build processes or other setup tasks. These instances should be
# investigated and can be added to an allow-list if they are confirmed to be benign
# within your environment.
#
# Tuning:
# The list of suspicious child processes can be tuned. For example, if your developers
# frequently use python scripts during package installation, you might consider removing
# 'python.exe' to reduce noise, or add more specific command-line filtering.
#
`comment("Search for process creation events from the Endpoint data model for efficiency.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process_cmd values(Processes.parent_process) as parent_process_cmd from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("npm.exe", "npm")) AND (Processes.process_name IN ("powershell.exe", "pwsh.exe", "cmd.exe", "sh", "bash", "zsh", "curl.exe", "wget.exe", "python.exe", "python3.exe")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
`comment("Rename fields for clarity and consistency.")`
| rename Processes.* as *
`comment("Format timestamps for readability.")`
| fieldformat firstTime = strftime(firstTime, "%Y-%m-%d %H:%M:%S")
| fieldformat lastTime = strftime(lastTime, "%Y-%m-%d %H:%M:%S")
`comment("Provide a summary of the detected activity.")`
| table firstTime, lastTime, dest, user, parent_process_name, parent_process_cmd, process_name, process_cmd, count
```

### XORIndex C2 Communication via Vercel
---
```sql
# Date: 2025-07-22
# References:
# - https://www.bleepingcomputer.com/news/security/north-korean-xorindex-malware-hidden-in-67-malicious-npm-packages/
#
# Description:
# Detects network traffic to Vercel-hosted infrastructure specifically targeting the '/api/ipcheck' path.
# This pattern is a known indicator of command-and-control (C2) activity for the XORIndex malware loader,
# which is distributed via malicious npm packages.
#
# Data Source:
# This rule is designed for network traffic logs that are compliant with the Splunk
# Common Information Model (CIM), such as from firewalls, proxies, or Zeek.
#
# False Positives:
# Legitimate applications hosted on Vercel might use an '/api/ipcheck' endpoint for benign
# purposes. Investigate the source process and application making the request. If benign,
# consider excluding the specific source host or application from this alert.
#
# Tuning:
# To reduce noise, you can filter for specific source IP ranges (e.g., developer subnets)
# or exclude known legitimate applications that communicate with Vercel.
#
`comment("Search network traffic logs from the Network_Traffic data model for efficiency.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.url_path="/api/ipcheck" AND All_Traffic.dest_host="*.vercel.app") by All_Traffic.src All_Traffic.dest_host All_Traffic.url All_Traffic.user
`comment("Rename fields for clarity.")`
| rename All_Traffic.* as *
`comment("Filter out events where the source and destination are the same.")`
| where src!=dest_host
`comment("Format timestamps for readability.")`
| fieldformat firstTime = strftime(firstTime, "%Y-%m-%d %H:%M:%S")
| fieldformat lastTime = strftime(lastTime, "%Y-%m-%d %H:%M:%S")
`comment("Provide a summary of the detected C2 activity.")`
| table firstTime, lastTime, src, user, dest_host, url, count
```

### Suspicious JavaScript eval() Execution by Node.js
---
```sql
# Date: 2025-07-22
# References:
# - https://www.bleepingcomputer.com/news/security/north-korean-xorindex-malware-hidden-in-67-malicious-npm-packages/
#
# Description:
# Detects the Node.js process (node.exe) executing a command line that includes the 'eval()' function.
# This is a known TTP for malware like XORIndex, which is delivered via malicious npm packages.
# The malware uses 'eval()' within post-installation scripts to execute downloaded payloads like
# the BeaverTail and InvisibleFerret backdoors. This rule looks for node.exe processes spawned by
# common package manager or shell processes.
#
# Data Source:
# This rule is designed for process execution logs that are compliant with the Splunk
# Common Information Model (CIM), typically from sources like Sysmon (Event ID 1),
# CrowdStrike, Carbon Black, or OS native logs.
#
# False Positives:
# Legitimate development tools, code bundlers (e.g., Webpack in development mode), or custom build
# scripts may use 'eval()' for dynamic code execution. Investigate the full command line and the
# parent process context. If benign, consider excluding the specific script path or parent process.
#
# Tuning:
# To reduce noise, you can create an allow-list for parent processes or specific, known-good
# command lines that legitimately use 'eval()' in your environment.
#
`comment("Search for node.js processes executing a command containing 'eval()'.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process_cmd from datamodel=Endpoint.Processes where (Processes.process_name="node.exe" AND Processes.process="*eval(*") by Processes.dest Processes.user Processes.parent_process_name
`comment("Rename fields for clarity.")`
| rename Processes.* as *
`comment("Filter for parent processes commonly associated with package installation scripts to increase fidelity.")`
| where parent_process_name IN ("npm.exe", "npm", "cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "zsh")
`comment("Format timestamps for readability.")`
| fieldformat firstTime = strftime(firstTime, "%Y-%m-%d %H:%M:%S")
| fieldformat lastTime = strftime(lastTime, "%Y-%m-%d %H:%M:%S")
`comment("Provide a summary of the detected activity.")`
| table firstTime, lastTime, dest, user, parent_process_name, process_cmd, count
```

### BeaverTail Data Exfiltration
---
```sql
# Date: 2025-07-22
# References:
# - https://www.bleepingcomputer.com/news/security/north-korean-xorindex-malware-hidden-in-67-malicious-npm-packages/
#
# Description:
# Detects non-browser processes accessing sensitive user data locations, such as cryptocurrency
# wallet files and browser extension storage directories. This behavior is a key indicator
# of information-stealing malware like BeaverTail, which aims to exfiltrate credentials,
# session tokens, and cryptocurrency.
#
# Data Source:
# This rule is designed for file system monitoring logs that are compliant with the Splunk
# Common Information Model (CIM), typically from sources like Sysmon (Event ID 11),
# CrowdStrike, Carbon Black, or other EDRs.
#
# False Positives:
# Legitimate applications like backup utilities, cloud synchronization clients (e.g., OneDrive, Dropbox),
# or other security agents may access these file paths. Investigate the process performing the
# action. If benign, add the process name to the exclusion list.
#
# Tuning:
# The list of excluded processes is critical for tuning. Add any legitimate applications
# in your environment that are expected to access these paths to the `process_name` IN (...) clause.
#
`comment("Search for file system events in sensitive user directories.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.action) as action from datamodel=Endpoint.Filesystem where (
    `comment("Define paths for common cryptocurrency wallets and browser extension data.")`
    (Filesystem.file_path IN (
        "*\\AppData\\Roaming\\*wallet*",
        "*\\AppData\\Roaming\\Electrum\\*",
        "*\\AppData\\Roaming\\Exodus\\*",
        "*\\AppData\\Roaming\\Bitcoin\\*",
        "*\\AppData\\Roaming\\MetaMask\\*",
        "*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Local Extension Settings\\*",
        "*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Sync Extension Settings\\*",
        "*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\storage.js",
        "*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\browser-extension-data\\*",
        "*\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\Local Extension Settings\\*"
    ))
    `comment("Exclude common browsers and sync clients to reduce false positives.")`
    AND NOT (Filesystem.process_name IN ("chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe", "explorer.exe", "OneDrive.exe", "Dropbox.exe"))
) by Filesystem.dest Filesystem.user Filesystem.process_name
`comment("Rename fields for clarity.")`
| rename Filesystem.* as *
`comment("Format timestamps for readability.")`
| fieldformat firstTime = strftime(firstTime, "%Y-%m-%d %H:%M:%S")
| fieldformat lastTime = strftime(lastTime, "%Y-%m-%d %H:%M:%S")
`comment("Provide a summary of the detected activity.")`
| table firstTime, lastTime, dest, user, process_name, file_path, action, count
```

### InvisibleFerret Python Execution
---
```sql
# Date: 2025-07-22
# References:
# - https://www.bleepingcomputer.com/news/security/north-korean-xorindex-malware-hidden-in-67-malicious-npm-packages/
#
# Description:
# Detects the Python interpreter being launched by a non-standard parent process, such as Node.js,
# a web browser, or a Microsoft Office application. This behavior is highly anomalous and can
# indicate that a primary implant or exploit is executing a Python-based backdoor like InvisibleFerret
# as a secondary payload.
#
# Data Source:
# This rule is designed for process execution logs that are compliant with the Splunk
# Common Information Model (CIM), typically from sources like Sysmon (Event ID 1),
# CrowdStrike, Carbon Black, or other EDRs.
#
# False Positives:
# While uncommon, some legitimate applications or development workflows might involve a Node.js
# application spawning a Python script. Investigate the parent process and the executed
# Python command. If the activity is benign, consider adding the parent process to an exclusion list.
#
# Tuning:
# The list of suspicious parent processes can be expanded or reduced based on your environment.
# For example, if a specific internal tool legitimately spawns Python, it should be excluded.
#
`comment("Search for Python processes using the Endpoint data model.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process_cmd from datamodel=Endpoint.Processes where (
    (Processes.process_name IN ("python.exe", "python3.exe"))
    `comment("Filter for parent processes that do not typically launch Python, such as those related to the XORIndex attack chain, browsers, or Office apps.")`
    AND (Processes.parent_process_name IN (
        "node.exe", "npm.exe", "wscript.exe", "cscript.exe",
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "chrome.exe", "firefox.exe", "msedge.exe"
    ))
) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
`comment("Rename fields for clarity.")`
| rename Processes.* as *
`comment("Format timestamps for readability.")`
| fieldformat firstTime = strftime(firstTime, "%Y-%m-%d %H:%M:%S")
| fieldformat lastTime = strftime(lastTime, "%Y-%m-%d %H:%M:%S")
`comment("Provide a summary of the detected activity.")`
| table firstTime, lastTime, dest, user, parent_process_name, process_name, process_cmd, count
```