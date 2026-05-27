### Venom Spider's Evolving More_eggs Campaign Targeting HR
---

The financially motivated threat group Venom Spider (also known as TA4557 or Golden Chickens) is actively targeting corporate Human Resources departments with spear-phishing emails containing fake resumes. These campaigns leverage server-side polymorphism and legitimate Windows utilities to deliver and execute the More_eggs backdoor, enabling a wide range of malicious activities from credential theft to data exfiltration.


Recent intelligence indicates Venom Spider continues to refine its tactics, including using benign initial emails to build trust before delivering malicious links and leveraging LinkedIn for distribution, making it harder for automated defenses to detect the threat. Additionally, More_eggs has been observed to perform more extensive system awareness checks, including querying notepad.exe version, network adapter IP addresses, running processes, and default startup configurations, alongside performance monitoring via typeperf.exe for evasion.

### Actionable Threat Data
---

Monitor for the creation of .lnk files in suspicious locations (e.g., `C:\Users\%username%\AppData\Local\Temp\`) that execute `cmd.exe` or `powershell.exe` with obfuscated commands.

Detect the execution of `ie4uinit.exe` from non-standard directories (e.g., `%temp%`) or with unusual arguments, as this legitimate utility is abused to execute malicious .inf files.

Look for the presence and execution of `msxsl.exe` in user-specific AppData directories (e.g., `C:\Users\%username%\AppData\Roaming\Adobe\`) or with command-line arguments indicating remote XSL file execution, as it's used to run JavaScript payloads.

Identify network connections to newly observed or suspicious domains and IP addresses, particularly those associated with dynamic DNS services or cloud hosting providers, which may indicate More_eggs command-and-control activity.

Implement detections for the creation of files with random names and specific extensions (e.g., .dll, .txt) in `C:\Users\%username%\AppData\Roaming\Adobe\` and their subsequent execution via `regsvr32.exe`.

### Suspicious LNK File Execution
---
```sql
`comment("This search identifies suspicious execution of cmd.exe or powershell.exe, which may be launched from a malicious LNK file. This technique is used by threat actors like Venom Spider to execute obfuscated commands as part of the More_eggs backdoor delivery, as described in the provided intelligence.")`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="cmd.exe" OR Processes.process_name="powershell.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`

`comment("Filter for command prompt or powershell, common interpreters for malicious scripts embedded in LNK files.")`
| where (process_name="cmd.exe" OR process_name="powershell.exe")

`comment("A common parent for user-clicked LNK files is explorer.exe.")`
| where parent_process_name="explorer.exe"

`comment("Malicious LNK files often contain long, embedded scripts. A command length over 1024 characters is highly suspicious.")`
| where len(process) > 1024

`comment("Calculate the frequency of characters often used for obfuscation in batch scripts to evade detection.")`
| eval obfuscation_chars_count = (mvcount(split(process, "%")) - 1) + (mvcount(split(process, "^")) - 1) + (mvcount(split(process, "&")) - 1)

`comment("Filter for command lines that are both long and have a high number of obfuscation characters. This combination is a strong indicator of a malicious script. FP Note: Some legitimate but complex scripts or installers might trigger this detection. Review the 'process' field to understand the command's purpose. If legitimate processes are caught, consider adding them to a filter list or adjusting the 'len(process)' and 'obfuscation_chars_count' thresholds.")`
| where obfuscation_chars_count > 50

`comment("Group and format the results for alerting.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, parent_process_name, process_name, process, obfuscation_chars_count
| `suspicious_lnk_file_execution_filter`
```

### Abuse of ie4uinit.exe
---
```sql
`comment("This search detects the potential abuse of the legitimate Windows binary ie4uinit.exe, a technique used by threat actors like Venom Spider to execute malicious code via .inf files.")`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="ie4uinit.exe" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`

`comment("Filter for ie4uinit.exe being launched by suspicious parent processes. Legitimate execution is typically parented by userinit.exe or svchost.exe. FP Note: While uncommon, some legitimate software installers or scripts may launch ie4uinit.exe. Review the parent process command line and user context to determine if the activity is benign.")`
| where parent_process_name IN ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")

`comment("Format the results for alerting.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, parent_process_name, process_name, process
| `abuse_of_ie4uinit_exe_filter`
```

### Abuse of msxsl.exe
---
```sql
`comment("This search detects the potential abuse of msxsl.exe, a legitimate Microsoft utility for processing XSL files. Threat actors like Venom Spider use this tool to execute malicious JavaScript payloads, as detailed in the provided intelligence.")`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="msxsl.exe" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path Processes.process
| `drop_dm_object_name(Processes)`

`comment("Filter for msxsl.exe being executed from the AppData\\Roaming\\Adobe directory, which is the specific location where the More_eggs dropper places it. This is a highly anomalous path for this binary.")`
| where match(process_path, /(?i)C:\\Users\\[^\\]+\\AppData\\Roaming\\Adobe\\msxsl.exe$/)

`comment("Additionally, filter for command lines that reference .txt files. The malware uses .txt files to store and launch its JavaScript payload, whereas legitimate msxsl.exe usage typically involves .xml and .xsl files. FP Note: While unlikely, custom scripts might use .txt files with msxsl.exe. Review the full command line and user context to confirm maliciousness.")`
| where like(process, "%.txt%")

`comment("Format the results for alerting.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, parent_process_name, process_name, process_path, process
| `abuse_of_msxsl_exe_filter`
```

### More_eggs C2 Communication
---
```sql
`comment("This search detects potential C2 communication associated with the More_eggs backdoor by looking for network traffic to suspicious or newly observed domains, a TTP used by Venom Spider.")`
| tstats `security_content_summariesonly` values(All_Traffic.url) as url min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (All_Traffic.dest_port=80 OR All_Traffic.dest_port=443) by All_Traffic.src All_Traffic.dest
| `drop_dm_object_name("All_Traffic")`

`comment("Filter out common domains using a lookup to focus on potentially malicious, newly observed, or DGA domains. Note: This lookup (local_traffic_dest_allowlist) must be maintained.")`
| lookup local_traffic_dest_allowlist dest as dest OUTPUT is_allowlisted
| where is_allowlisted!="true"

`comment("Identify specific patterns associated with More_eggs C2, such as the URL path structure or connections to dynamic DNS providers. FP Note: Legitimate services may use DDNS. If false positives occur, consider tuning the list of DDNS providers or adding specific legitimate DDNS domains to the allowlist.")`
| where (match(url, /(?i)\/id\/\d+$/) OR match(dest, /(?i)(\.ddns\.net|\.no-ip\.com|\.duckdns\.org|\.hopto\.org|\.dynv6\.net)$/))

`comment("Format the results for alerting.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, src, dest, url
| `more_eggs_c2_communication_filter`
```

### More_eggs Dropper File Creation
---
```sql
`comment("This search detects the creation and execution of a malicious DLL consistent with the More_eggs dropper. This TTP is used by the Venom Spider threat group, as detailed in the provided intelligence.")`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="regsvr32.exe" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`

`comment("Filter for regsvr32.exe, the utility used by the malware to execute its payload.")`
| where process_name="regsvr32.exe"

`comment("Look for command-line arguments that match the specific pattern used by the More_eggs dropper. This includes execution from the user's Adobe AppData folder, a highly anomalous location for a DLL to be registered from. FP Note: While highly specific, a legitimate but poorly designed application could potentially match this pattern. Review the parent process and user context to confirm malicious activity.")`
| where match(process, /(?i)C:\\Users\\[^\\]+\\AppData\\Roaming\\Adobe\\/)

`comment("Further refine by looking for the specific filename pattern 'd{5}.dll' (a 'd' followed by five digits) and silent execution flags, which are strong indicators of the More_eggs dropper.")`
| where match(process, /(?i)(\/s|\/i:).+d\d{5}\.dll/)

`comment("Format the results for alerting.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, parent_process_name, process_name, process
| `more_eggs_dropper_file_creation_filter`
```

### More_eggs Dropper Hash
---
```sql
`comment("This search detects the execution of a process matching the known SHA-256 hash of the More_eggs dropper, as identified in the provided intelligence from Arctic Wolf. Detection of this hash is a high-fidelity indicator of compromise.")`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash_sha256="f7a405795f11421f0996be0d0a12da743cc5aaf65f79e0b063be6965c8fb8016" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_hash_sha256
| `drop_dm_object_name(Processes)`

`comment("Format the results for alerting.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, parent_process_name, process_name, process, process_hash_sha256
| `more_eggs_dropper_hash_filter`
```

### More_eggs C2 Domain
---
```sql
`comment("This search detects network traffic to the known More_eggs C2 domain tool.municipiodechepo.org, as identified in the Arctic Wolf intelligence. Detecting this traffic is a high-fidelity indicator of a compromised host communicating with the threat actor's infrastructure.")`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="tool.municipiodechepo.org" OR All_Traffic.url="*tool.municipiodechepo.org*") by All_Traffic.src, All_Traffic.dest, All_Traffic.user, All_Traffic.url
| `drop_dm_object_name("All_Traffic")`

`comment("Format the results for alerting.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, src, dest, user, url
| `more_eggs_c2_domain_filter`
```

### More_eggs Phishing Domain
---
```sql
`comment("This search detects network traffic to known phishing domains used by Venom Spider to deliver the More_eggs backdoor, as identified in the Arctic Wolf intelligence. Detecting this traffic is a high-fidelity indicator of a user clicking on a malicious link from the phishing campaign.")`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("doefstf.ryanberardi.com", "dtde.ryanberardi.com") OR All_Traffic.url IN ("*doefstf.ryanberardi.com*", "*dtde.ryanberardi.com*")) by All_Traffic.src, All_Traffic.dest, All_Traffic.user, All_Traffic.url
| `drop_dm_object_name("All_Traffic")`

`comment("Format the results for alerting.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, src, dest, user, url
| `more_eggs_phishing_domain_filter`
```
