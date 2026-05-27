### HazyBeacon Malware Campaign Targeting Southeast Asian Governments
---

The CL-STA-1020 threat cluster is actively targeting governmental entities in Southeast Asia with a novel Windows backdoor named HazyBeacon. This campaign focuses on covert intelligence gathering, particularly sensitive government data related to tariffs and trade disputes, by leveraging legitimate cloud services for stealthy command and control (C2) and data exfiltration.


The most significant new finding is the use of AWS Lambda URLs for C2 communication, allowing the HazyBeacon backdoor to blend malicious traffic with legitimate AWS services, making detection challenging. This novel approach to C2, combined with DLL sideloading and the use of common cloud storage services for exfiltration, represents an evolving tactic by state-backed actors to evade traditional security measures.

Actionable Threat Data

    Monitor for mscorsvw.exe loading mscorsvc.dll from unusual or non-standard directories, especially outside of %WINDIR%\Microsoft.NET\Framework\ or %WINDIR%\Microsoft.NET\Framework64\.

    Detect the creation of new Windows services, specifically one named "msdnetsvc", which is used for persistence by the HazyBeacon backdoor.

    Look for outbound network connections from mscorsvw.exe or newly created services to AWS Lambda URLs, particularly those with the pattern *.lambda-url.*.on[.]aws.

    Identify and investigate suspicious file creations or modifications within C:\ProgramData for known HazyBeacon payloads such as 7z.exe, igfx.exe, GoogleGet.exe, google.exe, GoogleDrive.exe, GoogleDriveUpload.exe, and Dropbox.exe.

    Monitor for unusual or high-volume data transfers to legitimate cloud storage services like Google Drive and Dropbox from government networks, especially when initiated by newly observed executables or processes.

### AWS Lambda C2
---
```sql
`comment("This detection rule identifies potential C2 traffic associated with the HazyBeacon backdoor by looking for network connections from mscorsvw.exe to AWS Lambda URLs.")`
tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest_host="*.lambda-url.*.on.aws" AND (All_Traffic.process_name="mscorsvw.exe" OR All_Traffic.process_path="*\\mscorsvw.exe") by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_host, All_Traffic.process_name, All_Traffic.user
`comment("The process mscorsvw.exe is part of the .NET Framework and should not typically make direct connections to AWS Lambda URLs. Such activity is highly suspicious and a key indicator of this threat.")`
`comment("False Positive Tuning: If legitimate internal tools use mscorsvw.exe to connect to known Lambda URLs, consider adding them to an allowlist to reduce noise.")`
| rename "All_Traffic.*" as "*"
| convert ctime(firstTime) ctime(lastTime)
| fields firstTime, lastTime, src, dest, dest_host, user, process_name, count
```

### HazyBeacon DLL Sideloading
---
```sql
`comment("Title: HazyBeacon DLL Sideloading via mscorsvc.dll")`
`comment("Description: Detects the loading of mscorsvc.dll by mscorsvw.exe from a non-standard directory. This is a known DLL Sideloading technique used by the HazyBeacon backdoor to achieve execution and persistence.")`
`comment("Date: 2025-07-22")`
`comment("References: https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/")`
`comment("MITRE ATT&CK Tactic: Persistence, Privilege Escalation, Defense Evasion")`
`comment("MITRE ATT&CK Technique: T1574.001 - Hijack Execution Flow: DLL Sideloading")`

`comment("This search leverages the Image_Loads data model to find instances of mscorsvw.exe loading mscorsvc.dll.")`
tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Image_Loads where (Image_Loads.process_name="mscorsvw.exe") AND (Image_Loads.file_name="mscorsvc.dll") AND NOT (Image_Loads.file_path="C:\\Windows\\Microsoft.NET\\Framework\\*" OR Image_Loads.file_path="C:\\Windows\\Microsoft.NET\\Framework64\\*") by Image_Loads.dest, Image_Loads.user, Image_Loads.process_name, Image_Loads.process_path, Image_Loads.file_path
`comment("The core of the detection filters for loads outside of the legitimate .NET Framework directories, which is highly indicative of malicious activity.")`
`comment("False Positive Tuning: Legitimate but unusual software installations might place this DLL in other locations. If such cases are identified, their specific paths can be added to the exclusion list in the 'where' clause to reduce noise.")`
| rename "Image_Loads.*" as "*"
| convert ctime(firstTime) ctime(lastTime)
| fields firstTime, lastTime, dest, user, process_name, process_path, file_path, count
```

### HazyBeacon Persistence Service
---
```sql
`comment("Title: HazyBeacon Persistence Service Creation")`
`comment("Description: Detects the creation of the 'msdnetsvc' Windows service. This specific service name is used by the HazyBeacon backdoor to establish persistence on a compromised host.")`
`comment("Date: 2025-07-22")`
`comment("References: https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/")`
`comment("MITRE ATT&CK Tactic: Persistence")`
`comment("MITRE ATT&CK Technique: T1543.003 - Create or Modify System Process: Windows Service")`

`comment("This search leverages the Processes data model to find command-line activity related to service creation.")`
tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="sc.exe" OR Processes.process_name="sc") AND Processes.process="*create*" AND Processes.process="*msdnetsvc*" by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process, Processes.process_id, Processes.parent_process_id
`comment("The core of the detection filters for the execution of sc.exe with 'create' and the specific service name 'msdnetsvc' in the command line.")`
`comment("False Positive Tuning: The service name 'msdnetsvc' is specific to this threat. False positives are unlikely but could occur if legitimate software coincidentally uses the same name. Review the parent process and user context to validate legitimacy.")`
| rename "Processes.*" as "*"
| convert ctime(firstTime) ctime(lastTime)
| fields firstTime, lastTime, dest, user, parent_process_name, process_name, process, process_id, parent_process_id, count
```

### HazyBeacon Backdoor Hash
---
```sql
`comment("Title: HazyBeacon Backdoor Execution by Hash")`
`comment("Description: Detects the execution of the HazyBeacon backdoor by its known SHA256 hash. This is a high-fidelity indicator of compromise associated with the CL-STA-1020 threat actor.")`
`comment("Date: 2025-07-22")`
`comment("References: https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/")`
`comment("MITRE ATT&CK Tactic: Execution")`
`comment("MITRE ATT&CK Technique: T1204.002 - User Execution: Malicious File")`

`comment("This search uses the Endpoint data model to find processes matching a specific hash.")`
tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.hash="4931df8650521cfd686782919bda0f376475f9fc5f1fee9d7cf3a4e0d9c73e30" by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process, Processes.process_id, Processes.parent_process_id, Processes.hash
`comment("The where clause filters for the specific SHA256 hash of the HazyBeacon backdoor.")`
`comment("False Positive Tuning: This is a static hash-based detection. False positives are extremely unlikely.")`
| rename "Processes.*" as "*"
| convert ctime(firstTime) ctime(lastTime)
| fields firstTime, lastTime, dest, user, parent_process_name, process_name, process, process_id, parent_process_id, hash, count
```

### HazyBeacon Payload Hashes
---
```sql
`comment("Title: HazyBeacon Payload Execution by Hash")`
`comment("Description: Detects the execution of known HazyBeacon payloads (file collectors, uploaders) by their SHA256 hashes. These tools are used for data staging and exfiltration.")`
`comment("Date: 2025-07-22")`
`comment("References: https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/")`
`comment("MITRE ATT&CK Tactic: Collection, Exfiltration")`
`comment("MITRE ATT&CK Technique: T1005 - Data from Local System, T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage")`

`comment("This search uses the Endpoint data model to find processes matching a list of known malicious hashes.")`
tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.hash IN ("d20b536c88ecd326f79d7a9180f41a2e47a40fcf2cc6a2b02d68a081c89eaeaa", "304c615f4a8c2c2b36478b693db767d41be998032252c8159cc22c18a65ab498", "f0c9481513156b0cdd216d6dfb53772839438a2215d9c5b895445f418b64b886", "3255798db8936b5b3ae9fed6292413ce20da48131b27394c844ecec186a1e92f", "279e60e77207444c7ec7421e811048267971b0db42f4b4d3e975c7d0af7f511e", "d961aca6c2899cc1495c0e64a29b85aa226f40cf9d42dadc291c4f601d6e27c3") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process, Processes.process_id, Processes.parent_process_id, Processes.hash
`comment("The where clause filters for the specific SHA256 hashes of the HazyBeacon payloads.")`
`comment("False Positive Tuning: This is a static hash-based detection. False positives are extremely unlikely. If a hash collision is ever discovered, the specific hash can be removed from the list.")`
| rename "Processes.*" as "*"
| convert ctime(firstTime) ctime(lastTime)
| fields firstTime, lastTime, dest, user, parent_process_name, process_name, process, process_id, parent_process_id, hash, count
```

### Exfiltration to Cloud Storage
---
```sql
`comment("Title: High Volume Data Exfiltration to Cloud Storage")`
`comment("Description: Detects potentially anomalous high-volume data uploads to common cloud storage services (Google Drive, Dropbox) from non-standard processes. This behavior can be indicative of data exfiltration using custom or renamed tools, as seen in the HazyBeacon campaign.")`
`comment("Date: 2025-07-22")`
`comment("References: https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/")`
`comment("MITRE ATT&CK Tactic: Exfiltration")`
`comment("MITRE ATT&CK Technique: T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage")`

`comment("This search uses the Network_Traffic data model to identify large data uploads to known cloud storage providers.")`
tstats summariesonly=true sum(All_Traffic.bytes_out) as total_bytes_out from datamodel=Network_Traffic where All_Traffic.dest_host IN ("*drive.google.com", "*.googleapis.com", "*dropbox.com", "*.dropboxapi.com") AND All_Traffic.process_name!="" by All_Traffic.src, All_Traffic.user, All_Traffic.process_name, All_Traffic.dest_host
`comment("The core of the detection filters for traffic to known cloud storage domains and aggregates the total bytes sent by process.")`
| `comment("Filter out common browsers and legitimate sync clients to reduce noise. This list may need to be customized for your environment.")`
| search NOT (process_name IN ("chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "Dropbox.exe", "GoogleDriveFS.exe", "rclone.exe"))
`comment("The threshold below is set to 100MB. Adjust this value based on your organization's baseline network activity to tune for sensitivity.")`
| where total_bytes_out > 104857600
| eval total_MB_out = round(total_bytes_out/1024/1024, 2)
| rename "All_Traffic.*" as "*"
| fields src, user, process_name, dest_host, total_MB_out
| sort - total_MB_out
```