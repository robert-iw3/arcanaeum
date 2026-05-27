### AI Model Security Report
---

This report details the critical vulnerabilities in AI model scanning, particularly focusing on the limitations of static analysis and the emerging threats in the AI supply chain. It highlights how malicious actors can bypass current detection mechanisms by exploiting serialization formats and custom model architectures, emphasizing the need for dynamic analysis and robust security measures.

Recent intelligence indicates a significant increase in AI supply chain attacks, with threat actors actively weaponizing open-source AI models and libraries, particularly those distributed through platforms like Hugging Face. This evolution goes beyond traditional software supply chain risks, introducing novel attack vectors such as model poisoning and the exploitation of deserialization vulnerabilities in widely used AI frameworks like PyTorch and TensorFlow.

### Actionable Threat Data
---

Monitor for suspicious activity during AI model loading and inference: Malicious AI models can execute arbitrary code or perform unexpected system calls during loading or inference. Implement monitoring for process creation (e.g., os.system, subprocess.Popen), network connections, and file system modifications initiated by AI model processes.

Implement dynamic analysis in a sandboxed environment for all third-party AI models: Static scanners are insufficient to detect sophisticated bypass techniques. Utilize sandboxing to observe the actual behavior of AI models during execution, identifying anomalous activities such as unauthorized code execution, process manipulation, or network communication.

Scrutinize AI model serialization formats for embedded malicious code: Formats like Pickle, Joblib, and even SafeTensors (under specific conditions) can be exploited to embed and execute arbitrary Python code. Prioritize scanning and validation of these formats for unusual imports or structures that could indicate malicious payloads.

Validate the integrity and provenance of all AI model components: Attackers are poisoning training data and injecting malicious code into open-source repositories. Establish a robust supply chain security framework that includes cryptographic signing, versioning, and thorough auditing of all model artifacts and their dependencies.

Be aware of vulnerabilities in popular AI frameworks and libraries: Regularly update and patch AI frameworks like PyTorch (e.g., CVE-2025-32434, CVE-2024-5480), TensorFlow (e.g., CVE-2023-33976, CVE-2024-3660), MLflow (e.g., CVE-2023-6018, CVE-2024-2928), and Joblib (e.g., CVE-2024-34997) as new vulnerabilities are discovered and disclosed.

### Suspicious Process Spawned by AI/ML Model Loading
---

Detects when a Python process, after loading a common AI/ML model file, spawns a command-line interpreter.
This behavior is suspicious as model loading and inference should typically not require executing arbitrary system commands.
This pattern can indicate a malicious model file designed for code execution, as discussed in the "Smashing Model Scanners" research.

### Splunk
---
```sql
-- author: RW
-- date: 2025-08-14
-- tags:
--   - AI/ML Supply Chain Attacks
--   asset_type: Endpoint
--   confidence: 60
--   impact: 80
--   mitre_attack_id:
--     - T1203
--     - T1059

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe", "python3.exe", "pythonw.exe")) AND (Processes.process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "zsh", "csh", "tcsh", "ksh", "dash", "tclsh")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
-- Filter for parent command line containing a model file extension. This provides the AI/ML context.
| where like(parent_process, "%.pkl") OR like(parent_process, "%.pickle") OR like(parent_process, "%.joblib") OR like(parent_process, "%.bin") OR like(parent_process, "%.pt") OR like(parent_process, "%.pth") OR like(parent_process, "%.h5") OR like(parent_process, "%.keras") OR like(parent_process, "%.onnx") OR like(parent_process, "%.model") OR like(parent_process, "%.sav") OR like(parent_process, "%.ckpt") OR like(parent_process, "%.safetensors")
-- Potential for False Positives: Some legitimate ML/automation scripts might call shell commands.
-- Consider excluding known-good scripts or parent processes if they generate noise.
-- For example: | where NOT (like(parent_process, "%legitimate_script.py%"))
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| rename dest as host
| table firstTime, lastTime, host, user, parent_process_name, parent_process, process_name, process, count
```

### Crowdstrike
---
```sql
event_platform=Win event_simpleName=ProcessRollup2 ParentBaseFileName IN ("python.exe","python3.exe","pythonw.exe") FileName IN ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","zsh","csh","tcsh","ksh","dash","tclsh") CommandLine IN (".pkl&quot;,&quot;.pickle&quot;,&quot;.joblib&quot;,&quot;.bin&quot;,&quot;.pt&quot;,&quot;.pth&quot;,&quot;.h5&quot;,&quot;.keras&quot;,&quot;.onnx&quot;,&quot;.model&quot;,&quot;.sav&quot;,&quot;.ckpt","*.safetensors")
| group by aid, ContextTimeStamp, TargetProcessId, ParentBaseFileName, CommandLine, FileName, UserName
| aggregate firstTime=min(ContextTimeStamp), lastTime=max(ContextTimeStamp), count=count(TargetProcessId) by aid, UserName, ParentBaseFileName, CommandLine, FileName
| project firstTime, lastTime, aid as host, UserName as user, ParentBaseFileName as parent_process_name, CommandLine as parent_process, FileName as process_name, CommandLine as process, count
```

### Datadog
---
```sql
processes.parent.name:("python.exe" OR "python3.exe" OR "pythonw.exe") processes.name:("cmd.exe" OR "powershell.exe" OR "pwsh.exe" OR "sh" OR "bash" OR "zsh" OR "csh" OR "tcsh" OR "ksh" OR "dash" OR "tclsh") processes.parent.cmdline:(*.pkl OR *.pickle OR *.joblib OR *.bin OR *.pt OR *.pth OR *.h5 OR *.keras OR *.onnx OR *.model OR *.sav OR *.ckpt OR *.safetensors)
| select min(timestamp) as firstTime, max(timestamp) as lastTime, host, user, processes.parent.name as parent_process_name, processes.parent.cmdline as parent_process, processes.name as process_name, processes.cmdline as process, count() as count
| group by host, user, parent_process_name, parent_process, process_name, process
```

### Elastic
---
```sql
FROM *
| WHERE process.parent.name IN ("python.exe", "python3.exe", "pythonw.exe")
  AND process.name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "zsh", "csh", "tcsh", "ksh", "dash", "tclsh")
  AND (process.parent.command_line LIKE ".pkl" OR process.parent.command_line LIKE ".pickle" OR process.parent.command_line LIKE ".joblib" OR process.parent.command_line LIKE ".bin" OR process.parent.command_line LIKE ".pt" OR process.parent.command_line LIKE ".pth" OR process.parent.command_line LIKE ".h5" OR process.parent.command_line LIKE ".keras" OR process.parent.command_line LIKE ".onnx" OR process.parent.command_line LIKE ".model" OR process.parent.command_line LIKE ".sav" OR process.parent.command_line LIKE ".ckpt" OR process.parent.command_line LIKE ".safetensors")
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), count = COUNT() BY host.name, user.name, process.parent.name, process.parent.command_line, process.name, process.command_line
| KEEP firstTime, lastTime, host.name AS host, user.name AS user, process.parent.name AS parent_process_name, process.parent.command_line AS parent_process, process.name AS process_name, process.command_line AS process, count
```

### Sentinel One
---
```sql
SELECT MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime, EndpointName AS host, UserName AS user, ParentProcessName AS parent_process_name, ParentCmdLine AS parent_process, ProcessName AS process_name, CmdLine AS process, COUNT(*) AS count
FROM process
WHERE ParentProcessName IN ('python.exe', 'python3.exe', 'pythonw.exe')
  AND ProcessName IN ('cmd.exe', 'powershell.exe', 'pwsh.exe', 'sh', 'bash', 'zsh', 'csh', 'tcsh', 'ksh', 'dash', 'tclsh')
  AND (ParentCmdLine LIKE '%.pkl' OR ParentCmdLine LIKE '%.pickle' OR ParentCmdLine LIKE '%.joblib' OR ParentCmdLine LIKE '%.bin' OR ParentCmdLine LIKE '%.pt' OR ParentCmdLine LIKE '%.pth' OR ParentCmdLine LIKE '%.h5' OR ParentCmdLine LIKE '%.keras' OR ParentCmdLine LIKE '%.onnx' OR ParentCmdLine LIKE '%.model' OR ParentCmdLine LIKE '%.sav' OR ParentCmdLine LIKE '%.ckpt' OR ParentCmdLine LIKE '%.safetensors')
GROUP BY EndpointName, UserName, ParentProcessName, ParentCmdLine, ProcessName, CmdLine
```

### AI Model Spawning Suspicious Child Process
---

Detects when a Python process, after its command line indicates the loading of a common AI/ML model file, spawns a command-line interpreter. Malicious AI models can create untraced processes during loading or inference. Monitoring for unexpected process creation is vital for early detection.

### Splunk
---
```sql
-- author: RW
-- date: 2025-08-14
-- tags:
--     - AI/ML Supply Chain Attacks
--   asset_type: Endpoint
--   confidence: 60
--   impact: 80
--   mitre_attack_id:
--     - T1059
--     - T1566.001

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe", "python3.exe", "pythonw.exe")) AND (Processes.process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "zsh", "csh", "tcsh", "ksh", "dash", "tclsh")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
-- Filter for parent command line containing a model file extension. This provides the AI/ML context.
| where like(parent_process, "%.pkl") OR like(parent_process, "%.pickle") OR like(parent_process, "%.joblib") OR like(parent_process, "%.bin") OR like(parent_process, "%.pt") OR like(parent_process, "%.pth") OR like(parent_process, "%.h5") OR like(parent_process, "%.keras") OR like(parent_process, "%.onnx") OR like(parent_process, "%.model") OR like(parent_process, "%.sav") OR like(parent_process, "%.ckpt") OR like(parent_process, "%.safetensors")
-- Potential for False Positives: Some legitimate ML/automation scripts might call shell commands.
-- Consider excluding known-good scripts or parent processes if they generate noise.
-- For example: | where NOT (like(parent_process, "%legitimate_script.py%"))
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| rename dest as host
| table firstTime, lastTime, host, user, parent_process_name, parent_process, process_name, process, count
```

### Crowdstrike
---
```sql
event_platform=Win event_simpleName=ProcessRollup2 ParentBaseFileName IN ("python.exe","python3.exe","pythonw.exe") FileName IN ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","zsh","csh","tcsh","ksh","dash","tclsh") CommandLine IN (".pkl&quot;,&quot;.pickle&quot;,&quot;.joblib&quot;,&quot;.bin&quot;,&quot;.pt&quot;,&quot;.pth&quot;,&quot;.h5&quot;,&quot;.keras&quot;,&quot;.onnx&quot;,&quot;.model&quot;,&quot;.sav&quot;,&quot;.ckpt","*.safetensors")
| group by aid, ContextTimeStamp, TargetProcessId, ParentBaseFileName, CommandLine, FileName, UserName
| aggregate firstTime=min(ContextTimeStamp), lastTime=max(ContextTimeStamp), count=count(TargetProcessId) by aid, UserName, ParentBaseFileName, CommandLine, FileName
| project firstTime, lastTime, aid as host, UserName as user, ParentBaseFileName as parent_process_name, CommandLine as parent_process, FileName as process_name, CommandLine as process, count
```

### Datadog
---
```sql
processes.parent.name:("python.exe" OR "python3.exe" OR "pythonw.exe") processes.name:("cmd.exe" OR "powershell.exe" OR "pwsh.exe" OR "sh" OR "bash" OR "zsh" OR "csh" OR "tcsh" OR "ksh" OR "dash" OR "tclsh") processes.parent.cmdline:(*.pkl OR *.pickle OR *.joblib OR *.bin OR *.pt OR *.pth OR *.h5 OR *.keras OR *.onnx OR *.model OR *.sav OR *.ckpt OR *.safetensors)
| select min(timestamp) as firstTime, max(timestamp) as lastTime, host, user, processes.parent.name as parent_process_name, processes.parent.cmdline as parent_process, processes.name as process_name, processes.cmdline as process, count() as count
| group by host, user, parent_process_name, parent_process, process_name, process
```

### Elastic
---
```sql
FROM *
| WHERE process.parent.name IN ("python.exe", "python3.exe", "pythonw.exe")
  AND process.name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "zsh", "csh", "tcsh", "ksh", "dash", "tclsh")
  AND (process.parent.command_line LIKE ".pkl" OR process.parent.command_line LIKE ".pickle" OR process.parent.command_line LIKE ".joblib" OR process.parent.command_line LIKE ".bin" OR process.parent.command_line LIKE ".pt" OR process.parent.command_line LIKE ".pth" OR process.parent.command_line LIKE ".h5" OR process.parent.command_line LIKE ".keras" OR process.parent.command_line LIKE ".onnx" OR process.parent.command_line LIKE ".model" OR process.parent.command_line LIKE ".sav" OR process.parent.command_line LIKE ".ckpt" OR process.parent.command_line LIKE ".safetensors")
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), count = COUNT() BY host.name, user.name, process.parent.name, process.parent.command_line, process.name, process.command_line
| KEEP firstTime, lastTime, host.name AS host, user.name AS user, process.parent.name AS parent_process_name, process.parent.command_line AS parent_process, process.name AS process_name, process.command_line AS process, count
```

### Sentinel One
---
```sql
SELECT MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime, EndpointName AS host, UserName AS user, ParentProcessName AS parent_process_name, ParentCmdLine AS parent_process, ProcessName AS process_name, CmdLine AS process, COUNT(*) AS count
FROM process
WHERE ParentProcessName IN ('python.exe', 'python3.exe', 'pythonw.exe')
  AND ProcessName IN ('cmd.exe', 'powershell.exe', 'pwsh.exe', 'sh', 'bash', 'zsh', 'csh', 'tcsh', 'ksh', 'dash', 'tclsh')
  AND (ParentCmdLine LIKE '%.pkl' OR ParentCmdLine LIKE '%.pickle' OR ParentCmdLine LIKE '%.joblib' OR ParentCmdLine LIKE '%.bin' OR ParentCmdLine LIKE '%.pt' OR ParentCmdLine LIKE '%.pth' OR ParentCmdLine LIKE '%.h5' OR ParentCmdLine LIKE '%.keras' OR ParentCmdLine LIKE '%.onnx' OR ParentCmdLine LIKE '%.model' OR ParentCmdLine LIKE '%.sav' OR ParentCmdLine LIKE '%.ckpt' OR ParentCmdLine LIKE '%.safetensors')
GROUP BY EndpointName, UserName, ParentProcessName, ParentCmdLine, ProcessName, CmdLine
```

### AI Model Initiating Network Connection

Detects when a Python process, with a command line indicating the loading of a common AI/ML model file, initiates an outbound network connection.
This behavior is suspicious as model loading and inference should typically not require arbitrary network connections.
This could indicate a malicious model attempting data exfiltration or establishing a command-and-control channel.

### Splunk
---
```sql
-- author: RW
-- date: 2025-08-14
-- tags:
--     - AI/ML Supply Chain Attacks
--   asset_type: Endpoint
--   confidence: 60
--   impact: 70
--   mitre_attack_id:
--     - T1071
--     - T1041
--     - T1566.001

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Network_Traffic.process) as process from datamodel=Endpoint.Network_Traffic where (Network_Traffic.process_name IN ("python.exe", "python3.exe", "pythonw.exe")) AND (NOT Network_Traffic.dest_ip IN ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1", "::1")) by Network_Traffic.dest Network_Traffic.user Network_Traffic.process_name Network_Traffic.dest_ip Network_Traffic.dest_port
| `drop_dm_object_name(Network_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- Filter for command line containing a model file extension. This provides the AI/ML context.
| where like(process, "%.pkl") OR like(process, "%.pickle") OR like(process, "%.joblib") OR like(process, "%.bin") OR like(process, "%.pt") OR like(process, "%.pth") OR like(process, "%.h5") OR like(process, "%.keras") OR like(process, "%.onnx") OR like(process, "%.model") OR like(process, "%.sav") OR like(process, "%.ckpt") OR like(process, "%.safetensors")
-- FP Tuning: Legitimate ML workflows might connect to known services (e.g., cloud storage, model hubs).
-- Consider excluding known-good destination IPs or domains if this rule is noisy.
-- For example: | where dest_ip != "1.2.3.4" AND dest_ip != "5.6.7.8"
| rename dest as host
| table firstTime, lastTime, host, user, process_name, process, dest_ip, dest_port, count
```

### Crowdstrike
---
```sql
event_platform=Win event_simpleName=NetworkConnectV2 FileName IN ("python.exe","python3.exe","pythonw.exe") NOT RemoteAddress IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.1","::1") CommandLine IN (".pkl&quot;,&quot;.pickle&quot;,&quot;.joblib&quot;,&quot;.bin&quot;,&quot;.pt&quot;,&quot;.pth&quot;,&quot;.h5&quot;,&quot;.keras&quot;,&quot;.onnx&quot;,&quot;.model&quot;,&quot;.sav&quot;,&quot;.ckpt","*.safetensors")
| group by aid, ContextTimeStamp, FileName, CommandLine, RemoteAddress, RemotePort, UserName
| aggregate firstTime=min(ContextTimeStamp), lastTime=max(ContextTimeStamp), process=values(CommandLine), count=count() by aid, UserName, FileName, RemoteAddress, RemotePort
| project firstTime, lastTime, aid as host, UserName as user, FileName as process_name, process, RemoteAddress as dest_ip, RemotePort as dest_port, count
```

### Datadog
---
```sql
network.process.name:("python.exe" OR "python3.exe" OR "pythonw.exe") NOT network.dest.ip:("10.0.0.0/8" OR "172.16.0.0/12" OR "192.168.0.0/16" OR "127.0.0.1" OR "::1") network.process.cmdline:(*.pkl OR *.pickle OR *.joblib OR *.bin OR *.pt OR *.pth OR *.h5 OR *.keras OR *.onnx OR *.model OR *.sav OR *.ckpt OR *.safetensors)
| select min(timestamp) as firstTime, max(timestamp) as lastTime, host, user, network.process.name as process_name, network.process.cmdline as process, network.dest.ip as dest_ip, network.dest.port as dest_port, count() as count
| group by host, user, process_name, process, dest_ip, dest_port
```

### Elastic
---
```sql
FROM *
| WHERE process.name IN ("python.exe", "python3.exe", "pythonw.exe")
  AND NOT destination.ip IN ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1", "::1")
  AND (process.command_line LIKE ".pkl" OR process.command_line LIKE ".pickle" OR process.command_line LIKE ".joblib" OR process.command_line LIKE ".bin" OR process.command_line LIKE ".pt" OR process.command_line LIKE ".pth" OR process.command_line LIKE ".h5" OR process.command_line LIKE ".keras" OR process.command_line LIKE ".onnx" OR process.command_line LIKE ".model" OR process.command_line LIKE ".sav" OR process.command_line LIKE ".ckpt" OR process.command_line LIKE ".safetensors")
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), count = COUNT(), process = VALUES(process.command_line) BY host.name, user.name, process.name, destination.ip, destination.port
| KEEP firstTime, lastTime, host.name AS host, user.name AS user, process.name AS process_name, process, destination.ip AS dest_ip, destination.port AS dest_port, count
```

### Sentinel One
---
```sql
SELECT MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime, EndpointName AS host, UserName AS user, ProcessName AS process_name, CmdLine AS process, DstIP AS dest_ip, DstPort AS dest_port, COUNT(*) AS count
FROM network
WHERE ProcessName IN ('python.exe', 'python3.exe', 'pythonw.exe')
  AND NOT DstIP IN ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.1', '::1')
  AND (CmdLine LIKE '%.pkl' OR CmdLine LIKE '%.pickle' OR CmdLine LIKE '%.joblib' OR CmdLine LIKE '%.bin' OR CmdLine LIKE '%.pt' OR CmdLine LIKE '%.pth' OR CmdLine LIKE '%.h5' OR CmdLine LIKE '%.keras' OR CmdLine LIKE '%.onnx' OR CmdLine LIKE '%.model' OR CmdLine LIKE '%.sav' OR CmdLine LIKE '%.ckpt' OR CmdLine LIKE '%.safetensors')
GROUP BY EndpointName, UserName, ProcessName, CmdLine, DstIP, DstPort
```

### Malicious Code Execution via Pickle Deserialization
---

Detects when a Python process, after loading a pickle (.pkl, .pickle) file, spawns a command-line interpreter. This is a strong indicator of a malicious pickle file executing arbitrary code upon deserialization, a technique highlighted in AI/ML security research.

### Splunk
---
```sql
-- author: RW
-- date: 2025-08-14
-- tags:
--     - AI/ML Supply Chain Attacks
--   asset_type: Endpoint
--   confidence: 70
--   impact: 80
--   mitre_attack_id:
--     - T1203
--     - T1059

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe", "python3.exe", "pythonw.exe")) AND (Processes.process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "zsh", "csh", "tcsh", "ksh", "dash", "tclsh")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
-- Filter for parent command line containing a pickle file extension.
| where like(parent_process, "%.pkl") OR like(parent_process, "%.pickle")
-- FP Tuning: Some legitimate automation or data science workflows might execute shell commands.
-- Review the parent script's command line and purpose to validate, and exclude if necessary.
-- For example: | where NOT (like(parent_process, "%legit_script_that_uses_shell.py%"))
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| rename dest as host
| table firstTime, lastTime, host, user, parent_process_name, parent_process, process_name, process, count
```

### Crowdstrike
---
```sql
event_platform=Win event_simpleName=ProcessRollup2 ParentBaseFileName IN ("python.exe","python3.exe","pythonw.exe") FileName IN ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","zsh","csh","tcsh","ksh","dash","tclsh") CommandLine IN (".pkl&quot;,&quot;.pickle")
| group by aid, ContextTimeStamp, TargetProcessId, ParentBaseFileName, CommandLine, FileName, UserName
| aggregate firstTime=min(ContextTimeStamp), lastTime=max(ContextTimeStamp), count=count(TargetProcessId) by aid, UserName, ParentBaseFileName, CommandLine, FileName
| project firstTime, lastTime, aid as host, UserName as user, ParentBaseFileName as parent_process_name, CommandLine as parent_process, FileName as process_name, CommandLine as process, count
```

### Datadog
---
```sql
processes.parent.name:("python.exe" OR "python3.exe" OR "pythonw.exe") processes.name:("cmd.exe" OR "powershell.exe" OR "pwsh.exe" OR "sh" OR "bash" OR "zsh" OR "csh" OR "tcsh" OR "ksh" OR "dash" OR "tclsh") processes.parent.cmdline:(*.pkl OR *.pickle)
| select min(timestamp) as firstTime, max(timestamp) as lastTime, host, user, processes.parent.name as parent_process_name, processes.parent.cmdline as parent_process, processes.name as process_name, processes.cmdline as process, count() as count
| group by host, user, parent_process_name, parent_process, process_name, process
```

### Elastic
---
```sql
FROM *
| WHERE process.parent.name IN ("python.exe", "python3.exe", "pythonw.exe")
  AND process.name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "zsh", "csh", "tcsh", "ksh", "dash", "tclsh")
  AND (process.parent.command_line LIKE ".pkl" OR process.parent.command_line LIKE ".pickle")
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), count = COUNT(*) BY host.name, user.name, process.parent.name, process.parent.command_line, process.name, process.command_line
| KEEP firstTime, lastTime, host.name AS host, user.name AS user, process.parent.name AS parent_process_name, process.parent.command_line AS parent_process, process.name AS process_name, process.command_line AS process, count
```

### Sentinel One
---
```sql
SELECT MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime, EndpointName AS host, UserName AS user, ParentProcessName AS parent_process_name, ParentCmdLine AS parent_process, ProcessName AS process_name, CmdLine AS process, COUNT(*) AS count
FROM process
WHERE ParentProcessName IN ('python.exe', 'python3.exe', 'pythonw.exe')
  AND ProcessName IN ('cmd.exe', 'powershell.exe', 'pwsh.exe', 'sh', 'bash', 'zsh', 'csh', 'tcsh', 'ksh', 'dash', 'tclsh')
  AND (ParentCmdLine LIKE '%.pkl' OR ParentCmdLine LIKE '%.pickle')
GROUP BY EndpointName, UserName, ParentProcessName, ParentCmdLine, ProcessName, CmdLine
```

### Malicious Code Execution via Joblib Deserialization
---

Detects when a Python process, after loading a Joblib (.joblib) file, spawns a command-line interpreter. This is a strong indicator of a malicious Joblib file executing arbitrary code upon deserialization, a technique highlighted in AI/ML security research.

### Splunk
---
```sql
-- author: RW
-- date: 2025-08-14
-- tags:
--     - AI/ML Supply Chain Attacks
--   asset_type: Endpoint
--   confidence: 70
--   impact: 80
--   mitre_attack_id:
--     - T1203
--     - T1059
--     - T1566.001

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe", "python3.exe", "pythonw.exe")) AND (Processes.process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "zsh", "csh", "tcsh", "ksh", "dash", "tclsh")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
-- Filter for parent command line containing a joblib file extension, which provides the AI/ML context.
| where like(parent_process, "%.joblib%")
-- FP Tuning: Some legitimate automation or data science workflows might execute shell commands.
-- Review the parent script's command line and purpose to validate, and exclude if necessary.
-- For example: | where NOT (like(parent_process, "%legit_automation_script.py%"))
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| rename dest as host
| table firstTime, lastTime, host, user, parent_process_name, parent_process, process_name, process, count
```

### Crowdstrike
---
```sql
event_platform=Win event_simpleName=ProcessRollup2 ParentBaseFileName IN ("python.exe","python3.exe","pythonw.exe") FileName IN ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","zsh","csh","tcsh","ksh","dash","tclsh") CommandLine IN ("*.joblib")
| group by aid, ContextTimeStamp, TargetProcessId, ParentBaseFileName, CommandLine, FileName, UserName
| aggregate firstTime=min(ContextTimeStamp), lastTime=max(ContextTimeStamp), count=count(TargetProcessId) by aid, UserName, ParentBaseFileName, CommandLine, FileName
| project firstTime, lastTime, aid as host, UserName as user, ParentBaseFileName as parent_process_name, CommandLine as parent_process, FileName as process_name, CommandLine as process, count
```

### Datadog
---
```sql
processes.parent.name:("python.exe" OR "python3.exe" OR "pythonw.exe") processes.name:("cmd.exe" OR "powershell.exe" OR "pwsh.exe" OR "sh" OR "bash" OR "zsh" OR "csh" OR "tcsh" OR "ksh" OR "dash" OR "tclsh") processes.parent.cmdline:*.joblib
| select min(timestamp) as firstTime, max(timestamp) as lastTime, host, user, processes.parent.name as parent_process_name, processes.parent.cmdline as parent_process, processes.name as process_name, processes.cmdline as process, count() as count
| group by host, user, parent_process_name, parent_process, process_name, process
```

### Elastic
---
```sql
FROM *
| WHERE process.parent.name IN ("python.exe", "python3.exe", "pythonw.exe")
  AND process.name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "zsh", "csh", "tcsh", "ksh", "dash", "tclsh")
  AND process.parent.command_line LIKE ".joblib"
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), count = COUNT() BY host.name, user.name, process.parent.name, process.parent.command_line, process.name, process.command_line
| KEEP firstTime, lastTime, host.name AS host, user.name AS user, process.parent.name AS parent_process_name, process.parent.command_line AS parent_process, process.name AS process_name, process.command_line AS process, count
```

### Sentinel One
---
```sql
SELECT MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime, EndpointName AS host, UserName AS user, ParentProcessName AS parent_process_name, ParentCmdLine AS parent_process, ProcessName AS process_name, CmdLine AS process, COUNT(*) AS count
FROM process
WHERE ParentProcessName IN ('python.exe', 'python3.exe', 'pythonw.exe')
  AND ProcessName IN ('cmd.exe', 'powershell.exe', 'pwsh.exe', 'sh', 'bash', 'zsh', 'csh', 'tcsh', 'ksh', 'dash', 'tclsh')
  AND ParentCmdLine LIKE '%.joblib'
GROUP BY EndpointName, UserName, ParentProcessName, ParentCmdLine, ProcessName, CmdLine
```