### Gunra Ransomware Linux Variant Analysis
---

Gunra ransomware has expanded its operations with a new Linux variant, significantly broadening its attack surface beyond its initial Windows-only focus. This new variant is designed for highly efficient and customizable encryption, featuring multi-threaded capabilities and flexible encryption options.

The Linux variant of Gunra ransomware introduces the ability to utilize up to 100 encryption threads, a significant increase compared to other ransomware, and supports partial encryption with configurable ratios and limits, making its encryption process faster and more adaptable. Additionally, unlike its Windows counterpart, the Linux variant does not drop a ransom note and can store RSA-encrypted keys in separate keystore files, complicating recovery efforts.

### Actionable Threat Data
---

### File Renaming:
---

Gunra ransomware renames encrypted files by appending the `.ENCRT` extension.

```sql
AgentName IS NOT EMPTY
AND FileName LIKE "%.ENCRT"
| SELECT EventTime AS _time, AgentName AS host, FilePath AS file_path, FileName AS file_name, EventType AS action
| FORMAT _time = "yyyy-MM-dd'T'HH:mm:ss"
| SORT _time DESC
```

### Command-Line Arguments:
---
The Linux variant requires specific command-line arguments for execution, including `--threads`, `--path`, `--exts`, `--ratio`, `--keyfile`, `--store`, and `--limit`.

```sql
AgentName IS NOT EMPTY
AND (
  ProcessCmd LIKE "*--threads*"
  OR ProcessCmd LIKE "* -t *"
)
AND (
  ProcessCmd LIKE "*--path*"
  OR ProcessCmd LIKE "* -p *"
)
AND (
  ProcessCmd LIKE "*--exts*"
  OR ProcessCmd LIKE "* -e *"
)
AND (
  ProcessCmd LIKE "*--keyfile*"
  OR ProcessCmd LIKE "* -k *"
)
| SELECT AgentName AS host, User AS user, ParentProcessName AS parent_process, ProcessName AS process_name, ProcessCmd AS process_command_line, COUNT(*) AS count, MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime
| GROUP BY AgentName, User, ParentProcessName, ProcessName, ProcessCmd
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```

### Keystore File Creation:
---

When the `--store` parameter is used, the ransomware creates separate keystore files (e.g., `filename.keystore`) to store RSA-encrypted blobs.

```sql
AgentName IS NOT EMPTY
AND FileName LIKE "*.keystore"
| SELECT AgentName AS host, User AS user, ProcessName AS process, FilePath AS file_path, FileName AS file_name, COUNT(*) AS count, MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime
| GROUP BY AgentName, User, ProcessName, FilePath, FileName
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```

### RSA Public Key Requirement:
---

The ransomware requires a PEM file containing an RSA public key at runtime for its encryption routine.

```sql
AgentName IS NOT EMPTY
AND (
  ProcessCmd LIKE "%--keyfile%*.pem%"
  OR ProcessCmd LIKE "% -k %*.pem%"
)
| SELECT AgentName AS host, User AS user, ParentProcessName AS parent_process, ProcessName AS process_name, ProcessCmd AS process_command_line, COUNT(*) AS count, MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime
| GROUP BY AgentName, User, ParentProcessName, ProcessName, ProcessCmd
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```