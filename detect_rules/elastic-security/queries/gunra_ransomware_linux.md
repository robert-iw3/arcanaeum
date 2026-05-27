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
FROM *
| WHERE (
  event.module = "file"
  AND file.name LIKE "%.ENCRT"
)
| KEEP @timestamp, host.name, file.path, file.name, event.action
| EVAL _time = TO_STRING(@timestamp, "yyyy-MM-dd'T'HH:mm:ss")
| SORT _time DESC
```

### Command-Line Arguments:
---
The Linux variant requires specific command-line arguments for execution, including `--threads`, `--path`, `--exts`, `--ratio`, `--keyfile`, `--store`, and `--limit`.

```sql
FROM *
| WHERE (
  process.command_line LIKE "*--threads*"
  OR process.command_line LIKE "* -t *"
)
AND (
  process.command_line LIKE "*--path*"
  OR process.command_line LIKE "* -p *"
)
AND (
  process.command_line LIKE "*--exts*"
  OR process.command_line LIKE "* -e *"
)
AND (
  process.command_line LIKE "*--keyfile*"
  OR process.command_line LIKE "* -k *"
)
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.parent.name, process.name, process.command_line
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
| RENAME host.name AS host, process.parent.name AS parent_process, process.name AS process_name, process.command_line AS process_command_line
```

### Keystore File Creation:
---

When the `--store` parameter is used, the ransomware creates separate keystore files (e.g., `filename.keystore`) to store RSA-encrypted blobs.

```sql
FROM *
| WHERE file.name LIKE "*.keystore"
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.name, file.path, file.name
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
| RENAME host.name AS host, process.name AS process, file.path AS file_path, file.name AS file_name
```

### RSA Public Key Requirement:
---

The ransomware requires a PEM file containing an RSA public key at runtime for its encryption routine.

```sql
FROM *
| WHERE (
  process.command_line LIKE "%--keyfile%*.pem%"
  OR process.command_line LIKE "% -k %*.pem%"
)
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.parent.name, process.name, process.command_line
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
| RENAME host.name AS host, user.name AS user, process.parent.name AS parent_process, process.name AS process_name, process.command_line AS process_command_line
```