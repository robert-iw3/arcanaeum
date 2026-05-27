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
index=* sourcetype=linux_filesystem_events
| where like(file_name, "%.ENCRT")
| table _time, host, file_path, file_name, action
```

CIM:

```sql
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="*.ENCRT" by Filesystem.dest, Filesystem.user, Filesystem.process_name, Filesystem.file_path
| `drop_dm_object_name("Filesystem")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
`comment("The following line renames fields for better readability in the output.")`
| rename dest as host, user as user, process_name as process, file_path as file
`comment("False Positive Tuning: While the .ENCRT extension is specific, a legitimate application could potentially use it. Consider filtering by process name or looking for a high volume of these files from a single host to increase fidelity.")`
```

### Command-Line Arguments:
---
The Linux variant requires specific command-line arguments for execution, including `--threads`, `--path`, `--exts`, `--ratio`, `--keyfile`, `--store`, and `--limit`.

```sql
index=* sourcetype=linux_process_events
| where process_name="gunra_linux_variant" AND (cmd_line LIKE "%--threads%" OR cmd_line LIKE "%--path%" OR cmd_line LIKE "%--exts%" OR cmd_line LIKE "%--keyfile%")
| table _time, host, process_name, cmd_line
```

CIM:

```sql
`comment("This detection rule identifies the execution of the Gunra ransomware Linux variant by its unique command-line arguments as described in the provided intelligence.")`
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where ((Processes.process="*--threads*" OR Processes.process="* -t *") AND (Processes.process="*--path*" OR Processes.process="* -p *") AND (Processes.process="*--exts*" OR Processes.process="* -e *") AND (Processes.process="*--keyfile*" OR Processes.process="* -k *")) by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
`comment("Renaming fields for better readability and context.")`
| rename dest as host, parent_process_name as parent_process, process_name as process_name, process as process_command_line
`comment("False Positive Tuning: The combination of these command-line arguments is highly specific to the Gunra ransomware. However, a legitimate custom script or tool could potentially use a similar syntax. If false positives occur, investigate the process_name and parent_process to determine if it is legitimate activity.")`
```

### Keystore File Creation:
---

When the `--store` parameter is used, the ransomware creates separate keystore files (e.g., `filename.keystore`) to store RSA-encrypted blobs.

```sql
index=* sourcetype=linux_filesystem_events
| where like(file_name, "%.keystore") AND action="created"
| table _time, host, file_path, file_name, action
```

CIM:

```sql
`comment("This detection rule identifies the creation of files with the .keystore extension. This behavior is associated with the Gunra ransomware when it is executed with the --store parameter to save RSA-encrypted keys to separate files.")`
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="*.keystore" by Filesystem.dest, Filesystem.user, Filesystem.process_name, Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name("Filesystem")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
`comment("Renaming fields for better readability and context.")`
| rename dest as host, process_name as process, file_path as file_path, file_name as file_name
`comment("False Positive Tuning: The .keystore extension is legitimately used by many applications, particularly those based on Java, for storing cryptographic keys. This may lead to false positives. To improve fidelity, investigate the creating process (process). If it is a known legitimate application like 'java' or 'keytool', it is likely benign. Consider filtering out known application paths. A high volume of .keystore files created in a short time, especially alongside other Gunra indicators, would be highly suspicious.")`
```

### RSA Public Key Requirement:
---

The ransomware requires a PEM file containing an RSA public key at runtime for its encryption routine.

```sql
index=* sourcetype=linux_process_events
| where process_name="gunra_linux_variant" AND cmd_line LIKE "%--keyfile=%.pem%"
| table _time, host, process_name, cmd_line
```

CIM:

```sql
`comment("This detection rule identifies processes launched with command-line arguments that specify a .pem file, a behavior associated with the Gunra ransomware's Linux variant which requires an RSA public key for its encryption routine.")`
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process LIKE "%--keyfile%*.pem%" OR Processes.process LIKE "% -k %*.pem%") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
`comment("Renaming fields for better readability and context.")`
| rename dest as host, user as user, parent_process_name as parent_process, process_name as process_name, process as process_command_line
`comment("False Positive Tuning: Legitimate applications, such as OpenSSL or other cryptographic tools, may use .pem files as command-line arguments. Investigate the process_name and parent_process to determine if the activity is benign. If this rule is too noisy, consider adding known legitimate process names to an exclusion list.")`
```