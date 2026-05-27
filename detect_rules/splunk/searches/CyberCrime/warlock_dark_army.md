### Warlock Dark Army Ransomware Report
---

Warlock Dark Army is a ransomware group that encrypts files using the Tiny Encryption Algorithm (TEA) and demands ransom in Bitcoin, often communicating via Telegram. While initially thought to be related to Chaos ransomware, analysis indicates it is a distinct variant with unique attributes like its C/C++ compilation and use of TEA for encryption.


Recent intelligence indicates Warlock Dark Army has expanded its targeting to include government agencies worldwide and may be connected to the Black Basta ransomware group, suggesting an evolution in their operational scope and potential affiliations.

### Actionable Threat Data
---

Monitor for the creation of new files in the `%TEMP%` directory with suspicious, randomly generated filenames (e.g., `Nygi26XApwVsKic.exe`) as observed with Warlock Dark Army self-copies.

Detect modifications to the `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` registry key to establish persistence, specifically looking for new entries that point to executables in the `%TEMP%` directory.

Look for the creation of new registry entries under HKCR (HKEY_CLASSES_ROOT) with unusual key names (e.g., `KRKKHCRAPPRJISH`) and `Shell\open\command` subkeys pointing to executables in the `%TEMP%` directory, used for persistence and setting default icons.

Identify files with the `.warlockdarkarmyofficials` extension, which is appended to encrypted files by this ransomware.

Monitor for the presence of ransom notes, typically named `read_it.txt` or similar, on the desktop or in affected directories, containing contact information like Telegram channels.

### Warlock Dark Army Hash
---
```sql
-- name: Warlock Dark Army Ransomware Hash
-- date: 2025-07-23
-- description: Detects the execution of a process with a hash known to be associated with Warlock Dark Army ransomware.
-- references:
--   - https://labs.k7computing.com/index.php/ransomed-by-warlock-dark-army-officials/

-- This query leverages the Endpoint data model to find processes matching a known malicious hash.
-- This detection is high-fidelity as it relies on a specific IOC.
from datamodel=Endpoint.Processes

-- Filter for the known malicious MD5 hash of Warlock Dark Army ransomware.
| where Processes.process_hash_md5 = "f0979d897155f51fd96a63c61e05d85c"

-- Format the results for easy analysis.
| table _time, dest, user, Processes.process_name, Processes.process, Processes.process_path, Processes.process_hash_md5
```

### Warlock Dark Army Temp File
---
```sql
-- name: Warlock Dark Army Temp File Creation
-- date: 2025-07-23
-- description: Detects the creation of a randomly named executable in a temporary directory, a behavior associated with Warlock Dark Army ransomware.
-- references:
--   - https://labs.k7computing.com/index.php/ransomed-by-warlock-dark-army-officials/

-- Use the Filesystem data model to look for file creation events.
from datamodel=Endpoint.Filesystem

-- Filter for file creation events in common temporary directories.
| where Filesystem.action = "create" AND (Filesystem.file_path LIKE "%\\AppData\\Local\\Temp\\%" OR Filesystem.file_path LIKE "C:\\Windows\\Temp\\%")

-- The malware sample creates a 16-character alphanumeric executable.
-- This logic checks for .exe files with a name length of 16 characters.
| where match(Filesystem.file_name, /^[A-Za-z0-9]{16}\.exe$/)

-- Potential for False Positives: Legitimate software installers or updaters may also create randomly named executables in temp folders.
-- Consider filtering by file signature status or excluding known good parent processes if false positives occur.
-- | where Filesystem.file_is_signed = "false"

-- Format the results for analysis.
| table _time, dest, user, Filesystem.file_name, Filesystem.file_path, Filesystem.action, Filesystem.process_guid
```

### Warlock Dark Army Run Key Persistence
---
```sql
-- name: Warlock Dark Army Run Key Persistence
-- date: 2025-07-23
-- description: Detects the modification of a Run registry key to point to an executable in a temporary directory, a persistence technique used by Warlock Dark Army ransomware.
-- references:
--   - https://labs.k7computing.com/index.php/ransomed-by-warlock-dark-army-officials/

-- Use the Registry data model to look for registry modification events.
from datamodel=Endpoint.Registry

-- Filter for registry set events in the HKLM Run key.
| where Registry.action = "set" AND Registry.registry_path LIKE "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\%"

-- Filter for values that point to an executable in a common temporary directory.
| where (Registry.registry_value_data LIKE "%\\AppData\\Local\\Temp\\%.exe" OR Registry.registry_value_data LIKE "%\\Windows\\Temp\\%.exe")

-- Potential for False Positives: Some legitimate software installers or updaters might use this persistence method.
-- Consider adding filters to exclude known good software or look for additional suspicious activity from the source process if false positives occur.

-- Format the results for analysis.
| table _time, dest, user, Registry.process_guid, Registry.registry_path, Registry.registry_value_name, Registry.registry_value_data
```

### Warlock Dark Army HKCR Persistence
---
```sql
-- name: Warlock Dark Army HKCR Persistence
-- date: 2025-07-23
-- description: Detects the creation of a new HKEY_CLASSES_ROOT (HKCR) shell open command entry that points to an executable in a temporary directory. This persistence technique is used by Warlock Dark Army ransomware.
-- references:
--   - https://labs.k7computing.com/index.php/ransomed-by-warlock-dark-army-officials/

-- Use the Registry data model to look for registry modification events.
from datamodel=Endpoint.Registry

-- Filter for registry set events targeting a shell\open\command path under HKCR.
| where Registry.action = "set" AND Registry.registry_path LIKE "HKEY_CLASSES_ROOT\\%\\shell\\open\\command"

-- Filter for values that point to an executable in a common temporary directory.
| where (Registry.registry_value_data LIKE "%\\AppData\\Local\\Temp\\%.exe" OR Registry.registry_value_data LIKE "%\\Windows\\Temp\\%.exe")

-- Extract the HKCR key name for further analysis. The example key is "KRKKHCRAPPRJISH".
| rex field=Registry.registry_path "HKEY_CLASSES_ROOT\\\\(?<hkcr_key>[^\\\\]+)\\\\"

-- Potential for False Positives: Legitimate installers might briefly create HKCR entries pointing to temp locations.
-- To reduce noise, consider filtering for unusual key names (e.g., long, random-looking strings like the example "KRKKHCRAPPRJISH") if legitimate application names appear.
-- For example: | where len(hkcr_key) > 10 AND match(hkcr_key, /^[A-Z0-9]+$/)

-- Format the results for analysis.
| table _time, dest, user, Registry.process_guid, Registry.registry_path, Registry.registry_value_data, hkcr_key
```

### Warlock Dark Army Encrypted Extension
---
```sql
-- name: Warlock Dark Army Encrypted File Extension
-- date: 2025-07-23
-- description: Detects the creation or renaming of files with the ".warlockdarkarmyofficials" extension, which is indicative of Warlock Dark Army ransomware activity.
-- references:
--   - https://labs.k7computing.com/index.php/ransomed-by-warlock-dark-army-officials/

-- Use the Filesystem data model to look for file creation or rename events.
from datamodel=Endpoint.Filesystem

-- Filter for file create or rename actions where the file name ends with the specific ransomware extension.
-- This is a high-fidelity indicator of Warlock Dark Army ransomware.
| where (Filesystem.action = "create" OR Filesystem.action = "rename") AND Filesystem.file_name LIKE "%.warlockdarkarmyofficials"

-- Format the results for analysis.
| table _time, dest, user, Filesystem.process_guid, Filesystem.file_name, Filesystem.file_path, Filesystem.action
```

### Warlock Dark Army Ransom Note
---
```sql
-- name: Warlock Dark Army Ransom Note
-- date: 2025-07-23
-- description: Detects the creation of a ransom note file named "read_it.txt", which is associated with Warlock Dark Army ransomware.
-- references:
--   - https://labs.k7computing.com/index.php/ransomed-by-warlock-dark-army-officials/

-- Use the Filesystem data model to look for file creation events.
from datamodel=Endpoint.Filesystem

-- Filter for the creation of the specific ransom note file.
-- While the article doesn't name the file, "read_it.txt" is a common convention for ransom notes.
| where Filesystem.action = "create" AND Filesystem.file_name = "read_it.txt"

-- Potential for False Positives: The filename "read_it.txt" is generic and could be used by legitimate applications or users.
-- To increase fidelity, consider correlating this alert with other Warlock Dark Army indicators, such as file encryption activity (.warlockdarkarmyofficials) originating from the same process (process_guid).

-- Format the results for analysis.
| table _time, dest, user, Filesystem.process_guid, Filesystem.file_name, Filesystem.file_path, Filesystem.action
```

