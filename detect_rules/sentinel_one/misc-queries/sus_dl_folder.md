### Suspicious Downloads Folder Execution

Detects execution of files from Downloads, Temp, or AppData folders by browsers, indicating potential FileFix attacks where malicious files are downloaded and immediately executed.

T1204.002 - Malicious File

T1059 - Command and Scripting Interpreter

T1059.007 - JavaScript

T1204 - User Execution

TA0002 - Execution

```sql
(src.process.image.path contains:anycase 'Downloads' or  src.process.image.path contains:anycase 'Temp' or  src.process.image.path contains:anycase 'AppData\\Local\\Temp') andsrc.process.name matches '.*\\.(scr|bat|cmd|ps1|vbs|js)$' andsrc.process.parent.name in:anycase ('chrome.exe', 'firefox.exe', 'msedge.exe', 'explorer.exe')
```