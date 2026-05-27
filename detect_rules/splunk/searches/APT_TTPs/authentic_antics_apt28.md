### AUTHENTIC ANTICS Malware Report
---

AUTHENTIC ANTICS is a sophisticated credential and OAuth 2.0 token-stealing malware primarily targeting Microsoft Outlook on Windows operating systems. It employs extensive defense evasion techniques and operates by displaying malicious login prompts within the Outlook process to intercept credentials and tokens, which are then used to exfiltrate data via the victim's own email account.

Recent intelligence attributes the AUTHENTIC ANTICS malware to APT28 (Fancy Bear), a threat actor linked to Russia's GRU, highlighting a state-sponsored espionage campaign targeting Western logistics and technology sectors. This attribution underscores the persistent and sophisticated nature of the threat, emphasizing the need for robust defenses against such advanced persistent threats.

### Actionable Threat Data
---

Persistence via COM Hijacking: AUTHENTIC ANTICS establishes persistence by hijacking COM objects, specifically by modifying the `HKLM\SOFTWARE\Classes\CLSID\{1299CF18-C4F5-4B6A-BB0F-2299F0398E27}\InprocServer32` registry key to point to its loader (`Microsoft.Identity64.dll`). This technique allows the malware to execute when Outlook starts. (T1546.015)

Credential and Token Theft from Outlook Process: The malware runs within the Outlook process (outlook.exe) and generates fake login prompts to steal credentials and OAuth 2.0 tokens. This activity can be identified by monitoring for unexpected login prompts originating from the `outlook.exe` process. (T1557, T1187)

Defense Evasion through API Unhooking and Environmental Keying: AUTHENTIC ANTICS unhooks registry APIs within `ntdll.dll` to evade monitoring and uses environmental keying (deriving decryption keys from machine-specific data like MachineGuid and Volume Serial Number) to ensure the stealer payload only decrypts on the intended victim's machine. (T1562.001, T1480.001)

Exfiltration via Victim's Email Account: Stolen data is exfiltrated by sending emails from the victim's Outlook account to an actor-controlled email address. The malware sets the `SaveToSentItems` flag to false to prevent these emails from appearing in the victim's sent folder. Monitoring for unusual outbound email activity, especially emails with obfuscated content or sent to suspicious external addresses, is crucial. (T1567)

Registry-Based Data Storage and Execution Frequency Control: AUTHENTIC ANTICS stores a Counter value in `HKCU\Software\Microsoft\Office\16.0\Outlook\Logging\` to control its execution frequency (once every 6 days). Monitoring for suspicious modifications or access patterns to this registry key can indicate malware presence. (T1070.004)

### COM Hijacking Persistence
---
```sql
`comment("
name: "AUTHENTIC ANTICS COM Hijacking Persistence"
author: "Rob Weber"
date: "2025-07-25"
version: "1.0"

description: >
  "This rule detects a specific COM hijacking technique used by the AUTHENTIC ANTICS malware for persistence.
  The malware modifies the InprocServer32 key for the Outlook `npmproxy.dll` CLSID ({1299CF18-C4F5-4B6A-BB0F-2299F0398E27})
  to point to its own malicious DLL, `Microsoft.Identity64.dll`. This allows the malware to be loaded by Outlook on startup."

data_source:
  - "Sysmon Event ID 13"
  - "EDR Registry Events"

how_to_implement: >
  "This detection requires registry modification events, such as those from Sysmon (Event ID 13) or other EDR sources,
  mapped to the 'Registry' data model. The CLSID {1299CF18-C4F5-4B6A-BB0F-2299F0398E27} is specific to an Outlook component,
  and its InprocServer32 key should legitimately point to `npmproxy.dll`. Any other value is highly suspicious."

known_false_positives: >
  "False positives are unlikely as this is a very specific registry key tied to an Outlook component.
  However, if legitimate software in your environment modifies this key, consider adding the legitimate DLL path to the exclusion in the search."

references:
  - "NCSC Malware Analysis Report: AUTHENTIC ANTICS"

tags:
  analytic_story:
    - "AUTHENTIC ANTICS"
  mitre_attack_id:
    - "T1546.015"
  kill_chain_phases:
    - "Persistence"
  security_domain: "endpoint"
  asset_type: "Endpoint"
")`

search: >
  `tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Registry
  where Registry.registry_path="*\\Classes\\CLSID\\{1299CF18-C4F5-4B6A-BB0F-2299F0398E27}\\InprocServer32"
  AND Registry.registry_value_name IN ("(Default)", "Default")
  AND NOT Registry.registry_value_data LIKE "%npmproxy.dll"
  by Registry.dest, Registry.user, Registry.process_name, Registry.registry_path, Registry.registry_value_data
  | `drop_dm_object_name("Registry")`
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
```

### Outlook Process Impersonation
---
```sql
`comment("
name: "AUTHENTIC ANTICS Forced Authentication via Outlook"
author: "Rob Weber"
date: "2025-07-25"
version: "1.0"

description: >
  "Detects a potential forced authentication attempt originating from the Microsoft Outlook process.
  The AUTHENTIC ANTICS malware, as detailed in the NCSC report, generates a pop-up browser window from within the Outlook process,
  directing the user to the Microsoft authorization endpoint with parameters that force a new login.
  This allows the malware to intercept the authentication flow and steal credentials and OAuth 2.0 tokens."

data_source:
  - "EDR Network Events"
  - "Web Proxy Logs"
  - "Sysmon Event ID 22"

how_to_implement: >
  "This detection requires network connection or web proxy logs, such as those from EDR tools or Sysmon (Event ID 22 for DNS queries which can be correlated),
  mapped to the 'Web' data model. The `process_name` and `url` fields are essential for this detection to function correctly."

known_false_positives: >
  "Legitimate authentication flows, particularly when a user's session has expired or when adding a new account to Outlook, may generate similar network traffic.
  The use of `prompt=login` increases suspicion but does not eliminate the possibility of legitimate activity.
  False positives can be reduced by correlating these alerts with other AUTHENTIC ANTICS indicators or with user reports of unexpected login prompts.
  Consider baselining normal authentication behavior and alerting on significant deviations."

references:
  - "NCSC Malware Analysis Report: AUTHENTIC ANTICS"

tags:
  analytic_story:
    - "AUTHENTIC ANTICS"
  mitre_attack_id:
    - "T1187"
    - "T1557"
  kill_chain_phases:
    - "Credential Access"
  security_domain: "endpoint"
  asset_type: "Endpoint"
")`

search: >
  `tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web
  where
    Web.process_name = "outlook.exe"
    AND Web.url LIKE "%login.microsoftonline.com/common/oauth2/authorize%"
    AND Web.url LIKE "%client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c%"
    AND Web.url LIKE "%redirect_uri=ms-appx-web%3a%2f%2fMicrosoft.AAD.BrokerPlugin%2fd3590ed6-52b3-4102-aeff-aad2292ab01c%"
    AND Web.url LIKE "%prompt=login%"
  by Web.dest, Web.user, Web.process_name, Web.url
  | `drop_dm_object_name("Web")`
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `comment("This search looks for network traffic from outlook.exe that matches the specific authentication request used by AUTHENTIC ANTICS.")`
  | `comment("The 'prompt=login' parameter is key, as it forces a credential entry prompt, which is central to the malware's theft mechanism.")`
```

### Registry API Unhooking
---
```sql
`comment("
name: "AUTHENTIC ANTICS ntdll.dll API Unhooking"
author: "Rob Weber"
date: "2025-07-25"
version: "1.0"

description: >
  "Detects potential API unhooking activity characteristic of the AUTHENTIC ANTICS malware.
  This malware unhooks registry-related functions within ntdll.dll to evade monitoring by security tools.
  This detection identifies alerts from EDR products that have detected this in-memory tampering,
  focusing on attempts originating from the Outlook process."

data_source:
  - "EDR Alerts"

how_to_implement: >
  "This detection requires an EDR or other advanced endpoint security tool capable of detecting and alerting on in-memory API unhooking or module tampering.
  These alerts must be ingested into Splunk and mapped to the 'Alerts' data model.
  You will likely need to customize the 'Alerts.signature' and 'Alerts.object' field checks to match the specific output of your EDR product."

known_false_positives: >
  "False positives are possible if other legitimate software, such as security products or debuggers, perform actions that are flagged as unhooking by your EDR.
  Focusing on alerts originating from 'outlook.exe' significantly increases the fidelity.
  Investigation should confirm if the activity is part of a known software behavior or corresponds with other AUTHENTIC ANTICS indicators."

references:
  - "NCSC Malware Analysis Report: AUTHENTIC ANTICS"

tags:
  analytic_story:
    - "AUTHENTIC ANTICS"
  mitre_attack_id:
    - "T1562.001"
  kill_chain_phases:
    - "Defense Evasion"
  security_domain: "endpoint"
  asset_type: "Endpoint"
")`

search: >
  `tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Alerts
  where
    (Alerts.signature_id IN ("*Unhooking*", "*Tampering*") OR Alerts.signature IN ("*API Unhooking*", "*Memory Patching*", "*Defense Evasion*"))
    AND Alerts.process_name = "outlook.exe"
    AND Alerts.object LIKE "%ntdll.dll%"
  by Alerts.dest, Alerts.user, Alerts.process_name, Alerts.object, Alerts.signature, Alerts.signature_id, Alerts.vendor_product
  | `drop_dm_object_name("Alerts")`
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `comment("This search looks for alerts from EDR tools that indicate API unhooking or memory tampering.")`
  | `comment("It is specifically scoped to outlook.exe targeting ntdll.dll, which is the behavior described for AUTHENTIC ANTICS.")`
```

### Environmental Keying Evasion
---
```sql
`comment("
name: "AUTHENTIC ANTICS Environmental Keying Attempt"
author: "Rob Weber"
date: "2025-07-25"
version: "1.0"

description: >
  "Detects a potential environmental keying attempt by the AUTHENTIC ANTICS malware.
  The malware's loader, running in the context of outlook.exe, reads the MachineGuid from the registry
  as part of its process to derive a machine-specific key to decrypt its stealer payload.
  While other processes may legitimately query this value, access by outlook.exe is anomalous and warrants investigation."

data_source:
  - "Sysmon Event ID 13"
  - "EDR Registry Events"

how_to_implement: >
  "This detection requires registry modification events, such as those from Sysmon (Event ID 13: RegistryValueRead) or other EDR sources,
  mapped to the 'Registry' data model. Ensure that logging for read access to the HKLM\\Software\\Microsoft\\Cryptography key is enabled."

known_false_positives: >
  "Legitimate Outlook add-ins or enterprise management software that integrates with Outlook could potentially query the MachineGuid for identification purposes.
  This behavior is considered uncommon for Outlook itself.
  If false positives occur, investigate the specific add-ins running within Outlook on the affected host.
  Correlate alerts with other AUTHENTIC ANTICS indicators to increase confidence."

references:
  - "NCSC Malware Analysis Report: AUTHENTIC ANTICS"

tags:
  analytic_story:
    - "AUTHENTIC ANTICS"
  mitre_attack_id:
    - "T1480.001"
  kill_chain_phases:
    - "Defense Evasion"
  security_domain: "endpoint"
  asset_type: "Endpoint"
")`

search: >
  `tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Registry
  where Registry.process_name="outlook.exe" AND Registry.registry_path="*\\Microsoft\\Cryptography\\MachineGuid"
  by Registry.dest, Registry.user, Registry.process_name, Registry.registry_path
  | `drop_dm_object_name("Registry")`
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `comment("This search identifies when the Outlook process reads the MachineGuid registry value, a key step in the malware's environmental keying TTP.")`
```

### Stealthy Email Exfiltration
---
```sql
`comment("
name: "AUTHENTIC ANTICS Stealthy Email Exfiltration"
author: "Rob Weber"
date: "2025-07-25"
version: "1.0"

description: >
  "Detects stealthy email exfiltration activity characteristic of the AUTHENTIC ANTICS malware.
  The malware sends stolen data via the victim's email account by making a POST request to the Outlook API endpoint '/me/sendMail'.
  Crucially, it includes the parameter '\"SaveToSentItems\": \"false\"' in the request body to prevent the exfiltration email from appearing in the user's Sent Items folder."

data_source:
  - "Web Proxy Logs"
  - "EDR Network Events"

how_to_implement: >
  "This detection requires network traffic logs with visibility into HTTP request bodies (e.g., from a web proxy or an EDR tool).
  These logs must be ingested and mapped to the 'Web' data model, with the POST body content available in the 'form_data' field.
  If your data source uses a different field for the POST body, you will need to update the search accordingly."

known_false_positives: >
  "False positives are expected to be low, as setting 'SaveToSentItems' to 'false' is not a feature of standard email clients.
  However, custom applications or scripts that integrate with the Outlook API could potentially use this functionality for legitimate purposes.
  If false positives occur, investigate the source application on the host and consider creating an exclusion for known legitimate tools."

references:
  - "NCSC Malware Analysis Report: AUTHENTIC ANTICS"

tags:
  analytic_story:
    - "AUTHENTIC ANTICS"
  mitre_attack_id:
    - "T1567"
  kill_chain_phases:
    - "Exfiltration"
  security_domain: "network"
  asset_type: "Network"
")`

search: >
  `tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web
  where
    Web.http_method="POST"
    AND Web.url="https://outlook.office.com/api/v2.0/me/sendMail"
    AND Web.form_data LIKE "%\"SaveToSentItems\": \"false\"%"
  by Web.dest, Web.user, Web.src, Web.url, Web.form_data
  | `drop_dm_object_name("Web")`
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `comment("This search identifies POST requests to the specific Outlook sendMail API endpoint.")`
  | `comment("The key indicator is the presence of '\"SaveToSentItems\": \"false\"' in the POST body, which is highly anomalous for standard user activity.")`
```

### Registry-Based Execution Control
---
```sql
`comment("
name: "AUTHENTIC ANTICS Execution Frequency Control"
author: "Rob Weber"
date: "2025-07-25"
version: "1.0"

description: >
  "Detects the creation or modification of the 'Counter' registry value used by AUTHENTIC ANTICS to control its execution frequency.
  The malware writes a future timestamp to HKCU\\Software\\Microsoft\\Office\\16.0\\Outlook\\Logging\\Counter to ensure it only runs once every 6 days.
  According to the NCSC report, the presence of this 'Counter' value is not legitimate and is a strong indicator of the malware's presence."

data_source:
  - "Sysmon Event ID 12, 13"
  - "EDR Registry Events"

how_to_implement: >
  "This detection requires registry modification events, such as those from Sysmon (Event ID 12: RegistryCreate, Event ID 13: RegistryValueSet) or other EDR sources,
  mapped to the 'Registry' data model. Ensure logging for this specific Outlook registry path is enabled."

known_false_positives: >
  "False positives are expected to be very low, as the NCSC report indicates that the 'Counter' value within this specific registry key is not legitimate.
  However, it is possible that a custom or third-party Outlook add-in could use this key for its own purposes.
  Any alerts should be investigated to determine the parent process and its legitimacy."

references:
  - "NCSC Malware Analysis Report: AUTHENTIC ANTICS"

tags:
  analytic_story:
    - "AUTHENTIC ANTICS"
  mitre_attack_id:
    - "T1112"
  kill_chain_phases:
    - "Defense Evasion"
  security_domain: "endpoint"
  asset_type: "Endpoint"
")`

search: >
  `tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Registry
  where
    Registry.registry_path = "*\\Software\\Microsoft\\Office\\16.0\\Outlook\\Logging"
    AND Registry.registry_value_name = "Counter"
  by Registry.dest, Registry.user, Registry.process_name, Registry.registry_path, Registry.registry_value_name, Registry.registry_value_data
  | `drop_dm_object_name("Registry")`
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `comment("This search identifies any process creating or modifying the specific 'Counter' registry value used by AUTHENTIC ANTICS for execution timing.")`
```