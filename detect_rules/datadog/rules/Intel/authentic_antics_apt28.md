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
-- references:
--   - "NCSC Malware Analysis Report: AUTHENTIC ANTICS"

-- tags:
--  analytic_story:
--    - "AUTHENTIC ANTICS"
--  mitre_attack_id:
--    - "T1546.015"
--  kill_chain_phases:
--    - "Persistence"
--  security_domain: "endpoint"
--  asset_type: "Endpoint"

source:registry registry.path:*\\Classes\\CLSID\\{1299CF18-C4F5-4B6A-BB0F-2299F0398E27}\\InprocServer32 registry.value_name:(Default "(Default)") -registry.value_data:*npmproxy.dll
| groupby host, user, process.name, registry.path, registry.value_data
```

### Outlook Process Impersonation
---
```sql
-- references:
--   - "NCSC Malware Analysis Report: AUTHENTIC ANTICS"

-- tags:
--  analytic_story:
--    - "AUTHENTIC ANTICS"
--  mitre_attack_id:
--    - "T1187"
--    - "T1557"
--  kill_chain_phases:
--    - "Credential Access"
--  security_domain: "endpoint"
--  asset_type: "Endpoint"

source:web process.name:outlook.exe url:*login.microsoftonline.com/common/oauth2/authorize* url:*client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c* url:*redirect_uri=ms-appx-web%3a%2f%2fMicrosoft.AAD.BrokerPlugin%2fd3590ed6-52b3-4102-aeff-aad2292ab01c* url:*prompt=login*
| groupby host, user, process.name, url
```

### Registry API Unhooking
---
```sql
-- references:
--  - "NCSC Malware Analysis Report: AUTHENTIC ANTICS"

-- tags:
--  analytic_story:
--    - "AUTHENTIC ANTICS"
--  mitre_attack_id:
--    - "T1562.001"
--  kill_chain_phases:
--    - "Defense Evasion"
--  security_domain: "endpoint"
--  asset_type: "Endpoint"

source:alerts (signature_id:(*Unhooking* *Tampering*) OR signature:(*API Unhooking* *Memory Patching* *Defense Evasion*)) process.name:outlook.exe object:*ntdll.dll*
| groupby host, user, process.name, object, signature, signature_id, vendor_product
```

### Environmental Keying Evasion
---
```sql
-- references:
--  - "NCSC Malware Analysis Report: AUTHENTIC ANTICS"

-- tags:
--  analytic_story:
--    - "AUTHENTIC ANTICS"
--  mitre_attack_id:
--    - "T1480.001"
--  kill_chain_phases:
--    - "Defense Evasion"
--  security_domain: "endpoint"
--  asset_type: "Endpoint"

source:registry process.name:outlook.exe registry.path:*\\Microsoft\\Cryptography\\MachineGuid
| groupby host, user, process.name, registry.path
```

### Stealthy Email Exfiltration
---
```sql
-- references:
--   - "NCSC Malware Analysis Report: AUTHENTIC ANTICS"

-- tags:
--  analytic_story:
--    - "AUTHENTIC ANTICS"
--  mitre_attack_id:
--    - "T1567"
--  kill_chain_phases:
--    - "Exfiltration"
--  security_domain: "network"
--  asset_type: "Network"

source:web http.method:POST url:https://outlook.office.com/api/v2.0/me/sendMail form_data:*\"SaveToSentItems\": \"false\"*
| groupby host, user, src.ip, url, form_data
```

### Registry-Based Execution Control
---
```sql
-- references:
--   - "NCSC Malware Analysis Report: AUTHENTIC ANTICS"

-- tags:
--  analytic_story:
--    - "AUTHENTIC ANTICS"
--  mitre_attack_id:
--    - "T1112"
--  kill_chain_phases:
--    - "Defense Evasion"
--  security_domain: "endpoint"
--  asset_type: "Endpoint"

source:registry registry.path:*\\Software\\Microsoft\\Office\\16.0\\Outlook\\Logging registry.value_name:Counter
| groupby host, user, process.name, registry.path, registry.value_name, registry.value_data
```