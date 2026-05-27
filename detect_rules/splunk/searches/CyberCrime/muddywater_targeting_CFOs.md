### APT MuddyWater Targets CFOs with Multi-Stage Phishing & NetBird Abuse
---

APT MuddyWater is actively targeting CFOs and finance executives globally through sophisticated multi-stage spear-phishing campaigns. These attacks leverage legitimate remote access tools like NetBird and OpenSSH for persistent control, alongside custom Firebase-hosted phishing pages and malicious VBScripts.

The campaign demonstrates an evolution in MuddyWater's tactics, including a shift in C2 infrastructure from 192.3.95.152 to 198.46.178.135, and the use of varying payload paths within Firebase/Web App projects to evade detection. Additionally, the group continues to abuse legitimate RMM tools like Atera Agent, with increased activity noted since October 2023, often registering agents with compromised email accounts.

### Actionable Threat Data
---

Monitor for spear-phishing emails impersonating recruiters (e.g., Rothschild & Co) that contain links to Firebase-hosted domains (e.g., googl-6c11f.firebaseapp[.]com, googl-165a0.web[.]app, cloud-ed980.firebaseapp[.]com, cloud-233f9.firebaseapp[.]com).

Detect the download and execution of ZIP archives (e.g., F-144822.zip, Rothschild_&_Co-6745763.zip) containing VBScript files (e.g., F-144822.vbs, cis.vbs) from suspicious URLs, particularly those hosted on 198.46.178[.]135.

Look for the silent installation of legitimate remote access tools like NetBird and OpenSSH, especially when initiated by VBScripts or PowerShell, and the creation of hidden local administrator accounts with default credentials such as user / Bs@202122.

Identify the creation of scheduled tasks designed to ensure persistence for NetBird or other remote access tools, and modifications to registry keys to hide user accounts or enable RDP.

Monitor network traffic for connections to known MuddyWater C2 infrastructure, including 198.46.178[.]135 and 192[.]3.95.152, and be alert for traffic to domains like my-sharepoint-inc[.]com, my1cloudlive[.]com, my2cloudlive[.]com, and web-16fe[.]app.

### Combined Analysis Search
---
```sql
-- Name: MuddyWater Campaign - NetBird and VBScript Activity
-- Author: RW
-- Date: 2025-08-21
-- Description: This rule detects TTPs and IOCs associated with a MuddyWater campaign targeting CFOs. The campaign involves multi-stage phishing, VBScript downloaders, and the abuse of legitimate tools like NetBird and OpenSSH for persistence.
-- False Positive Sensitivity: Medium
-- References: https://hunt.io/blog/apt-muddywater-deploys-multi-stage-phishing-to-target-cfos

(index=* sourcetype IN (
    "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "WinEventLog:Microsoft-Windows-Sysmon/Operational",
    "stream:http",
    "stream:dns",
    "pan:traffic",
    "suricata"
    )
)
(
    `-- IOC: Malicious Hashes`
    (md5 IN ("23dda825f91be93f5de415886f17ad4a", "5325de5231458543349152f0ea1cc3df", "0aa883cd659ef9957fded2516b70c341", "7ddc947ce8999c8a4a36ac170dcd7505", "2cddc7a31ea289e8c1e5469f094e975a", "f359f20dbd4b1cb578d521052a1b0e9f") OR file_hash IN ("23dda825f91be93f5de415886f17ad4a", "5325de5231458543349152f0ea1cc3df", "0aa883cd659ef9957fded2516b70c341", "7ddc947ce8999c8a4a36ac170dcd7505", "2cddc7a31ea289e8c1e5469f094e975a", "f359f20dbd4b1cb578d521052a1b0e9f"))
)
OR
(
    `-- IOC: C2 Network Connections`
    (dest_ip IN ("192.3.95.152", "198.46.178.135") OR dest IN ("192.3.95.152", "198.46.178.135"))
    OR
    (dest_host IN ("googl-6c11f.firebaseapp.com", "googl-6c11f.web.app", "googl-165a0.web.app", "cloud-ed980.firebaseapp.com", "cloud-ed980.web.app", "cloud-233f9.firebaseapp.com", "cloud-233f9.web.app", "my1cloudlive.com", "my2cloudlive.com", "web-16fe.app", "my-sharepoint-inc.com") OR query IN ("googl-6c11f.firebaseapp.com", "googl-6c11f.web.app", "googl-165a0.web.app", "cloud-ed980.firebaseapp.com", "cloud-ed980.web.app", "cloud-233f9.firebaseapp.com", "cloud-233f9.web.app", "my1cloudlive.com", "my2cloudlive.com", "web-16fe.app", "my-sharepoint-inc.com") OR url IN ("*googl-6c11f.firebaseapp.com*", "*googl-6c11f.web.app*", "*googl-165a0.web.app*", "*cloud-ed980.firebaseapp.com*", "*cloud-ed980.web.app*", "*cloud-233f9.firebaseapp.com*", "*cloud-233f9.web.app*", "*my1cloudlive.com*", "*my2cloudlive.com*", "*web-16fe.app*", "*my-sharepoint-inc.com*"))
)
OR
(
    `-- TTP: VBScript downloader creating a second stage payload (Sysmon EventCode 11)`
    (EventCode=11 (ParentImage="*\\wscript.exe" OR ParentImage="*\\cscript.exe") TargetFilename="C:\\bin\\*.vbs")
)
OR
(
    `-- TTP: Creation of the specific hidden admin user (Sysmon EventCode 1)`
    (EventCode=1 (Image="*\\net.exe" OR Image="*\\net1.exe") CommandLine="*user*user*Bs@202122*/add*")
)
OR
(
    `-- TTP: Adding user to local admin group (Sysmon EventCode 1)`
    (EventCode=1 (Image="*\\net.exe" OR Image="*\\net1.exe") CommandLine="*localgroup*user*/add*" (CommandLine="*Administrators*" OR CommandLine="*Administrateurs*"))
)
OR
(
    `-- TTP: Registry modification to hide the user account (Sysmon EventCode 12, 13)`
    (EventCode IN (12,13) TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\\user")
)
OR
(
    `-- TTP: Silent installation of NetBird or OpenSSH (Sysmon EventCode 1)`
    (EventCode=1 Image="*\\msiexec.exe" (CommandLine="*netbird.msi*" OR CommandLine="*OpenSSH.msi*") (CommandLine="*/qn*" OR CommandLine="*/quiet*" OR CommandLine="*/norestart*"))
)
OR
(
    `-- TTP: NetBird execution with the specific setup key (Sysmon EventCode 1)`
    (EventCode=1 Image="*\\netbird.exe" CommandLine="*E48E4A70-4CF4-4A77-946B-C8E50A60855A*")
)
OR
(
    `-- TTP: Persistence via scheduled tasks for NetBird (Sysmon EventCode 1)`
    (EventCode=1 Image="*\\schtasks.exe" CommandLine="*/create*" (CommandLine="*Start Netbird*" OR CommandLine="*ForceNetbirdRestart*") CommandLine="*net start netbird*")
)
OR
(
    `-- TTP: RDP being enabled via registry key modification (Sysmon EventCode 13)`
    (EventCode=13 TargetObject="*\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections" Details="DWORD (0x00000000)")
)
`-- Macro for filtering FPs. Can be customized with known good processes, users, etc.`
| `muddywater_campaign_netbird_and_vbscript_activity_filter`
`-- Categorize the type of activity found`
| eval activity = case(
    (isnotnull(md5) OR isnotnull(file_hash)), "Malicious File Detected by Hash",
    (isnotnull(dest_ip) OR isnotnull(dest) OR isnotnull(dest_host) OR isnotnull(query) OR isnotnull(url)), "C2 Network Connection Detected",
    (EventCode=11 AND (match(ParentImage, "wscript.exe$") OR match(ParentImage, "cscript.exe$")) AND match(TargetFilename, "C:\\\\bin\\\\.*\\.vbs")), "VBScript Downloader Detected",
    (EventCode=1 AND (match(Image, "net.exe$") OR match(Image, "net1.exe$")) AND like(CommandLine, "%user%user%Bs@202122%/add%")), "Hidden Admin Account Creation",
    (EventCode=1 AND (match(Image, "net.exe$") OR match(Image, "net1.exe$")) AND like(CommandLine, "%localgroup%user%/add%") AND (like(CommandLine, "%Administrators%") OR like(CommandLine, "%Administrateurs%"))), "User Added to Admin Group",
    (EventCode IN (12,13) AND like(TargetObject, "%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\\user")), "Hidden User Account via Registry",
    (EventCode=1 AND match(Image, "msiexec.exe$") AND (like(CommandLine, "%netbird.msi%") OR like(CommandLine, "%OpenSSH.msi%")) AND (like(CommandLine, "%/qn%") OR like(CommandLine, "%/quiet%") OR like(CommandLine, "%/norestart%"))), "Silent MSI Install of NetBird/OpenSSH",
    (EventCode=1 AND match(Image, "netbird.exe$") AND like(CommandLine, "%E48E4A70-4CF4-4A77-946B-C8E50A60855A%")), "NetBird Execution with Campaign Key",
    (EventCode=1 AND match(Image, "schtasks.exe$") AND like(CommandLine, "%/create%") AND (like(CommandLine, "%Start Netbird%") OR like(CommandLine, "%ForceNetbirdRestart%")) AND like(CommandLine, "%net start netbird%")), "NetBird Persistence via Scheduled Task",
    (EventCode=13 AND like(TargetObject, "%\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections") AND Details="DWORD (0x00000000)"), "RDP Enabled via Registry",
    1=1, "Unknown MuddyWater Activity"
)
`-- Table of notable fields for investigation`
| table _time, host, user, activity, Image, CommandLine, ParentImage, TargetFilename, TargetObject, Details, md5, file_hash, dest, dest_ip, dest_host, url, query
```