### Scattered Spider Threat Intelligence Report
---

Scattered Spider is a sophisticated, financially motivated cybercriminal group known for its advanced social engineering tactics, primarily targeting large organizations and their IT help desks for data extortion and ransomware deployment. Recent updates indicate an evolution in their TTPs, including more refined social engineering, the use of new malware variants like RattyRAT and DragonForce ransomware, and a focus on exfiltrating data from cloud data platforms like Snowflake.

Scattered Spider has recently incorporated DragonForce ransomware into their operations, alongside their usual data exfiltration for extortion, and is actively targeting cloud data platforms like Snowflake for rapid, large-volume data exfiltration. They have also refined their social engineering to pose as employees to trick IT/helpdesk staff into providing sensitive information or transferring MFA to their devices, and are using new legitimate tools like AnyDesk and Teleport.sh, and new malware like RattyRAT.

### Actionable Threat Data
---

Monitor for suspicious activity related to remote access tools (e.g., AnyDesk, Teleport.sh, TeamViewer, Splashtop, ScreenConnect, Pulseway, Level.io, Fleetdeck.io, Ngrok, Tactical.RMM, Tailscale) being installed or executed, especially from unusual user accounts or outside of approved IT processes.

Implement robust logging and alerting for MFA fatigue attacks (repeated MFA notification prompts) and SIM swap attempts, as these are primary initial access
vectors for Scattered Spider.

Detect and investigate attempts to access or exfiltrate data from cloud storage services (e.g., Amazon S3, MEGA[.]NZ) and cloud data platforms like Snowflake, particularly when originating from newly created or suspicious accounts.

Look for the creation of new user identities or social media profiles within your environment, as Scattered Spider uses these for persistence and to backstop newly created identities.

Monitor for the presence and activity of new malware variants like RattyRAT (Java-based remote access trojan) and indicators of DragonForce ransomware deployment, especially on VMware ESXi servers.

### Suspicious Remote Access Tool Usage
---
```sql
// Detects execution of legitimate remote access tools associated with Scattered Spider for initial access, persistence, and lateral movement
ProcessName IN ("AnyDesk.exe", "TeamViewer.exe", "ngrok.exe", "TacticalRMM.exe", "tailscale.exe", "tailscaled.exe", "tsh.exe")
OR ProcessName LIKE "Splashtop%"
OR ProcessName LIKE "ScreenConnect.Client%"
OR ProcessName LIKE "ConnectWiseControl.Client%"
OR ProcessName LIKE "Pulseway%"
OR ProcessName LIKE "level%"
OR ProcessName LIKE "fleetdeck%"
| SELECT
    AgentName AS host_name,
    User AS user_name,
    ParentProcessName AS parent_process_name,
    ProcessName AS process_name,
    ProcessCmd AS process_command_line,
    COUNT(*) AS count,
    MIN(EventTime) AS firstTime,
    MAX(EventTime) AS lastTime
| GROUP BY
    AgentName,
    User,
    ParentProcessName,
    ProcessName,
    ProcessCmd
| WHERE NOT (
    User IN ("admin_user1", "admin_user2") OR // Replace with authorized users
    ParentProcessName IN ("legitimate_parent1.exe", "legitimate_parent2.exe") // Replace with authorized parent processes
)
| FORMAT
    firstTime = DATETIME(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
    lastTime = DATETIME(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
```

### MFA Fatigue/SIM Swap Attempts
---
```sql
// Detects MFA fatigue or push spamming with high MFA failure counts followed by a success, a TTP of Scattered Spider (T1621)
EventType IN ("Authentication Success", "Authentication Failure")
AND User IS NOT NULL
AND User != "-"
AND User != "unknown"
| SELECT
    User AS user_name,
    SUM(CASE(EventType = "Authentication Failure", 1, 0)) AS failure_count,
    SUM(CASE(EventType = "Authentication Success", 1, 0)) AS success_count,
    COLLECT(SrcIP) AS src,
    COLLECT(ProcessName) AS app,
    MIN(EventTime) AS firstTime,
    MAX(EventTime) AS lastTime
| GROUP BY
    User,
    INTERVAL(EventTime, "15m")
| WHERE failure_count > 10 AND success_count > 0
| FORMAT
    firstTime = DATETIME(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
    lastTime = DATETIME(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
```

### Cloud Data Exfiltration
---
```sql
// Detects large-scale data exfiltration to known cloud storage platforms (e.g., Mega, AWS S3, Snowflake) used by Scattered Spider
NetworkDirection = "outbound"
AND NetworkDstDomain LIKE "%mega.nz"
   OR NetworkDstDomain LIKE "%s3.amazonaws.com"
   OR NetworkDstDomain LIKE "%.snowflakecomputing.com"
| SELECT
    AgentName AS source_ip,
    User AS user_name,
    NetworkDstDomain AS destination_domain,
    SUM(NetworkBytesOut) AS total_bytes_out,
    ROUND(SUM(NetworkBytesOut) / 1024 / 1024 / 1024, 2) AS total_gb_out,
    MIN(EventTime) AS firstTime,
    MAX(EventTime) AS lastTime
| GROUP BY
    AgentName,
    User,
    NetworkDstDomain,
    INTERVAL(EventTime, "1h")
| WHERE total_gb_out > 1
| FORMAT
    firstTime = DATETIME(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
    lastTime = DATETIME(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
```

### New User Identity Creation
---
```sql
// Detects creation of new user accounts by unauthorized users or systems, indicative of persistence (T1136) by Scattered Spider
AgentOS IN ("Windows", "Linux")
AND EventType = "User Account Created"
| SELECT
    AgentName AS source_system,
    User AS creating_user,
    TargetUser AS new_user_created,
    COUNT(*) AS count,
    MIN(EventTime) AS firstTime,
    MAX(EventTime) AS lastTime
| GROUP BY
    AgentName,
    User,
    TargetUser
| WHERE NOT (
    User IN ("admin_user1", "admin_user2") OR // Replace with authorized users
    AgentName IN ("dc1.example.com", "hr_system.example.com") // Replace with authorized systems
)
| FORMAT
    firstTime = DATETIME(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
    lastTime = DATETIME(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
```

### RattyRAT Malware Activity
---
```sql
// Detects execution of Java-based RattyRAT (jar files with 'ratty' in the name), used by Scattered Spider
ProcessName IN ("java.exe", "javaw.exe")
AND ProcessCmd LIKE "*-jar*"
AND ProcessCmd LIKE "*ratty*.jar"
| SELECT
    AgentName AS host_name,
    User AS user_name,
    ParentProcessName AS parent_process_name,
    ProcessName AS process_name,
    ProcessCmd AS process_command_line,
    COUNT(*) AS count,
    MIN(EventTime) AS firstTime,
    MAX(EventTime) AS lastTime
| GROUP BY
    AgentName,
    User,
    ParentProcessName,
    ProcessName,
    ProcessCmd
| FORMAT
    firstTime = DATETIME(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
    lastTime = DATETIME(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
```

### DragonForce Ransomware Deployment
---
```sql
AgentOS = "VMware ESXi" OR AgentName LIKE "%esxi%"
AND ProcessName = "esxcli"
AND ProcessCmd LIKE "%vm process kill%"
| SELECT
    AgentName AS host_name,
    User AS user_name,
    ParentProcessName AS parent_process_name,
    ProcessName AS process_name,
    ProcessCmd AS process_command_line,
    COUNT(*) AS count,
    MIN(EventTime) AS firstTime,
    MAX(EventTime) AS lastTime
| GROUP BY
    AgentName,
    User,
    ParentProcessName,
    ProcessName,
    ProcessCmd
| FORMAT
    firstTime = DATETIME(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
    lastTime = DATETIME(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
```