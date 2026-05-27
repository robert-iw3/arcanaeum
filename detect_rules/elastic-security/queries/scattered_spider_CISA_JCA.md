### Scattered Spider Threat intelligence Report
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
from *
| where event.category == "process" and event.type == "start"
  and process.name in (
    "AnyDesk.exe",
    "TeamViewer.exe",
    "ngrok.exe",
    "TacticalRMM.exe",
    "tailscale.exe",
    "tailscaled.exe",
    "tsh.exe"
  ) or process.name like "Splashtop%"
     or process.name like "ScreenConnect.Client%"
     or process.name like "ConnectWiseControl.Client%"
     or process.name like "Pulseway%"
     or process.name like "level%"
     or process.name like "fleetdeck%"
  and not user.name in ("admin_user1", "admin_user2") // Replace with your authorized users
  and not process.parent.name in ("legitimate_parent1.exe", "legitimate_parent2.exe") // Replace with your authorized parent processes
| stats
    count = COUNT(*),
    firstTime = Min(@timestamp),
    lastTime = MAX(@timestamp)
  by
    host.name,
    user.name,
    process.parent.name,
    process.name,
    process.command_line
| eval
    firstTime = TO_STRinG(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
    lastTime = TO_STRinG(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| keep
    host.name,
    user.name,
    process.parent.name,
    process.name,
    process.command_line,
    count,
    firstTime,
    lastTime
```

### MFA Fatigue/SIM Swap Attempts
---
```sql
from *
| where event.category == "authentication"
  and event.type in ("authentication_success", "authentication_failure")
  and user.name IS not NULL
  and user.name != "-"
  and user.name != "unknown"
| eval
    action = CASE(
      event.outcome == "success", "success",
      event.outcome == "failure", "failure",
      NULL
    )
| stats
    failure_count = SUM(CASE(action == "failure", 1, 0)),
    success_count = SUM(CASE(action == "success", 1, 0)),
    src = COLLECT(source.ip),
    app = COLLECT(process.name),
    firstTime = Min(@timestamp),
    lastTime = MAX(@timestamp)
  by
    user.name,
    BUCKET(@timestamp, 15 minutes)
| where failure_count > 10 and success_count > 0
| eval
    firstTime = TO_STRinG(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
    lastTime = TO_STRinG(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| keep
    user.name,
    failure_count,
    success_count,
    src,
    app,
    firstTime,
    lastTime
```

### Cloud Data Exfiltration
---
```sql
from *
| where event.category == "network"
  and event.type == "connection"
  and network.direction == "outbound"
| where destination.domain like "%mega.nz"
     or destination.domain like "%s3.amazonaws.com"
     or destination.domain like "%.snowflakecomputing.com"
| stats
    total_bytes_out = SUM(network.bytes),
    firstTime = Min(@timestamp),
    lastTime = MAX(@timestamp)
  by
    source.ip,
    user.name,
    destination.domain,
    BUCKET(@timestamp, 1 hour)
| eval
    total_gb_out = ROUND(total_bytes_out / 1024 / 1024 / 1024, 2),
    firstTime = TO_STRinG(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
    lastTime = TO_STRinG(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| where total_gb_out > 1
| keep
    source.ip,
    user.name,
    destination.domain,
    total_bytes_out,
    total_gb_out,
    firstTime,
    lastTime
```

### New User Identity Creation
---
```sql
from *
| where event.category == "iam"
  and event.action == "user-account-creation"
| stats
    count = COUNT(*),
    firstTime = Min(@timestamp),
    lastTime = MAX(@timestamp)
  by
    user.name,
    host.name,
    user.target.name
| where not (
    user.name in ("admin_user1", "admin_user2") or // Replace with your authorized users
    host.name in ("dc1.example.com", "hr_system.example.com") // Replace with your authorized systems
  )
| eval
    firstTime = TO_STRinG(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
    lastTime = TO_STRinG(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| keep
    user.name AS creating_user,
    host.name AS source_system,
    user.target.name AS new_user_created,
    count,
    firstTime,
    lastTime
```

### RattyRAT Malware Activity
---
```sql
from *
| where event.category == "process"
  and event.type == "start"
  and process.name in ("java.exe", "javaw.exe")
  and process.command_line like "*-jar*"
  and process.command_line like "*ratty*.jar"
| stats
    count = COUNT(*),
    firstTime = Min(@timestamp),
    lastTime = MAX(@timestamp)
  by
    host.name,
    user.name,
    process.parent.name,
    process.name,
    process.command_line
| eval
    firstTime = TO_STRinG(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
    lastTime = TO_STRinG(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| keep
    host.name,
    user.name,
    process.parent.name,
    process.name,
    process.command_line,
    count,
    firstTime,
    lastTime
```

### DragonForce Ransomware Deployment
---
```sql
from *
| where event.category == "process"
  and event.type == "start"
  and (host.os.name == "VMware ESXi" or host.name like "%esxi%")
  and process.name == "esxcli"
  and process.command_line like "*vm process kill*"
| stats
    count = COUNT(*),
    firstTime = Min(@timestamp),
    lastTime = MAX(@timestamp)
  by
    host.name,
    user.name,
    process.parent.name,
    process.name,
    process.command_line
| eval
    firstTime = TO_STRinG(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
    lastTime = TO_STRinG(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| keep
    host.name,
    user.name,
    process.parent.name,
    process.name,
    process.command_line,
    count,
    firstTime,
    lastTime
```