## Miscellaneous Custom Detection Rules for Datadog

https://docs.datadoghq.com/security/detection_rules/#create-detection-rules

### Create the Detection Rules in Datadog
---
https://docs.datadoghq.com/security/cloud_siem/detection_rules/signal_correlation_rules/#create-a-signal-correlation-rule

To implement the provided signal correlation rules in the Datadog UI, follow these steps using the example:

  Navigate to Detection Rules:

    In the Datadog app, go to Security > Detection Rules.

    Click + New Rule and select Signal Correlation as the rule type.

  Configure Rule Cases:

    For each case in the YAML (e.g., SQLi Authentication Bypass, Time-Based Blind SQLi, etc.), create a corresponding rule case in the UI.

    Select or define the rule query using Datadog’s search syntax (e.g., @event.outcome:(0 OR success OR allow OR accepted) AND @user.name:(*'\\ or\\ * OR *'or'--* OR *\\ or\\ 1=1* OR *admin'--*) for SQLi Authentication Bypass).

    Use the pencil icon to rename each case to match the detection type (e.g., SQLi Authentication Bypass).

    Set the severity for each case (e.g., high for Authentication Bypass, medium for Time-Based Blind).

  Define Correlation Logic:

    Use the correlated by dropdown to select grouping fields (e.g., @host, @user.name, @destination.ip for SQLi; @host, @kubernetes.audit.user.username, @container.image.name for Container Security).

    Set the evaluation window (e.g., 1h as specified in the YAML) to evaluate cases in real time. Ensure the evaluation window is less than or equal to the keep-alive and maximum signal duration.

  Add Tags and Notifications:

    In the Tag resulting signals dropdown, add tags like security:attack or technique:T1110-brute-force as recommended. For example, for SQLi, use security:attack; for Container Security, use security:anomaly or security:attack.

    In the Rule message section, use Markdown and template variables (e.g., {@client.ip}, {@user.name}) to customize notifications, mirroring the message format in the YAML (e.g., "SQLi Attempt: {distinct_count} type(s) from source {@client.ip} by user {@user.name} to destination {@destination.ip}: {case_names}").

  Order Rule Cases:

    Drag and drop rule cases in the UI to prioritize evaluation (e.g., higher-severity cases like Authentication Bypass first). Rule cases are evaluated as case statements, and the first matching case generates the signal.

  Save and Test:

    Save the rule and use the Log Explorer to verify that the queries return expected results, reducing false positives.

    Test the rule by generating sample logs or events that match the conditions to ensure signals are triggered correctly.

Example for SQLi Rule

  For the SQLi Detection rule:

    Create a signal correlation rule with five cases, each corresponding to a detection type (e.g., SQLi Authentication Bypass, Time-Based Blind SQLi).

    Input queries like @event.outcome:(0 OR success OR allow OR accepted) AND @user.name:(*'\\ or\\ * OR *'or'--* OR *\\ or\\ 1=1* OR *admin'--*) for the first case.

    Group by @host, @user.name, @destination.ip.

    Set tags like security:attack and a notification message like "SQLi Attempt: {distinct_count} type(s) from source {@client.ip} by user {@user.name} to destination {@destination.ip}: {case_names}".

    Set the evaluation window to 1h.

Example for Container Security Rule

  For the Container Security rule:

    Create cases for each detection (e.g., High/Critical Vulnerabilities, Privileged Containers).

    Use queries like @vulnerability.severity:(High OR Critical) or @kubernetes.pod.security_context.privileged:true -@kubernetes.audit.user.username:(system:masters OR cluster-admin OR azure-operator).

    Group by @host, @kubernetes.audit.user.username, @container.image.name.

    Add tags like security:anomaly and a message like "Container Threat: {distinct_count} type(s) on host {@host} involving entity {@container.image.name or @kubernetes.audit.user.username}: {case_names}".

### API-Based Import Using Curl With JSON Formatted Rule
---

```bash
curl -X POST "https://api.<DATADOG_SITE>/api/v2/security_monitoring/rules" \
-H "Content-type: application/json" \
-H "DD-API-KEY: <DATADOG_API_KEY>" \
-H "DD-APPLICATION-KEY: <DATADOG_APP_KEY>" \
-d '{
  "data": {
    "type": "signal_correlation",
    "attributes": {
      "name": "Combined SQL Injection Detection",
      "enabled": true,
      "cases": [
        {
          "name": "SQLi Authentication Bypass",
          "status": "high",
          "query": "@event.outcome:(0 OR success OR allow OR accepted) AND @user.name:(*'\\ or\\ * OR *'or'--* OR *\\ or\\ 1=1* OR *admin'--*)"
        },
        // Add other cases
      ],
      "group_by_fields": ["@host", "@user.name", "@destination.ip"],
      "message": "SQLi Attempt: {distinct_count} type(s) from source {@client.ip} by user {@user.name} to destination {@destination.ip}: {case_names}",
      "tags": ["security:attack"]
    }
  }
}'
```

### Example Using Python Datadog API Client
---

```bash
pip install datadog-api-client
```

```python
from datadog_api_client import ApiClient, Configuration
from datadog_api_client.v2.api.security_monitoring_api import SecurityMonitoringApi
from datadog_api_client.v2.model.security_monitoring_rule_create_payload import SecurityMonitoringRuleCreatePayload
from datadog_api_client.v2.model.security_monitoring_rule_case import SecurityMonitoringRuleCase
from datadog_api_client.v2.model.security_monitoring_rule_options import SecurityMonitoringRuleOptions
from datadog_api_client.v2.model.security_monitoring_rule_query import SecurityMonitoringRuleQuery
from datadog_api_client.v2.model.security_monitoring_rule_type_read import SecurityMonitoringRuleTypeRead

# Configure API key and Application key
configuration = Configuration()
configuration.api_key["apiKeyAuth"] = "<YOUR_DATADOG_API_KEY>"
configuration.api_key["appKeyAuth"] = "<YOUR_DATADOG_APPLICATION_KEY>"

# Create the case for the rule
sql_injection_case = SecurityMonitoringRuleCase(
    name="SQLi Authentication Bypass",
    status="high",
    # The query attribute is deprecated in favor of `conditions`.
    # It is recommended to use `conditions` for new rules.
    conditions=["@event.outcome:(0 OR success OR allow OR accepted) AND @user.name:(*'\\ or\\ * OR *'or'--* OR *\\ or\\ 1=1* OR *admin'--*)"]
)

# Create the options for the rule
correlation_options = SecurityMonitoringRuleOptions(
    # The group_by_fields from your JSON correspond to `correlation_attributes`
    correlation_attributes=["@host", "@user.name", "@destination.ip"],
    # Evaluation window, keep alive, and max duration are not defined in your JSON
    # so they are set to default values here.
    evaluation_window=900,  # 15 minutes
    keep_alive=3600,        # 1 hour
    max_signal_duration=3600 # 1 hour
)

# Define the overall payload for the correlation rule
body = SecurityMonitoringRuleCreatePayload(
    name="Combined SQL Injection Detection",
    is_enabled=True,
    message="SQLi Attempt: {distinct_count} type(s) from source {@client.ip} by user {@user.name} to destination {@destination.ip}: {case_names}",
    tags=["security:attack"],
    # For a correlation rule, `queries` must be provided, even if empty.
    queries=[
        SecurityMonitoringRuleQuery(
            query="* AND @tags.key:value", # This should be replaced with a valid query matching signals
            aggregation="count",
            data_source="signals"
        )
    ],
    cases=[sql_injection_case],
    options=correlation_options,
    type=SecurityMonitoringRuleTypeRead("correlation_rule")
)

# Initialize the API client and create the rule
with ApiClient(configuration) as api_client:
    api_instance = SecurityMonitoringApi(api_client)
    try:
        response = api_instance.create_security_monitoring_rule(body=body)
        print("Successfully created Security Monitoring Rule:")
        print(response)
    except Exception as e:
        print(f"Error creating rule: {e}")
```

### Malicious VSCode Extension Activity Detection
---

Author: RW

Date: 2025-08-20

Description:

This search combines multiple detection techniques for malicious Visual Studio Code extension activity. It looks for extension installation via URI handlers or the command line, suspicious network connections from VSCode, file writes to extension directories, and the loading of unusual Node modules. These activities can indicate an attacker using VSCode for initial access or persistence.

```yaml
name: Malicious VSCode Extension Activity
type: signal_correlation
cases:
  - name: VSCode URI Handler Installation
    status: high
    query: "@process.name:Code.exe AND @process.cmdline:*--open-url* AND @process.cmdline:*vscode://*"
  - name: VSCode Extension CLI Installation
    status: high
    query: "@process.name:Code.exe AND @process.cmdline:*--install-extension* AND @process.cmdline:*.vsix*"
  - name: Suspicious Outbound Connection from VSCode
    status: medium
    query: "@process.name:Code.exe AND @url:* -@url:(*marketplace.visualstudio.com* OR *vscode.blob.core.windows.net* OR *update.code.visualstudio.com* OR *gallerycdn.vsassets.io*)"
  - name: File Write to VSCode Extension Directory
    status: medium
    query: "@file.path:(*\\.vscode\\extensions\\* OR *\\Microsoft\\ VS\\ Code\\resources\\app\\extensions\\*)"
  - name: Suspicious Node Module Loaded by VSCode
    status: high
    query: "@process.name:Code.exe AND @dll.name:*.node AND (@dll.path:*\\AppData\\Local* OR @dll.path:*\\Temp*) -@dll.path:(*\\.vscode\\extensions* OR *Microsoft\\ VS\\ Code*)"
signal_correlation:
  rule_id: vscode_malicious_correlation
  group_by_fields:
    - @host
    - @usr
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "Malicious VSCode Activity: {distinct_count} method(s) on host {@host} by user {@usr}: {case_names}"
severity: high
```

### Salty 2FA Phishing Campaign
---

description:

Detects various web-based indicators of the Salty 2FA phishing kit. This rule identifies the unique landing page domain structure, Cloudflare evasion, anti-analysis techniques, and the specific data exfiltration pattern.

author: RW

date: 2025-08-20

references:
  - https://any.run/cybersecurity-blog/salty2fa-technical-analysis/

tags:
  - attack.initial_access
  - attack.t1566
  - attack.exfiltration
  - attack.t1041
  - attack.defense_evasion
  - attack.t1622
  - threat_actor.storm-1575
  - phishing.salty_2fa

falsepositives:
  - The data exfiltration pattern is highly specific and has a low probability of false positives.
  - The landing page detection may trigger on legitimate services that use a similar domain structure and integrate both Cloudflare and Microsoft authentication, although the combination of indicators reduces this risk. Consider creating an allowlist for known good domains.

level: high

```yaml
name: Salty 2FA Phishing Kit Detection
type: signal_correlation
cases:
  - name: Salty 2FA Exfiltration
    status: high
    query: "@http.method:POST AND @network.destination.domain:*.ru AND @url.path:*/[0-9]{5,6}.php AND @http.request.body:(*request=%* AND *session=*)"
  - name: Salty 2FA Landing Page
    status: medium
    query: "@network.destination.domain:*.[a-z]{2}.com AND ((@http.response.body:*challenges.cloudflare.com/turnstile/* AND @http.response.body:*Microsoft* AND @http.response.body:*Sign\\ in*) OR (@http.response.body:*new\\ Date()* AND @http.response.body:*debugger*))"
signal_correlation:
  rule_id: salty_2fa_correlation
  group_by_fields:
    - @src
    - @dest
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "Salty 2FA Phishing: {distinct_count} type(s) from src {@src} to dest {@dest}"
severity: high
```

### QuirkyLoader Malware Activity
---

Description:

This rule detects potential QuirkyLoader malware activity by searching for a combination of behavioral and indicator-based threats identified by IBM X-Force. It looks for specific processes targeted for hollowing, known malicious file hashes (SHA256), and network connections to known command-and-control (C2) infrastructure.

Author: RW

Date: 2025-08-20

References:
- https://www.ibm.com/think/x-force/ibm-x-force-threat-analysis-quirkyloader

False Positive Sensitivity: Medium
The processes targeted for hollowing (AddInProcess32.exe, InstallUtil.exe, aspnet_wp.exe) are legitimate Microsoft .NET components. Benign execution is common, especially in development environments. If false positives occur, consider filtering by parent process or command-line arguments.

Tactic(s): Execution, Defense Evasion

Technique(s): Process Hollowing (T1055.012), DLL Side-Loading (T1574.001)

```yaml
name: QuirkyLoader Malware Activity
type: signal_correlation
cases:
  - name: Process Hollowing Targets
    status: medium
    query: "@process.name:(AddInProcess32.exe OR InstallUtil.exe OR aspnet_wp.exe)"
  - name: Known Malicious File Hashes
    status: high
    query: "@file.hash:(011257eb766f253982b717b390fc36eb570473ed7805c18b101367c68af5 OR 0ea3a55141405ee0e2dfbf333de01fe93c12cf34555550e4f7bb3fdec2a7673b OR /* list all */)"
  - name: Known Malicious Domains
    status: high
    query: "@dns.query:(catherinereynolds.info OR mail.catherinereynolds.info)"
  - name: Known Malicious IPs
    status: high
    query: "@network.destination.ip:(157.66.22.11 OR 103.75.77.90 OR 161.248.178.212)"
signal_correlation:
  rule_id: quirkyloader_correlation
  group_by_fields:
    - @host
    - @usr
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "QuirkyLoader Activity: {distinct_count} indicator(s) on host {@host} by user {@usr}: {case_names}"
severity: high
```

### PipeMagic Backdoor Activity
---

Description:

Detects various Tactics, Techniques, and Procedures (TTPs) associated with the PipeMagic backdoor framework used by the Storm-2460 threat actor.

Author: RW

Date: 2025-08-20

Tactic: TA0002, TA0005, TA0006, TA0011

Technique: T1059, T1218.010, T1140, T1003.001, T1071.001, T1055

False Positives: Legitimate use of certutil for file downloads, though the combination of arguments is suspicious. 'dllhost.exe' accessing 'lsass.exe' can be legitimate; requires investigation of parent process context. The named pipe pattern could potentially collide with legitimate software.

References:
- https://www.microsoft.com/en-us/security/blog/2025/08/18/dissecting-pipemagic-inside-the-architecture-of-a-modular-backdoor-framework/
- https://securelist.com/pipemagic/117270/

```yaml
name: PipeMagic Backdoor Activity
type: signal_correlation
cases:
  - name: PipeMagic File Hash IOC
    status: high
    query: "@file.hash:(dc54117b965674bad3d7cd203ecf5e7fc822423a3f692895cf5e96e83fb88f6a OR 4843429e2e8871847bc1e97a0f12fa1f4166baa4735dff585cb3b4736e3fe49e OR 297ea881aa2b39461997baf75d83b390f2c36a9a0a4815c81b5cf8be42840fd1)"
  - name: PipeMagic Named Pipe
    status: medium
    query: "@winlog.event_id:17 AND @winlog.event_data.PipeName:\\.\\pipe\\1\\.[0-9a-fA-F]{32}"
  - name: PipeMagic C2 Connection
    status: high
    query: "@winlog.event_id:3 AND (@network.destination.domain:aaaaabbbbbbb.eastus.cloudapp.azure.com OR @network.destination.ip:127.0.0.1) AND @network.destination.port:(443 OR 8082)"
  - name: PipeMagic C2 HTTP Pattern
    status: high
    query: "@url:*.*/[a-fA-F0-9]{16} AND @http.headers:(*Upgrade:\\ websocket* AND *Connection:\\ Upgrade*)"
  - name: PipeMagic Certutil Download
    status: medium
    query: "@winlog.event_id:1 AND @process.name:certutil.exe AND @process.cmdline:*-urlcache* AND @process.cmdline:*-f* AND (@process.cmdline:*.tmp* OR @process.cmdline:*.dat* OR @process.cmdline:*.msbuild*)"
  - name: PipeMagic MSBuild Execution
    status: medium
    query: "@winlog.event_id:1 AND @process.parent.name:msbuild.exe AND @process.cmdline:*.mshi*"
  - name: PipeMagic LSASS Access
    status: high
    query: "@winlog.event_id:10 AND @winlog.event_data.TargetImage:*\\lsass.exe AND @winlog.event_data.SourceImage:*\\dllhost.exe"
signal_correlation:
  rule_id: pipemagic_correlation
  group_by_fields:
    - @host
    - @usr
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "PipeMagic Activity: {distinct_count} clause(s) on host {@host} by user {@usr}: {case_names}"
severity: high
```

### ESXi Host Suspicious Activity Detection (Recon, Privilege Escalation, Exfil, Evasion)
---
```yaml
name: ESXi Host Suspicious Activity
type: signal_correlation
cases:
  - name: ESXi System Reconnaissance
    status: medium
    query: "@message:*esxcli\\ system* AND (@message:*\\ get* OR @message:*\\ list*) -@message:*filesystem*"
  - name: External Root Login to ESXi UI
    status: high
    query: "@message:*root*logged\\ in*"
  - name: User Granted Admin Role on ESXi
    status: high
    query: "@message:*esxcli\\ system\\ permission\\ set* AND @message:*role\\ Admin*"
  - name: VIB Acceptance Level Tampering
    status: medium
    query: "@message:*esxcli\\ software\\ acceptance\\ set*"
  - name: SSH Enabled on ESXi Host
    status: medium
    query: "@message:*SSH\\ access\\ has\\ been\\ enabled*"
  - name: ESXi Encryption Settings Modified
    status: high
    query: "@message:*system\\ settings\\ encryption\\ set* AND (@message:*--require-secure-boot=0* OR @message:*--require-exec-installed-only=0* OR @message:*execInstalledOnly=false*)"
  - name: VM Exported via Remote Tool
    status: high
    query: "@message:*File\\ download\\ from\\ path* AND @message:*was\\ initiated\\ from*"
  - name: ESXi Audit Tampering
    status: medium
    query: "@message:*esxcli\\ system\\ auditrecords*"
  - name: ESXi Syslog Tampering
    status: medium
    query: "@message:*syslog\\ config\\ set* AND @message:*esxcli* OR @message:*Set\\ called\\ with\\ key* AND (@message:*Syslog.global.logHost* OR @message:*Syslog.global.logdir*)"
  - name: ESXi System Clock Manipulation
    status: medium
    query: "@message:*NTPClock* AND @message:*system\\ clock\\ stepped*"
signal_correlation:
  rule_id: esxi_suspicious_correlation
  group_by_fields:
    - @host
    - @usr
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "ESXi Suspicious Activity: {distinct_count} tactic(s) on host {@host} by user {@usr}: {case_names}"
severity: high
```

### CastleBot MaaS Activity Detection: File Hashes, C2 IPs, User-Agent, Persistence
---

description:

Detects various indicators and behaviors associated with the CastleBot MaaS framework, including C2 communication, known file hashes, and persistence techniques.

references:
  - https://www.ibm.com/think/x-force/dissecting-castlebot-maas-operation

author: RW

date: 2025-08-22

tags:
  - attack.execution
  - attack.persistence
  - attack.command_and_control
  - attack.t1059
  - attack.t1218
  - attack.t1071.001
  - attack.t1543.003
  - malware.castlebot
  - malware.warmcookie
  - malware.netsupport
  - malware.rhadamanthys
  - malware.remcos
  - malware.deerstealer
  - malware.hijackloader
  - malware.monsterv2

```yaml
name: CastleBot MaaS Activity
type: signal_correlation
cases:
  - name: Known File Hashes
    status: high
    query: "@file.hash:(202f6b6631ade2c41e4762b5877ce0063a3beabce0c3f8564b6499a1164c1e04 OR /* list all */)"
  - name: Known C2 IPs/Domains
    status: high
    query: "@network.destination.ip:(173.44.141.89 OR 80.77.23.48 OR 62.60.226.73 OR 107.158.128.45 OR 170.130.165.112 OR 107.158.128.105) OR @url:(*mhousecreative.com* OR *google.herionhelpline.com* OR */service/* OR */c91252f9ab114f26.php)"
  - name: Suspicious User-Agent to C2 IPs
    status: high
    query: "@http.user_agent:*Googlebot* AND @network.destination.ip:(173.44.141.89 OR 80.77.23.48 OR 62.60.226.73 OR 107.158.128.45)"
  - name: Persistence via Scheduled Task
    status: medium
    query: "@process.name:schtasks.exe AND @process.cmdline:(*/create* AND */sc* AND *onlogon*)"
signal_correlation:
  rule_id: castlebot_correlation
  group_by_fields:
    - @host
    - @usr
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "CastleBot Activity: {distinct_count} indicator(s) on host {@host} by user {@usr}: {case_names}"
severity: high
```

### Quasar RAT Indicators: Process, File, and Network Activity
---
```yaml
name: Quasar RAT Indicators
type: signal_correlation
cases:
  - name: Known Quasar RAT Loader Hash
    status: high
    query: "@process.hash:7300535ef26158bdb916b717390fc36eb570473ed7805c18b101367c68af5"
  - name: Scheduled Task with Highest Privileges
    status: medium
    query: "@process.name:schtasks.exe AND @process.cmdline:(*/rl* AND *highest*)"
  - name: System Shutdown/Reboot Attempt
    status: medium
    query: "@process.name:shutdown.exe AND @process.cmdline:(*/s\\ /t\\ 0* OR */r\\ /t\\ 0*)"
  - name: Unusual FileZilla Config Access
    status: high
    query: "@file.path:(*\\FileZilla\\recentservers.xml OR *\\FileZilla\\sitemanager.xml) -@process.name:filezilla.exe"
  - name: Startup Folder URL Shortcut for Persistence
    status: medium
    query: "@file.path:*\\Microsoft\\Windows\\Start\\ Menu\\Programs\\Startup\\*.url AND @event.action:created"
  - name: Mark-of-the-Web Bypass
    status: high
    query: "@file.name:*:Zone.Identifier AND @event.action:deleted"
  - name: Network Reconnaissance via IP Check Service
    status: medium
    query: "@dns.query:(*wtfismyip.com OR *checkip.* OR *ipecho.net OR *ipinfo.io OR *api.ipify.org OR *icanhazip.com OR *ip.anysrc.com OR *api.ip.sb OR ident.me OR www.myexternalip.com OR *zen.spamhaus.org OR *cbl.abuseat.org OR *b.barracudacentral.org OR *dnsbl-1.uceprotect.net OR *spam.dnsbl.sorbs.net OR *iplogger.org* OR *ip-api.com* OR *geoip.* OR *icanhazip.* OR *ipwho.is* OR *ifconfig.me* OR *myip.com* OR *ipstack.com* OR *myexternalip.com* OR *ip-api.io* OR *trackip.net* OR *ipgeolocation.io* OR *ipfind.io* OR *freegeoip.app* OR *ipv4bot.whatismyipaddress.com* OR *hacker-target.com/iptools*)"
signal_correlation:
  rule_id: quasar_rat_correlation
  group_by_fields:
    - @host
    - @usr
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "Quasar RAT Activity: {distinct_count} indicator(s) on host {@host} by user {@usr}: {case_names}"
severity: high
```

### Kerberoasting, AS-REP Roasting, DCSync, and AD DACL Modifications
---
```yaml
name: Kerberoasting, AS-REP Roasting, DCSync, and AD DACL Modifications
type: signal_correlation
cases:
  - name: Potential Kerberoasting (RC4)
    status: high
    query: "@winlog.event_id:4769 AND @winlog.event_data.Status:0x0 AND @winlog.event_data.TicketEncryptionType:0x17 -@winlog.event_data.ServiceName:*$*"
  - name: Potential AS-REP Roasting
    status: high
    query: "@winlog.event_id:4768 AND @winlog.event_data.Status:0x0 AND @winlog.event_data.ServiceName:krbtgt AND @winlog.event_data.PreAuthType:0 -@winlog.event_data.TargetUserName:*$*"
  - name: Potential DCSync Attack
    status: high
    query: "@winlog.event_id:4662 AND @winlog.event_data.ObjectServer:DS AND @winlog.event_data.ObjectType:{19195a5b-6da0-11d0-afd3-00c04fd930c9} AND (@winlog.event_data.Properties:*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2* OR @winlog.event_data.Properties:*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*) -@winlog.event_data.SubjectUserName:*$*"
  - name: AdminSDHolder DACL Modification
    status: medium
    query: "@winlog.event_id:5136 AND @winlog.event_data.LDAPDisplayName:nTSecurityDescriptor AND @winlog.event_data.ObjectDN:*CN=AdminSDHolder,CN=System,* AND @winlog.event_data.SubjectUserSid:!S-1-5-18"
  - name: Malicious AD DACL Modification
    status: medium
    query: "@winlog.event_id:5136 AND @winlog.event_data.LDAPDisplayName:nTSecurityDescriptor AND (@winlog.event_data.Value:*(A;;GA;;* OR @winlog.event_data.Value:*(A;;WD;;* OR @winlog.event_data.Value:*(A;;WO;;*) AND @winlog.event_data.SubjectUserSid:!S-1-5-18"
signal_correlation:
  rule_id: ad_kerberos_attacks_correlation
  group_by_fields:
    - @host
    - @usr
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "AD Attacks: {distinct_count} type(s) on host {@host} by user {@usr}: {case_names}"
severity: high
```

### Silk Typhoon Threat Actor: Anomalous Activity, Exfiltration, Webshells & Exploits
---

Author: RW

Date: 2025-08-22

This is a composite query to detect multiple TTPs associated with the Silk Typhoon threat actor.
It combines searches for:

1. Anomalous Entra Connect Activity

2. Suspicious App/Service Principal creation

3. Potential Cloud Data Exfiltration

4. Web Shell execution

5. Known Vulnerabilities exploited by the actor

```yaml
name: Silk Typhoon Associated Activity
type: signal_correlation
cases:
  - name: Suspicious Interactive Logon by Entra Connect Account
    status: high
    query: "@user.name:(*AAD_* OR *MSOL_*) AND @event.category:signin"
  - name: Password Reset by Entra Connect Account
    status: high
    query: "@event.action:Reset\\ user\\ password AND @event.outcome:success AND @event.initiated_by.user.userPrincipalName:(*AAD_* OR *MSOL_*)"
  - name: Add service principal
    status: medium
    query: "@event.category:ApplicationManagement AND @event.action:Add\\ service\\ principal"
  - name: Add OAuth2 permission grant
    status: medium
    query: "@event.category:ApplicationManagement AND @event.action:Add\\ OAuth2\\ permission\\ grant"
  - name: Add owner to service principal
    status: medium
    query: "@event.category:ApplicationManagement AND @event.action:Add\\ owner\\ to\\ service\\ principal"
  - name: Update application - Certificates and secrets management
    status: medium
    query: "@event.category:ApplicationManagement AND @event.action:Update\\ application\\ -\\ Certificates\\ and\\ secrets\\ management"
  - name: Potential High-Volume Data Access
    status: high
    query: "@event.action:(MailItemsAccessed OR FileDownloaded)"
  - name: Potential Web Shell Execution
    status: high
    query: "@process.parent.name:(*\\w3wp.exe OR *\\httpd.exe OR *\\nginx.exe OR *\\tomcat*.exe) AND @process.name:(*\\cmd.exe OR *\\powershell.exe OR *\\pwsh.exe OR *\\sh OR *\\bash)"
  - name: Vulnerable Device Identified
    status: medium
    query: "@vulnerability.id:(CVE-2025-0282 OR CVE-2024-3400 OR CVE-2023-3519 OR CVE-2021-26855 OR CVE-2021-26857 OR CVE-2021-26858 OR CVE-2021-27065)"
signal_correlation:
  rule_id: silk_typhoon_correlation
  group_by_fields:
    - @host
    - @usr
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "Silk Typhoon Activity: {distinct_count} part(s) on host {@host} by user {@usr}: {case_names}"
severity: high
```

### CORNFLAKE.V3 Backdoor Activity Detection
---

RW

This rule is designed to detect a wide range of activities associated with the CORNFLAKE.V3 backdoor, as detailed in observed/disseminated threat intelligence.

It combines multiple detection patterns covering execution, persistence, command and control, and post-exploitation behavior into a single query.

```yaml
name: CORNFLAKE.V3 Backdoor Activity
type: signal_correlation
cases:
  - name: Execution: CORNFLAKE.V3 (Node.js/PHP) spawned from PowerShell
    status: high
    query: "@winlog.event_id:1 AND @process.parent.executable:*\\powershell.exe AND @process.executable:*\\AppData\\Roaming* AND ((@process.executable:*\\node.exe AND @process.cmdline:*-e\\ *) OR (@process.executable:*\\php.exe AND @process.cmdline:*-d\\ * AND @process.cmdline:*\\ 1))"
  - name: Post-Exploitation: CORNFLAKE process spawning shell for reconnaissance
    status: high
    query: "@winlog.event_id:1 AND @process.parent.executable:*\\AppData\\Roaming\\*(node|php).exe AND @process.executable:*\\(cmd|powershell).exe AND @process.cmdline:(*systeminfo* OR *tasklist* OR *arp\\ -a* OR *nltest* OR *setspn* OR *whoami\\ /all* OR *Get-LocalGroup* OR *KerberosRequestorSecurityToken*)"
  - name: Persistence: Registry Run Key points to CORNFLAKE in AppData
    status: medium
    query: "@winlog.event_id:(12 OR 13) AND @winlog.event_data.TargetObject:*HKU*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run AND @winlog.event_data.Details:*AppData\\Roaming\\*(node|php).exe*"
  - name: C2: Network connection to known CORNFLAKE infrastructure
    status: high
    query: "@winlog.event_id:3 AND (@network.destination.ip:(138.199.161.141 OR 159.69.3.151 OR 167.235.235.151 OR 128.140.120.188 OR 177.136.225.135) OR @network.destination.domain:(varying-rentals-calgary-predict.trycloudflare.com OR dnsmicrosoftds-data.com OR windows-msg-as.live))"
  - name: IOC: Known CORNFLAKE or WINDYTWIST file hash detected
    status: high
    query: "@winlog.event_id:(1 OR 11) AND @winlog.event_data.Hashes:*MD5=(04668c6f39b0a67c4bd73d5459f8c3a3 OR bcdffa955608e9463f272adca205c9e65592840d98dcb63155b9fa0324a88be2 OR ec82216a2b42114d23d59eecb876ccfc)*"
  - name: Initial Access: PowerShell/MSHTA downloading Node.js/PHP runtime
    status: medium
    query: "@winlog.event_id:3 AND @process.executable:(*\\powershell.exe OR *\\mshta.exe) AND @network.destination.domain:(nodejs.org OR windows.php.net)"
  - name: Execution: Rundll32 executing a .png file from AppData (WINDYTWIST.SEA)
    status: high
    query: "@winlog.event_id:1 AND @process.executable:*\\rundll32.exe AND @process.cmdline:*\\AppData\\Roaming\\*.png*"
signal_correlation:
  rule_id: cornflake_v3_correlation
  group_by_fields:
    - @host
    - @usr
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "CORNFLAKE.V3 Activity: {distinct_count} reason(s) on host {@host} by user {@usr}: {case_names}"
severity: high
```

### DPRK Threat Actor Hunting: Impossible Travel, Phishing, Suspicious Processes, Persistence, and Crypto Activity
---

RW

This is a broad hunting query designed to identify various tactics, techniques, and procedures (TTPs) associated with DPRK threat actors,
as outlined in the DTEX "Exposing DPRK's Cyber Syndicate" report. This query combines several detection concepts into one search.
Due to its broad nature, it is intended for threat hunting or as a dashboard panel, not for high-fidelity alerting.
Each section should be tested and tuned for your specific environment to reduce false positives.

Data sources required: Authentication logs, Endpoint Detection and Response (EDR) logs, Web Proxy/Firewall logs, DNS logs, Email Security logs.

```yaml
name: DPRK Threat Actor Hunting
type: signal_correlation
cases:
  - name: Impossible Travel - Multi-Geo Login
    status: medium
    query: "@event.category:authentication AND @event.outcome:success"
  - name: Phishing Link Click
    status: high
    query: "@event.category:web AND @vulnerability.category:(Phishing\\ &\\ Fraud OR Malware)"
  - name: Suspicious TLD Visited
    status: medium
    query: "@url.domain:*.(xyz OR top OR online OR club OR live OR icu OR gq OR buzz)"
  - name: Suspicious Process Execution
    status: high
    query: "@process.name:(powershell.exe OR pwsh.exe) AND @process.cmdline:(*\\ -enc\\ * OR *\\ -encoded\\ * OR *\\ -w\\ hidden\\ * OR *\\ IEX\\ * OR *\\ Invoke-Expression\\ *) OR @process.name:mshta.exe AND @process.cmdline:(*http:* OR *https:* OR *javascript:*)"
  - name: New Service Created
    status: medium
    query: "@winlog.event_id:4697 AND @winlog.source:Microsoft-Windows-Security-Auditing"
  - name: New Scheduled Task Created
    status: medium
    query: "@winlog.event_id:106 AND @winlog.channel:Microsoft-Windows-TaskScheduler/Operational"
  - name: Cryptocurrency Site Visited
    status: low
    query: "@url:(*binance.com* OR *coinbase.com* OR *kraken.com* OR *kucoin.com* OR *bybit.com* OR *metamask.io*)"
signal_correlation:
  rule_id: dprk_hunting_correlation
  group_by_fields:
    - @host
    - @usr
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "DPRK Hunting: {distinct_count} activity(s) on host {@host} by user {@usr}: {case_names}"
severity: medium
```

### SHELLTER Evasion Framework Activity Detection
---

Author: RW

Date: 2025-08-23

Description:

This rule detects indicators and behaviors associated with the SHELLTER evasion framework. It identifies known malicious file hashes, C2 network communications, and TTPs like remapping ntdll.dll to bypass API hooks. This rule is written for Sysmon data but can be adapted for other EDR sources.

References: https://www.elastic.co/security-labs/taking-shellter

False Positive Sensitivity: Medium

Tactic: Defense Evasion, Command and Control

Technique: T1055, T1574.002, T1071

```yaml
name: SHELLTER Evasion Framework Activity
type: signal_correlation
cases:
  - name: Known SHELLTER-related hash
    status: high
    query: "@process.hash:(c865f24e4b9b0855b8b559fc3769239b0aa6e8d680406616a13d9a36fbbc2d30 OR 7d0c9855167e7c19a67f800892e974c4387e1004b40efb25a2a1d25a99b03a10 OR b3e93bfef12678294d9944e61d90ca4aa03b7e3dae5e909c3b2166f122a14dad OR da59d67ced88beae618b9d6c805f40385d0301d412b787e9f9c9559d00d2c880 OR 70ec2e65f77a940fd0b2b5c0a78a83646dec175836552622ad17fb974f1 OR 263ab8c9ec821ae573979ef2d5ad98cda5009a39e17398cd31b0fad98d862892)"
  - name: Known SHELLTER-related C2
    status: high
    query: "@network.destination.ip:(185.156.72.80 OR 94.141.12.182) OR @network.destination.domain:eaglekl.digital"
  - name: Behavioral - NTDLL Remapping for Hook Evasion
    status: medium
    query: "@winlog.event_id:10 AND @winlog.event_data.TargetImage:*\\ntdll.dll"
  - name: Behavioral - Suspicious Module Preloading
    status: medium
    query: "@dll.name:(wininet.dll OR crypt32.dll OR advapi32.dll OR urlmon.dll)"
signal_correlation:
  rule_id: shellter_evasion_correlation
  group_by_fields:
    - @host
    - @usr
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "SHELLTER Activity: {distinct_count} method(s) on host {@host} by user {@usr}: {case_names}"
severity: high
```

### Interlock Ransomware Activity
---

Author: RW

Date: 2025-08-23

Description:

This rule detects various Tactics, Techniques, and Procedures (TTPs) associated with the Interlock ransomware group (aka Nefarious Mantis). It combines network, process, file, and registry events to identify initial access, execution, persistence, and C2 communication patterns.

False Positive Sensitivity: Medium

References: https://arcticwolf.com/resources/blog/threat-actor-profile-interlock-ransomware/

Tactics: Initial Access, Execution, Persistence, Command and Control

Techniques: T1204.002, T1059.001, T1547.001, T1071.001, T1053.005

```yaml
name: Interlock Ransomware Activity
type: signal_correlation
cases:
  - name: Known Malicious Hash
    status: high
    query: "@process.hash:(2acaa9856ee29337c06cc2858fd71b860f53219504e6756faa3812019b5df5a6 OR 0b47e53f2ada0555588aa8a6a4491e14d7b2528c9a829ebb6f7e9463963cd0e4 OR /* list all */)"
  - name: Suspicious PowerShell Command
    status: high
    query: "@process.name:powershell.exe AND @process.cmdline:(*irm\\ * OR *iex\\ * OR *Invoke-RestMethod* OR *Invoke-Expression* OR *-w\\ h* OR *-windowstyle\\ hidden*)"
  - name: Registry Run Key Modification
    status: medium
    query: "@registry.path:*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run* AND @registry.value:(ChromeUpdater OR 0neDrive)"
  - name: C2 Communication
    status: high
    query: "@network.destination.ip:(168.119.96.41 OR 95.217.22.175 OR /* list all */) OR @network.destination.domain:(cluders.org OR bronxy.cc OR /* list all */ OR *trycloudflare.com*)"
  - name: Scheduled Task Creation
    status: medium
    query: "@process.name:schtasks.exe AND @process.cmdline:(*/create* AND (*/du\\ 9999:59* OR *BitLocker\\ Encrypt\\ All\\ Drives* AND *\\OneDriveCloud\\taskhostw.exe*))"
signal_correlation:
  rule_id: interlock_ransomware_correlation
  group_by_fields:
    - @host
    - @usr
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "Interlock Activity: {distinct_count} method(s) on host {@host} by user {@usr}: {case_names}"
severity: high
```

### Water Curse Threat Actor - Multi-Stage
---

This detection rule identifies multiple Tactics, Techniques, and Procedures (TTPs) associated with the Water Curse threat actor.
Water Curse leverages compromised GitHub repositories to distribute malware, targeting developers and cybersecurity professionals.
This rule detects the entire attack chain, from initial execution via malicious Visual Studio project files to defense evasion, persistence, and C2 communication.

Source: https://www.trendmicro.com/en_us/research/25/f/water-curse.html

RW

```yaml
name: Water Curse Threat Actor - Multi-Stage
type: signal_correlation
cases:
  - name: WaterCurse: Initial Execution via MSBuild
    status: high
    query: "@process.parent.name:MSBuild.exe AND @process.name:cmd.exe AND @process.cmdline:(*/c* AND *.exec.cmd* AND *Temp\\MSBuildTemp*)"
  - name: WaterCurse: Defense Evasion via PowerShell
    status: high
    query: "@process.name:powershell.exe AND @process.cmdline:(*Set-MpPreference*\\ -ExclusionPath*C:\\* OR *vssadmin*delete*shadows*/all* OR *Set-ItemProperty*HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\ NT\\SystemRestore*DisableSR*)"
  - name: WaterCurse: UAC Bypass via ms-settings Hijack
    status: medium
    query: "@registry.path:*\\Software\\Classes\\ms-settings\\shell\\open\\command* AND (@registry.value:(Default) OR @registry.value:DelegateExecute)"
  - name: WaterCurse: Persistence via Scheduled Task
    status: medium
    query: "@process.name:schtasks.exe AND @process.cmdline:(*/create* AND (*/du\\ 9999:59* OR *BitLocker\\ Encrypt\\ All\\ Drives* AND *\\OneDriveCloud\\taskhostw.exe*))"
  - name: WaterCurse: Staging and Reconnaissance
    status: high
    query: "@process.name:7z.exe AND @process.executable:C:\\ProgramData\\sevenZip\\* AND @process.cmdline:*-p* OR @process.parent.name:NVIDIA\\ Control\\ Panel.exe AND @process.parent.executable:*\\Microsoft\\Vault\\UserRoamingTiles\\NVIDIAContainer* AND @process.name:(curl.exe OR wmic.exe OR tasklist.exe)"
  - name: WaterCurse: Malicious File Artifact Creation
    status: high
    query: "@file.path:*\\.vs-script\\* AND @file.name:(antiDebug.ps1 OR disabledefender.ps1) OR @file.path:*\\AppData\\Local\\Temp\\* AND @file.name:SearchFilter.exe OR @file.path:*\\Microsoft\\Vault\\UserRoamingTiles\\NVIDIAContainer* AND @file.name:NVIDIA\\ Control\\ Panel.exe"
  - name: WaterCurse: C2/Exfiltration Network Connection
    status: high
    query: "@url:(*store-eu-par-2.gofile.io* OR *api.telegram.org* OR *popcorn-soft.glitch.me* OR *pastejustit.com* OR *pastesio.com*) OR @network.destination.ip:46.101.236.176 OR @process.name:RegAsm.exe"
signal_correlation:
  rule_id: water_curse_correlation
  group_by_fields:
    - @host
    - @usr
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "Water Curse Activity: {distinct_count} TTP(s) on host {@host} by user {@usr}: {case_names}"
severity: high
```

### PPL Abuse & Defender Tampering
---

Author: RW

Date: 2025-08-23

Description:

This is a consolidated detection rule that identifies multiple techniques associated with the abuse of Protected Process Light (PPL) to tamper with security products, specifically Windows Defender. It detects the use of the 'CreateProcessAsPPL.exe' tool, anomalous execution of 'ClipUp.exe' to write to protected directories, suspicious auto-start service creation for persistence, and direct file modification in Defender directories by unauthorized processes.

False Positives:

This detection combines several high-fidelity indicators.

False positives may occur if legitimate administrative tools create auto-start services from user/temp paths, or if third-party software installers legitimately write to Defender folders.

These should be investigated and can be added to exclusion lists if benign.

MITRE ATT&CK: T1055, T1543.003, T1562.001

```yaml
name: PPL Abuse and Defender Tampering Techniques
type: signal_correlation
cases:
  - name: PPL Loader launching ClipUp
    status: high
    query: "@winlog.event_id:1 AND @process.parent.executable:*\\CreateProcessAsPPL.exe AND @process.executable:*\\clipup.exe"
  - name: Anomalous ClipUp Execution for File Write
    status: high
    query: "@winlog.event_id:1 AND @process.executable:*\\System32\\clipup.exe AND @process.cmdline:*-ppl* AND (@process.cmdline:*\\ProgramData\\Microsoft\\Windows\\ Defender\\* OR @process.cmdline:*\\Program\\ Files\\Windows\\ Defender\\* OR @process.cmdline:*\\Program\\ Files\\ (x86)\\Windows\\ Defender\\* OR @process.cmdline:*-ppl\\ *PROGRA~*)"
  - name: Suspicious Auto-Start Service Creation
    status: medium
    query: "@winlog.event_id:1 AND @process.executable:*\\sc.exe AND @process.cmdline:*create* AND @process.cmdline:*start=auto* AND (@process.cmdline:*binPath=*CreateProcessAsPPL.exe* OR @process.cmdline:*binPath=*\\Users\\* OR @process.cmdline:*binPath=*\\ProgramData\\* OR @process.cmdline:*binPath=*\\Windows\\Temp\\* OR @process.cmdline:*binPath=*\\Temp\\* OR @process.cmdline:binPath=.*(cmd|powershell|pwsh).exe)"
  - name: Unauthorized Defender Directory File Modification
    status: medium
    query: "@winlog.event_id:11 AND (@file.path:C:\\ProgramData\\Microsoft\\Windows\\ Defender\\* OR @file.path:C:\\Program\\ Files\\Windows\\ Defender\\* OR @file.path:C:\\Program\\ Files\\ (x86)\\Windows\\ Defender\\*) -@process.executable:(\\MsMpEng.exe OR \\NisSrv.exe OR \\MsMpEngCP.exe OR \\MpCmdRun.exe OR \\TiWorker.exe OR \\TrustedInstaller.exe OR \\svchost.exe OR \\setup.exe)"
signal_correlation:
  rule_id: ppl_abuse_correlation
  group_by_fields:
    - @host
    - @usr
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "PPL Abuse: {distinct_count} technique(s) on host {@host} by user {@usr}: {case_names}"
severity: high
```

### Process CommandLine Spoofing
---

Author: RW

Date: 2025-08-23

Tactic: Defense Evasion

Technique: T1036.004

Description:

Detects instances where the process image path (the actual file on disk) differs from the executable path specified in the command line. This can indicate command line spoofing techniques, such as the one using symbolic links described in the reference, to evade defenses and mislead analysts.


```yaml
name: Process CommandLine Spoofing via Symbolic Link
type: signal_correlation
cases:
  - name: Process CommandLine Spoofing
    status: medium
    query: "@event.category:process AND @event.action:start AND @process.executable:* AND @process.cmdline:* -@process.parent.name:(services.exe OR svchost.exe OR WmiPrvSE.exe OR msiexec.exe OR TiWorker.exe) -@process.executable:(*(?i)C:\\Windows\\(System32 OR SysWOW64 OR servicing) OR C:\\Program\\ Files OR AppData\\Local\\Temp OR \\Windows\\Temp*)"
signal_correlation:
  rule_id: process_cmdline_spoofing
  group_by_fields:
    - @host
    - @usr
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "Process Spoofing: {distinct_count} instance(s) on host {@host} by user {@usr}"
severity: medium
```

### EDR Evasion: Process/Module/File Creation with Long File Path
---

Author: RW

Date: 2025-08-23

Description:

Detects the creation of processes, files, or the loading of modules at a path that exceeds the standard Windows MAX_PATH limit of 260 characters. Attackers leverage this behavior to cause EDRs and automated collection scripts to fail when trying to access the file, leading to "file not exist" errors and evasion of analysis. This rule combines checks for Sysmon Event Codes 1 (ProcessCreate), 7 (ImageLoad), and 11 (FileCreate).

MITRE ATT&CK: T1562.001, T1073

False Positive Sensitivity: Medium

```yaml
name: EDR File Collection Evasion via Long File Path
type: signal_correlation
cases:
  - name: Process Creation with Long Path
    status: medium
    query: "@winlog.event_id:1 AND @process.executable:*"
  - name: Module Load from Long Path
    status: medium
    query: "@winlog.event_id:7 AND @dll.path:*"
  - name: File Creation with Long Path
    status: medium
    query: "@winlog.event_id:11 AND @file.path:*"
signal_correlation:
  rule_id: edr_evasion_long_path
  group_by_fields:
    - @host
    - @usr
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "EDR Evasion: {distinct_count} long path creation(s) on host {@host} by user {@usr}: {case_names}"
severity: medium
```

### Suspicious SQL Server Activity
---

Author: RW

Date: 2025-08-23

Description:

Detects a variety of suspicious activities related to Microsoft SQL Server that could indicate reconnaissance, execution, or persistence. This includes enabling high-risk procedures, sqlservr.exe spawning shells, suspicious use of sqlcmd or Invoke-Sqlcmd, loading of untrusted CLR assemblies, and execution of suspicious startup procedures.

MITRE ATT&CK: T1543.003, T1059.001, T1059.003, T1059.006, T1003, T1041

```yaml
name: Suspicious SQL Server Activity
type: signal_correlation
cases:
  - name: High-Risk SQL Procedure Enabled
    status: high
    query: "@winlog.event_id:15457 AND @winlog.event_data.Data1:(xp_cmdshell OR Ole\\ Automation\\ Procedures) AND @winlog.event_data.Data2:1"
  - name: SQL CLR Enabled
    status: high
    query: "@winlog.event_id:15457 AND @winlog.event_data.Data1:clr\\ enabled AND @winlog.event_data.Data2:1"
  - name: SQL CLR Strict Security Disabled
    status: high
    query: "@winlog.event_id:15457 AND @winlog.event_data.Data1:clr\\ strict\\ security AND @winlog.event_data.Data2:0"
  - name: Suspicious SQL Startup Procedure
    status: medium
    query: "@winlog.event_id:17135 AND @winlog.event_data.Data1:(*xp_* OR *sp_* OR *cmdshell* OR *shell* OR *exec*)"
  - name: SQL Server Spawning Shell
    status: high
    query: "@process.parent.name:sqlservr.exe AND @process.name:(cmd.exe OR powershell.exe)"
  - name: Suspicious sqlcmd.exe Usage
    status: medium
    query: "@process.name:sqlcmd.exe AND @process.cmdline:(*xp_cmdshell* OR *sp_oacreate* OR *sp_add_trusted_assembly* OR *sp_configure* OR *OPENROWSET* OR *-o\\ * OR *--outputfile* OR *http*//* OR *-t\\ 0* OR *--query_timeout=0*)"
  - name: Potential SQL CLR Assembly Loaded
    status: medium
    query: "@file.name:*.dll AND @file.path:*\\Microsoft\\ SQL\\ Server\\*\\MSSQL\\Binn\\*"
  - name: Suspicious Invoke-Sqlcmd Usage
    status: medium
    query: "@winlog.event_id:4104 AND @winlog.event_data.ScriptBlockText:*Invoke-Sqlcmd* AND (@winlog.event_data.ScriptBlockText:*xp_cmdshell* OR @winlog.event_data.ScriptBlockText:*sp_oacreate* OR @winlog.event_data.ScriptBlockText:*sp_add_trusted_assembly* OR @winlog.event_data.ScriptBlockText:*sp_configure* OR @winlog.event_data.ScriptBlockText:*OPENROWSET* OR @winlog.event_data.ScriptBlockText:*-QueryTimeout\\ 0*)"
signal_correlation:
  rule_id: suspicious_sql_server_correlation
  group_by_fields:
    - @host
    - @usr
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "Suspicious SQL Activity: {distinct_count} type(s) on host {@host} by user {@usr}: {case_names}"
severity: high
```

### SQL Injection (SQLi) Attempts
---

Author: RW

Date: 2025-08-23

This rule combines multiple SQLi detection techniques into a single query.

It identifies general attempts, error-based, time-based, database reconnaissance, and authentication bypass attacks.

```yaml
name: Combined SQL Injection (SQLi) Detection
type: signal_correlation
cases:
  - name: SQLi Authentication Bypass
    status: high
    query: "@event.outcome:(0 OR success OR allow OR accepted) AND @user.name:(*'\\ or\\ * OR *'or'--* OR *\\ or\\ 1=1* OR *admin'--*)"
  - name: Time-Based Blind SQLi
    status: medium
    query: "@http.response.time_taken:>5 AND @http.url:(*sleep\\(* OR *waitfor\\ delay* OR *benchmark\\(* OR *pg_sleep\\(*)"
  - name: Error-Based SQLi
    status: medium
    query: "@http.response.body:(*error\\ in\\ your\\ sql\\ syntax* OR *unclosed\\ quotation\\ mark* OR *ora-[0-9][0-9][0-9][0-9][0-9]* OR *invalid\\ column\\ name*)"
  - name: SQLi DB Reconnaissance
    status: medium
    query: "@sql.query:* AND @sql.query:(*information_schema* OR *sys.objects* OR *pg_catalog* OR *sqlite_master*)"
  - name: General SQLi Attempt
    status: low
    query: "@http.url:(*'\\ or\\ * OR *\\ union\\ *select\\ * OR *--* OR *\\/\\** OR *';*)"
signal_correlation:
  rule_id: sqli_detection_correlation
  group_by_fields:
    - @host
    - @user.name
    - @destination.ip
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "SQLi Attempt: {distinct_count} type(s) from source {@client.ip} by user {@user.name} to destination {@destination.ip}: {case_names}"
severity: high
```

### Container Security: Vulnerabilities, Runtime, API, and Supply Chain Threat Detection
---

Author: RW

Date: 2025-08-23

Description:

This rule combines multiple detection logics to identify various threats in a containerized environment,
including vulnerable images, runtime escape attempts, insecure API usage, and supply chain risks.

Note: This query appends data from multiple sources (vulnerability management, Kubernetes audit, EDR).
You may need to adjust index, sourcetype, and field names to match your environment.

```yaml
name: Container Security Threat Detection
type: signal_correlation
cases:
  - name: High/Critical Vulnerabilities
    status: high
    query: "@vulnerability.severity:(High OR Critical)"
  - name: Privileged Containers
    status: high
    query: "@kubernetes.pod.security_context.privileged:true -@kubernetes.audit.user.username:(system:masters OR cluster-admin OR azure-operator)"
  - name: Runtime Escape Attempts
    status: high
    query: "@process.parent.executable:(*runc* OR *containerd-shim*) AND @process.name:(nsenter OR insmod OR modprobe OR chroot)"
  - name: Insecure API Access
    status: high
    query: "@kubernetes.audit.verb:create AND @kubernetes.audit.objectRef.resource:clusterrolebindings AND @kubernetes.audit.requestObject.roleRef.name:(cluster-admin OR admin) -@kubernetes.audit.user.username:(system:masters OR cluster-admin OR azure-operator)"
  - name: Untrusted Registry
    status: medium
    query: "@container.image.name:* -@container.image.name:(mcr.microsoft.com/* OR docker.io/* OR k8s.gcr.io/* OR quay.io/* OR gcr.io/*)"
signal_correlation:
  rule_id: container_security_correlation
  group_by_fields:
    - @host
    - @kubernetes.audit.user.username
    - @container.image.name
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "Container Threat: {distinct_count} type(s) on host {@host} involving entity {@container.image.name or @kubernetes.audit.user.username}: {case_names}"
severity: high
```

### AI Agent and IDE Threat Detection

Author: RW

Date: 2025-08-15

Description: This is a consolidated rule designed to detect a range of threats against AI Agents and Agentic IDEs, based on the 'From Prompts to Pwns' presentation. It combines multiple detection patterns including prompt injection (direct and indirect), AI-driven RCE, tool misuse, OSS watering hole attacks, and unauthorized IDE actions into a single query.

False Positive Sensitivity: Medium. This is a broad rule and will likely require tuning for your specific environment. Review the 'FP Tuning' comments within each section.

Tactics: Initial Access, Execution, Collection, Discovery, Exfiltration

Techniques: T1059, T1190, T1195.001, T1005, T1082, T1567

```yaml
name: AI Agent and IDE Threat Detection
type: signal_correlation
cases:
  - name: Direct Prompt Injection
    status: high
    query: "source:ai_agent_logs (@prompt:*ignore*instructions* OR @prompt:*disregard*instructions* OR @prompt:*repeat*instructions* OR @prompt:*reveal*prompt* OR @prompt:*</system\\ prompt>*)"
  - name: Indirect Prompt Injection
    status: high
    query: "source:ai_agent_logs @retrieved_data:* AND (@retrieved_data:*ignore*instructions* OR @retrieved_data:*run\\ the\\ following*) -@prompt:*ignore*instructions*"
  - name: AI Agent RCE via Code Generation
    status: critical
    query: "source:ai_agent_code_logs (@executed_code:*os.system\\(* OR @executed_code:*subprocess.run\\(* AND @executed_code:*base64.b64decode\\(*)"
  - name: AI Agent Tool Misuse
    status: high
    query: "source:ai_agent_tool_logs ((@tool_name:(cat OR type OR Get-Content) AND @tool_params:(*/etc/passwd* OR *.ssh/id_rsa* OR *secrets.txt*)) OR (@tool_name:(bash OR powershell.exe OR cmd.exe) AND @tool_params:(*whoami* OR *hostname* OR *net\\ user*)) OR (@tool_name:(curl OR wget) AND @tool_params:(-d* OR *-X\\ POST*)))"
  - name: OSS Watering Hole Attack
    status: high
    query: "source:(sysmon OR linux_audit) (@event_id:1 AND ((@process.name:(powershell.exe OR pwsh.exe) AND @process.command_line:(*Invoke-Expression* OR *DownloadString*)) OR (@process.name:(pip.exe OR uv.exe) AND @process.command_line:*install\\ \\(git\\|http* -@process.command_line:*-r* --requirement*) OR (@parent_process.name:python.exe AND @process.name:powershell.exe AND @process.command_line:*DownloadString*)))"
  - name: Agentic IDE Unauthorized Code Execution
    status: high
    query: "source:(sysmon OR linux_audit) ((@event_id:1 AND @parent_process.name:(cursor.exe OR Code.exe) AND @process.name:(powershell.exe OR cmd.exe OR bash OR curl OR wget) AND @process.command_line:(*Invoke-Expression* OR *whoami* OR *net\\ user* OR */etc/passwd*)) OR (@event_id:11 AND @file.name:*.cursorrules))"
signal_correlation:
  rule_id: ai_ide_threat_detection
  group_by_fields:
    - @host
    - @user.name
    - @process.name
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "AI Agent/IDE Threat: {distinct_count} type(s) on host {@host} by user {@user.name} involving process {@process.name}: {case_names}. Details: {@description}"
severity: high
tags:
  - security:attack
  - tactic:TA0001
  - tactic:TA0002
  - tactic:TA0005
  - tactic:TA0007
  - tactic:TA0010
  - technique:T1059
  - technique:T1190
  - technique:T1195.001
  - technique:T1005
  - technique:T1082
  - technique:T1567
```

### Potential XSS Payload in URL or Request Body

Description: Detects common XSS payloads in URLs or request bodies from web logs.

```yaml
name: Potential XSS Payload in URL or Request Body
type: log_detection
query: "source:(iis OR apache OR stream_http OR paloalto OR aws_waf) (@http.url:(*<script* OR *script>* OR *javascript:* OR *onload=* OR *onerror=* OR *onmouseover=* OR *onclick=* OR *alert\\(* OR *prompt\\(* OR *confirm\\(* OR *eval\\(* OR *String.fromCharCode\\(* OR *btoa\\(* OR *document.cookie* OR *document.write\\(* OR *\\"><* OR *src=x* OR *addEventListener\\(* OR @http.request_body:(*<script* OR *script>* OR *javascript:* OR *onload=* OR *onerror=* OR *onmouseover=* OR *onclick=* OR *alert\\(* OR *prompt\\(* OR *confirm\\(* OR *eval\\(* OR *String.fromCharCode\\(* OR *btoa\\(* OR *document.cookie* OR *document.write\\(* OR *\\"><* OR *src=x* OR *addEventListener\\(*))"
message: "Potential XSS payload detected: {matched_payloads} from source {@client.ip} to destination {@destination.ip} with user agent {@http.user_agent}. URLs: {@http.url}"
severity: medium
tags:
  - security:attack
  - technique:T1190
options:
  evaluation_window: 1h
  group_by:
    - @client.ip
    - @destination.ip
    - @http.user_agent
```

### Potential Data Exfiltration via Client-Side Request

Description: Detects potential data exfiltration where an internal referer leads to an external destination with suspicious patterns.

```yaml
name: Potential Data Exfiltration via Client-Side Request
type: log_detection
query: "source:(iis OR apache OR stream_http OR paloalto OR aws_waf) @http.url:* AND @http.referer:* AND @http.referer:*.your_company_domain.com OR @http.referer:*.your_other_app.io -@http.url:*.your_company_domain.com -@http.url:*.your_other_app.io AND (@destination.domain:(*.oastify.com OR *.burpcollaborator.net OR *.interact.sh OR *.requestbin.net) OR @http.url:*[\\?&](data|payload|html|content|b64)=[A-Za-z0-9+\\/_-]{100,}* OR @http.url.length:>1024)"
message: "Potential data exfiltration detected from {@client.ip} to external host {@destination.domain}. Reason: {@exfil_reason}. URLs: {@http.url}, Referer: {@http.referer}"
severity: high
tags:
  - security:attack
  - technique:T1567
options:
  evaluation_window: 1h
  group_by:
    - @client.ip
    - @destination.domain
    - @http.user_agent
    - @http.referer
```

### Potential Automated Form Resubmission for Account Takeover

Description: Detects rapid GET-then-POST sequences targeting account management pages, indicative of automated attacks.

```yaml
name: Potential Automated Form Resubmission for Account Takeover
type: log_detection
query: "source:(iis OR apache OR stream_http OR paloalto OR aws_waf) @http.url:(*/Account* OR */profile* OR */settings* OR */user/update* OR */change_password* OR */reset_email*) AND ((@http.method:GET AND @http.status:200) OR (@http.method:POST AND @http.status:(200 OR 302)))"
message: "Potential automated form resubmission detected from {@client.ip} for user {@user.name} on URL {@http.url}. Time between GET and POST: {time_between_get_and_post_sec}s, Steps: {steps_in_sequence}"
severity: high
tags:
  - security:attack
  - technique:T1110
options:
  evaluation_window: 1m
  group_by:
    - @client.ip
    - @user.name
    - @http.url
  transaction:
    start_condition: "@http.method:GET"
    end_condition: "@http.method:POST"
    max_duration: 5s
    min_events: 2
```

### Dynamic Loading of External JavaScript

Description: Detects external JavaScript loading from internal pages to untrusted domains.

```yaml
name: Dynamic Loading of External JavaScript
type: log_detection
query: "source:(iis OR apache OR stream_http OR paloalto OR aws_waf) @http.url:*.js AND @http.referer:* AND @http.referer:*.your_company_domain.com OR @http.referer:*.your_other_app.io -@http.url:*.your_company_domain.com -@http.url:*.your_other_app.io -@destination.domain:(google-analytics.com OR googletagmanager.com OR cdn.jsdelivr.net OR code.jquery.com OR some_ad_network.com OR your_support_widget.io)"
message: "External JavaScript loaded from {@destination.domain} by source page {@http.referer} from {@client.ip} with user agent {@http.user_agent}. Script URLs: {@http.url}"
severity: medium
tags:
  - security:attack
  - technique:T1190
options:
  evaluation_window: 1h
  group_by:
    - @client.ip
    - @http.referer
    - @destination.domain
    - @http.user_agent
```

### Suspicious Email or Password Change from New Source

Description: Detects successful email or password changes from unknown source IPs, using a baseline lookup.

```yaml
name: Suspicious Email or Password Change from New Source
type: log_detection
query: "source:(iis OR apache OR stream_http OR paloalto OR aws_waf OR applogs) ((@message:*email\\ address\\ (updated|changed)* AND @message:*success*) OR (@message:*password\\ (changed|reset)* AND @message:*success*) OR (@http.url:(*/Account.aspx* OR */api/user/profile* OR */settings/security*) AND @http.method:POST AND @http.status:(200 OR 302))) -@user_source_baseline.user:@user.name"
message: "Suspicious email/password change by {@user.name} from new source {@client.ip} with user agent {@http.user_agent}. URLs: {@http.url}, Messages: {@message}"
severity: high
tags:
  - security:attack
  - technique:T1110
options:
  evaluation_window: 1h
  group_by:
    - @user.name
    - @client.ip
    - @http.user_agent
  lookup:
    table: user_source_baseline
    key: user
    value: @user.name
    not_found: alert
```

### EarlyBird Injection via Suspended WerFault.exe

Description: Detects WerFault.exe created in a suspended state, indicative of EarlyBird injection (T1055.001, T1055.004).

```yaml
name: EarlyBird Injection via Suspended WerFault.exe
type: log_detection
query: "source:(wineventlog OR sysmon OR crowdstrike) (@process.name:WerFault.exe OR @process.path:*\\WerFault.exe) AND (@process.creation_flags:0x4 OR @process.flags:0x4)"
message: "Suspicious WerFault.exe created in suspended state on host {@host} by user {@user.name}. Parent: {@parent_process.name}, Command Line: {@process.command_line}, Flags: {@process.creation_flags OR @process.flags}"
severity: high
tags:
  - security:attack
  - technique:T1055.001
  - technique:T1055.004
options:
  evaluation_window: 1h
  group_by:
    - @host
    - @user.name
    - @parent_process.name
    - @process.name
    - @process.path
    - @process.command_line
```

### WerFault.exe Network Connections

Description: Detects outbound network connections from WerFault.exe to non-Microsoft domains, indicating potential C2 activity (T1071.001).

```yaml
name: WerFault.exe Network Connections
type: log_detection
query: "source:(stream OR paloalto OR suricata OR crowdstrike) (@process.name:WerFault.exe OR @process.path:*\\WerFault.exe) -@destination.domain:(*.microsoft.com OR *.windows.com OR *.msftconnecttest.com OR *.windowsupdate.com)"
message: "Suspicious network connection from WerFault.exe on host {@host} by user {@user.name} to destinations {@destination.domain}. Parent: {@parent_process.name}, Command Line: {@process.command_line}"
severity: high
tags:
  - security:attack
  - technique:T1071.001
options:
  evaluation_window: 1h
  group_by:
    - @host
    - @user.name
    - @parent_process.name
    - @process.name
    - @process.path
    - @destination.domain
```

### Mimicked Web Content for C2

Description: Detects HTTP/HTTPS requests mimicking font file paths (e.g., /assets/fonts/*.ttf) used for C2 communication, excluding browser processes (T1071.001).

```yaml
name: Mimicked Web Content for C2
type: log_detection
query: "source:(zscaler OR stream_http OR paloalto OR crowdstrike) @http.url:*assets/fonts/*.ttf -@process.name:(chrome.exe OR firefox.exe OR msedge.exe OR iexplore.exe OR browser.exe OR opera.exe OR safari.exe)"
message: "Suspicious font file URL access on host {@host} by user {@user.name}. URLs: {@http.url}, User Agents: {@http.user_agent}, Parent: {@parent_process.name}, Process: {@process.name}"
severity: high
tags:
  - security:attack
  - technique:T1071.001
options:
  evaluation_window: 1h
  group_by:
    - @host
    - @user.name
    - @parent_process.name
    - @process.name
    - @process.path
    - @http.user_agent
```

### Remote Process Executable Memory Allocation

Description: Detects memory allocation with PAGE_EXECUTE_READWRITE (0x40) permissions in a remote process, indicative of process injection (T1055).

```yaml
name: Remote Process Executable Memory Allocation
type: log_detection
query: "source:(crowdstrike OR carbonblack) @memory.allocation_flags:0x40 AND @actor_process.name!=@target_process.name -@actor_process.name:(csrss.exe OR lsass.exe OR svchost.exe OR YourEDRAgent.exe) -@target_process.name:(msedge.exe OR chrome.exe OR firefox.exe)"
message: "Suspicious memory allocation (RWX) by {@actor_process.name} in {@target_process.name} on host {@host} by user {@user.name}. Command Line: {@actor_process.command_line}"
severity: critical
tags:
  - security:attack
  - technique:T1055
options:
  evaluation_window: 1h
  group_by:
    - @host
    - @user.name
    - @actor_process.name
    - @actor_process.path
    - @actor_process.command_line
    - @target_process.name
    - @target_process.path
```

### WinHTTP Certificate Bypass Detected

Description: Detects use of WinHTTP APIs with security flags bypassing certificate validation, indicating potential malicious communication (T1102).

```yaml
name: WinHTTP Certificate Bypass Detected
type: log_detection
query: "source:(crowdstrike OR sysmon OR carbonblack) @api.parameters:(*SECURITY_FLAG_IGNORE_CERT_CN_INVALID* OR *SECURITY_FLAG_IGNORE_CERT_DATE_INVALID* OR *SECURITY_FLAG_IGNORE_UNKNOWN_CA* OR *SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE* OR *0x1000* OR *0x2000* OR *0x100* OR *0x200*) -@process.name:(YourInternalUpdater.exe OR YourDevTool.exe)"
message: "WinHTTP certificate bypass detected on host {@host} by user {@user.name}. Process: {@process.name}, Evidence: {@api.parameters}, Command Line: {@process.command_line}"
severity: high
tags:
  - security:attack
  - technique:T1102
options:
  evaluation_window: 1h
  group_by:
    - @host
    - @user.name
    - @parent_process.name
    - @process.name
    - @process.path
    - @process.command_line
    - @api.parameters
```

### UAC-0057 (Ghostwriter) Activity
---

Description: This rule detects various TTPs and IOCs associated with UAC-0057 (aka Ghostwriter, UNC1151) campaigns targeting Ukraine and Poland.

It covers suspicious file creation, persistence mechanisms, command execution, and network C2 patterns.

Data sources: Sysmon (Event IDs 1, 3, 11, 13), Proxy/Firewall logs

False Positive Sensitivity: Medium. Some network patterns, like connections to Slack, may require tuning based on your environment's baseline activity.

Author: RW

```yaml
name: UAC-0057 (Ghostwriter) Activity
type: signal_correlation
cases:
  - name: File Creation by Hash IOC
    status: high
    query: "source:(sysmon OR xmlwineventlog OR microsoft-windows-sysmon) @winlog.event_id:11 AND @winlog.event_data.sha256:(f6fec3722a8c98c29c5de10969b8f70962dbb47ba53dcbcd4a3bbc63996d258d OR deaa3f807de097c3bfff37a41e97af5091b2df0e3a6d01a11a206732f9c6e49c OR aac430127c438224ec61a6c02ea59eb3308eb54297daac985a7b26a75485e55f OR 06380c593d122fc4987e9d4559a9573a74803455809e89dd04d476870a427cbe OR 082877e6f8b28f6cf96d3498067b0c404351847444ebc9b886054f96d85d55d4 OR 082903a8bec2b0ef7c7df3e75871e70c996edcca70802d100c7f68414811c804 OR 69636ddc0b263c93f10b00000c230434febbd49ecdddf5af6448449ea3a85175 OR a2a2f0281eed6ec758130d2f2b2b5d4f578ac90605f7e16a07428316c9f6424e OR 8a057d88a391a89489697634580e43dbb14ef8ab1720cb9971acc418b1a43564 OR 707a24070bd99ba545a4b8bab6a056500763a1ce7289305654eaa3132c7cbd36 OR 5fa19aa32776b6ab45a99a851746fbe189f7a668daf82f3965225c1a2f8b9d36 OR 3b5980c758bd61abaa4422692620104a81eefbf151361a1d8afe8e89bf38579d OR c7e44bba26c9a57d8d0fa64a140d58f89d42fd95638b8e09bc0d2020424b640e OR 7c77d1ba7046a4b47aec8ec0f2a5f55c73073a026793ca986af22bbf38dc948c OR 559ee2fad8d16ecaa7be398022aa7aa1adbd8f8f882a34d934be9f90f6dcb90b)"
  - name: File Creation by Path IOC
    status: high
    query: "source:(sysmon OR xmlwineventlog OR microsoft-windows-sysmon) @winlog.event_id:11 AND @winlog.event_data.TargetFilename:(*\\Temp\\DefenderProtectionScope.log OR *\\Microsoft\\System\\ProtectedCertSystem.dll OR *\\Serv\\0x00bac729fe.log OR *\\Microsoft\\Windows\\Protection\\ overview.lnk OR *\\Temp\\sdw9gobh0n OR *\\Microsoft\\Windows\\Protection\\ overview\\ past.lnk OR *\\Logs\\sdw9gobh0n.log OR *\\SDXHelp\\SDXHelp.dll OR *\\Runtime\\RuntimeBroker.dll OR *\\MSDE\\mrasp86.dll OR *\\DiagnosticComponents\\DiagnosticComponents.dll OR *\\ProgramData\\OfficeRuntimeBroker.xlam OR *\\ProgramData\\OfficeRuntimeBroker.lnk OR *\\ProgramData\\~OfficeRuntimeBroker.dat OR *\\ProgramData\\ssh\\ssh.pif.pif.pif OR *\\ProgramData\\~DF20BC61C6277A354A.dat)"
  - name: Persistence via Run Key
    status: medium
    query: "source:(sysmon OR xmlwineventlog OR microsoft-windows-sysmon) @winlog.event_id:13 AND @winlog.event_data.TargetObject:*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run AND @winlog.event_data.Details:(SytemProtectionService OR MicrosoftDefender OR SytemProtectService OR Audio\\ Driver)"
  - name: Suspicious Rundll32 Execution
    status: high
    query: "source:(sysmon OR xmlwineventlog OR microsoft-windows-sysmon) @winlog.event_id:1 AND @process.executable:*\\rundll32.exe AND (@process.cmdline:* ,#1 OR @process.cmdline:* ,TS_STATUS_INFO_get0_status OR @process.cmdline:*shell32.dll,ShellExec_RunDLL)"
  - name: Suspicious Expand.exe Execution
    status: high
    query: "source:(sysmon OR xmlwineventlog OR microsoft-windows-sysmon) @winlog.event_id:1 AND @process.parent.executable:*\\excel.exe AND @process.executable:*\\expand.exe AND @process.cmdline:*.xlam AND @process.cmdline:*.dat AND @process.cmdline:*ProgramData*"
  - name: Network C2 Domain IOC
    status: critical
    query: "source:(sysmon OR xmlwineventlog OR microsoft-windows-sysmon OR stream_http OR paloalto OR zscaler) (@winlog.event_id:3 OR source:(stream_http OR paloalto OR zscaler)) AND (@dns.question.name:(sweetgeorgiayarns.online OR kitchengardenseeds.icu OR punandjokes.icu OR taskandpurpose.icu OR medpagetoday.icu OR pesthacks.icu OR curseforge.icu) OR @destination.domain:(sweetgeorgiayarns.online OR kitchengardenseeds.icu OR punandjokes.icu OR taskandpurpose.icu OR medpagetoday.icu OR pesthacks.icu OR curseforge.icu))"
  - name: Network C2 User-Agent IOC
    status: critical
    query: "source:(stream_http OR paloalto OR zscaler) @http.user_agent:(Mozilla/5.0\\ (Windows\\ NT\\ 10.0;\\ Win64;\\ x64)\\ AppleWebKit/537.36\\ (KHTML,\\ like\\ Gecko)\\ Chrome/98.0.4758.80\\ Safari/537.36 OR Mozilla/5.0\\ (iPhone;\\ CPU\\ iPhone\\ OS\\ 18_4_1\\ like\\ Mac\\ OS\\ X)\\ AppleWebKit/605.1.15\\ (KHTML,\\ like\\ Gecko)\\ CriOS/133.0.6943.84\\ Mobile/15E148\\ Safari/604.1) AND @destination.domain:(sweetgeorgiayarns.online OR kitchengardenseeds.icu OR punandjokes.icu OR taskandpurpose.icu OR medpagetoday.icu OR pesthacks.icu OR curseforge.icu)"
  - name: Network C2 via Slack Webhook
    status: critical
    query: "source:(stream_http OR paloalto OR zscaler) @http.url:*hooks.slack.com/services/* -@process.executable:(*\\slack.exe OR *\\chrome.exe OR *\\firefox.exe OR *\\msedge.exe OR *\\iexplore.exe) -@process.name:(slack.exe OR chrome.exe OR firefox.exe OR msedge.exe OR iexplore.exe)"
)
signal_correlation:
  rule_id: uac_0057_ghostwriter_activity
  group_by_fields:
    - @host
    - @user.name
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "UAC-0057 Activity: {distinct_count} detection(s) on host {@host} by user {@user.name}: {case_names}. Reason: {@detection_reason}"
severity: high
options:
  evaluation_window: 1h
tags:
  - security:attack
  - tactic:TA0001
  - tactic:TA0003
  - tactic:TA0005
  - tactic:TA0007
  - tactic:TA0011
```

### Linux Rootkit and Anti-Forensic Activity (DPRK Stealth Rootkit)
---

Author: RW

Date: 2025-08-14

References:

- https://sandflysecurity.com/blog/leaked-north-korean-linux-stealth-rootkit-analysis

- https://www.kernel.org/doc/html/latest/admin-guide/tainted-kernels.html

MITRE TTPs: T1564.001, T1547.006, T1070.004, T1070.006, T1562.003

```yaml
name: Linux Rootkit and Anti-Forensic Activity (DPRK Stealth Rootkit)
type: signal_correlation
cases:
  - name: Hidden Rootkit Artifact Detected
    status: high
    query: "source:(sysmon OR endpoint OR edr) (@process.path:(/usr/lib64/tracker-fs OR /usr/include/tracker-fs/tracker-efs OR /etc/init.d/tracker-fs OR /etc/rc[235].d/S55tracker-fs OR /proc/acpi/pcicard) OR @process.name:(/usr/lib64/tracker-fs OR /usr/include/tracker-fs/tracker-efs OR /etc/init.d/tracker-fs OR /etc/rc[235].d/S55tracker-fs OR /proc/acpi/pcicard) OR @file.path:(/usr/lib64/tracker-fs OR /usr/include/tracker-fs/tracker-efs OR /etc/init.d/tracker-fs OR /etc/rc[235].d/S55tracker-fs OR /proc/acpi/pcicard))"
  - name: Kernel Tainted by Unsigned Module
    status: high
    query: "source:syslog @process.name:kernel @message:*tainting\\ kernel* -@message:(*nvidia* OR *vboxdrv* OR *zfs*)"
  - name: Network Connection Without Associated Process
    status: medium
    query: "source:(network OR endpoint) @os:Linux AND @event.action:(allowed OR success) AND (@process.name:NULL OR @process.pid:0) AND -@network.destination.ip:(127.0.0.0/8 OR 10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16)"
  - name: Anti-Forensic History Disabling
    status: medium
    query: "source:(sysmon OR endpoint OR edr) @os:Linux AND (@process.name:(sh OR bash OR dash OR zsh OR ksh OR csh OR tcsh) AND @process.command_line:(--noprofile OR --norc OR HISTFILE=/dev/null OR HISTORY=/dev/null OR BASH_HISTORY=/dev/null OR unset\\ HISTFILE OR unset\\ HISTORY OR TMOUT=0)) OR (@process.name:ln AND @process.command_line:(-sf*/dev/null*) AND @process.command_line:(*.bash_history OR *.zsh_history OR *.zhistory OR *.history OR *.sh_history))"
signal_correlation:
  rule_id: linux_rootkit_antiforensic_activity
  group_by_fields:
    - @host
    - @user.name
    - @process.name
    - @parent_process.name
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "DPRK Rootkit Activity: {distinct_count} pattern(s) on host {@host} by user {@user.name}: {case_names}. Details: {@details}, Suspicious Process: {@process.name}, Command Line: {@process.command_line}, Parent: {@parent_process.name}"
severity: high
tags:
  - security:attack
  - technique:T1564.001
  - technique:T1547.006
  - technique:T1070.004
  - technique:T1070.006
  - technique:T1562.003
options:
  evaluation_window: 1h
```

### GRU Unit 29155 (Ember Bear/Cadet Blizzard) Activity
---

description:

Detects a wide range of Tactics, Techniques, and Procedures (TTPs) associated with the Russian GRU Unit 29155, also known as Ember Bear and Cadet Blizzard. This rule covers process execution, network communications, and specific tool usage as detailed in CISA advisory AA24-249A.

RW

date: 2025-08-21

reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-249a

tags: G1003, EMBER_BEAR, CADET_BLIZZARD, UNC2589, UAC-0056, WHISPERGATE, RUSSIA, TA0002, TA0005, TA0006, TA0007, TA0008, TA0010, TA0011, T1059.001, T1562.001, T1003, T1550.002, T1567.002, T1572, T1090.003, T1071.004, T1071.001, T1105

```yaml
name: GRU Unit 29155 (Ember Bear/Cadet Blizzard) Activity
type: signal_correlation
cases:
  - name: WhisperGate PowerShell
    status: high
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:(1 OR 4688) AND @process.name:(powershell.exe OR pwsh.exe) AND @process.command_line:* -enc\\ UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQAwAA==*"
  - name: PowerShell Defender Exclusion
    status: high
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:(1 OR 4688) AND @process.name:(powershell.exe OR pwsh.exe) AND @process.command_line:*Set-MpPreference*ExclusionPath*C:\\\\*"
  - name: AdvancedRun Defender Disabling
    status: high
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:(1 OR 4688) AND @process.name:AdvancedRun.exe AND (@process.command_line:*stop\\ WinDefend* OR @process.command_line:*rmdir\\ *C:\\\\ProgramData\\\\Microsoft\\\\Windows\\ Defender*)"
  - name: InstallUtil from Temp Path
    status: high
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:(1 OR 4688) AND @process.name:InstallUtil.exe AND (@process.executable:*\\\\AppData\\\\Local\\\\Temp\\\\* OR @process.executable:*\\\\Windows\\\\Temp\\\\*)"
  - name: Impacket Execution
    status: medium
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:(1 OR 4688) AND @process.command_line:(*secretsdump.py* OR *psexec.py*)"
  - name: Rclone Exfil to MEGA
    status: high
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:(1 OR 4688) AND @process.name:(rclone.exe OR rclone) AND @process.command_line:*mega*.nz*"
  - name: GOST Tunneling
    status: high
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:(1 OR 4688) AND @process.name:(java.exe OR java) AND (@process.command_line:*-L*socks5://* OR @process.command_line:*-L*rtcp://*)"
  - name: ProxyChains Usage
    status: medium
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:(1 OR 4688) AND @process.command_line:*proxychains*"
  - name: su-bruteforce Usage
    status: high
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:(1 OR 4688) AND @process.command_line:*su-bruteforce*"
  - name: LinPEAS Execution
    status: high
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:(1 OR 4688) AND @process.command_line:(*linpeas.sh* OR *linpeas.py*)"
  - name: GOST Tool File Hash
    status: high
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:11 AND @file.md5:896e0f54fc67d72d94b40d7885f10c51"
  - name: C2 Network Connection
    status: critical
    query: "source:(sysmon OR xmlwineventlog OR wineventlog OR network OR firewall OR proxy) (@destination.ip:(5.226.139.66 OR 45.141.87.11 OR 46.101.242.222 OR 62.173.140.223 OR 79.124.8.66 OR 90.131.156.107 OR 112.51.253.153 OR 112.132.218.45 OR 154.21.20.82 OR 179.43.133.202 OR 179.43.142.42 OR 179.43.162.55 OR 179.43.175.38 OR 179.43.175.108 OR 179.43.176.60 OR 179.43.187.47 OR 179.43.189.218 OR 185.245.84.227 OR 185.245.85.251 OR 194.26.29.84 OR 194.26.29.95 OR 194.26.29.98 OR 194.26.29.251) OR @destination.domain:(interlinks.top OR 3proxy.ru OR nssm.cc OR *cdn.discordapp.com OR *ngrok.com))"
  - name: Iodine DNS Tunneling
    status: critical
    query: "source:(sysmon OR xmlwineventlog OR wineventlog OR dns) @dns.question.name:dns.test658324901domain.me"
signal_correlation:
  rule_id: gru_unit_29155_activity
  group_by_fields:
    - @host
    - @user.name
    - @process.name
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "GRU Unit 29155 Activity: {distinct_count} TTP(s) on host {@host} by user {@user.name}: {case_names}. Details: {@process.command_line OR @file.md5 OR @destination.ip OR @destination.domain OR @dns.question.name}"
severity: high
tags:
  - security:attack
  - tactic:TA0002
  - tactic:TA0005
  - tactic:TA0006
  - tactic:TA0007
  - tactic:TA0008
  - tactic:TA0010
  - tactic:TA0011
  - technique:T1059.001
  - technique:T1562.001
  - technique:T1003
  - technique:T1550.002
  - technique:T1567.002
  - technique:T1572
  - technique:T1090.003
  - technique:T1071.004
  - technique:T1071.001
  - technique:T1105
options:
  evaluation_window: 1h
```

### Static Tundra Group Activity
---
```bash
----------------------------------------------------------------------------------

Name:         Static Tundra Group Activity

Author:       RW

Date:         2025-08-22


Description:  This detection looks for a combination of Tactics, Techniques, and

              Procedures (TTPs) associated with the Russian state-sponsored

              group Static Tundra. This includes network communications to

              known C2 IPs, network device configuration changes, and data

              exfiltration techniques.


References:   - https://blog.talosintelligence.com/static-tundra/


False Positive Sensitivity: Medium


Tactic:       Initial Access, Persistence, Defense Evasion, Collection, Exfiltration


Technique:    T1190 (Exploit Public-Facing Application), T1078 (Valid Accounts),

              T1098.002 (Create Account: Local Account), T1562.007 (Disable or

              Modify Cloud Firewall), T1020 (Automated Exfiltration), T1048 (Exfiltration

              Over Alternative Protocol)
----------------------------------------------------------------------------------
```

```yaml
name: Static Tundra Group Activity
type: signal_correlation
cases:
  - name: Static Tundra C2 IP Detected
    status: high
    query: "source:(paloalto OR opsec OR cisco_asa OR stream) (@network.source.ip:(185.141.24.222 OR 185.82.202.34 OR 185.141.24.28 OR 185.82.200.181) OR @network.destination.ip:(185.141.24.222 OR 185.82.202.34 OR 185.141.24.28 OR 185.82.200.181))"
  - name: Potential Inbound TFTP for Config Exfil
    status: medium
    query: "source:(paloalto OR opsec OR cisco_asa OR stream) @network.transport:udp @network.destination.port:69"
  - name: GRE Tunnel Established for Traffic Collection
    status: medium
    query: "source:(paloalto OR opsec OR cisco_asa OR stream) @network.protocol:gre"
  - name: Local TFTP Server Enabled for Config Exfil
    status: high
    query: "source:(cisco_ios OR syslog) @message:*tftp-server\\ nvram:startup-config*"
  - name: Config Exfil via TFTP Redirect
    status: high
    query: "source:(cisco_ios OR syslog) @message:*redirect\\ tftp://*"
  - name: Config Exfil via FTP
    status: high
    query: "source:(cisco_ios OR syslog) @message:*copy\\ running-config\\ ftp://*"
  - name: ACL Modification Detected
    status: medium
    query: "source:(cisco_ios OR syslog) @message:*access-list\\ *"
  - name: TACACS+ Config Modification Detected
    status: medium
    query: "source:(cisco_ios OR syslog) @message:*tacacs-server\\ *"
signal_correlation:
  rule_id: static_tundra_group_activity
  group_by_fields:
    - @host
    - @user.name
    - @network.source.ip
    - @network.destination.ip
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "Potential Static Tundra activity detected: {distinct_count} technique(s) on host {@host} by user {@user.name}. Techniques: {case_names}. Source: {@network.source.ip}, Destination: {@network.destination.ip}, Command: {@command}"
severity: high
tags:
  - security:attack
  - tactic:TA0001
  - tactic:TA0003
  - tactic:TA0005
  - tactic:TA0009
  - tactic:TA0010
  - technique:T1190
  - technique:T1078
  - technique:T1098.002
  - technique:T1562.007
  - technique:T1020
  - technique:T1048
options:
  evaluation_window: 1h
```

### Warlock Ransomware TTPs
---

Description: This rule detects a combination of Tactics, Techniques, and Procedures (TTPs) associated with Warlock ransomware campaigns.

It looks for evidence of discovery, credential access, defense evasion, lateral movement, and exfiltration by correlating multiple weak signals on a single host.

Author: RW

Date: 2025-08-21

References: https://www.trendmicro.com/en_us/research/25/h/warlock-ransomware.html

False Positive Sensitivity: Medium. This is a correlation rule that combines multiple weak signals.

Individual components, such as copying files to C$ or modifying RDP settings, might be legitimate administrative behavior.

The rule's strength comes from detecting multiple distinct TTPs on the same host in a short period. Consider tuning by adding known administrative accounts or tools to an exclusion list.

```yaml
name: Warlock Ransomware Activity
type: signal_correlation
cases:
  - name: Initial Access & Privilege Escalation via SharePoint
    status: high
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:1 @process.parent.name:w3wp.exe @process.parent:*SharePoint* (@process.command_line:*net\\ user\\ guest\\ /active:yes* OR @process.command_line:*net\\ localgroup\\ administrators\\ guest\\ /add* OR @process.command_line:*New-GPO*)"
  - name: Discovery
    status: medium
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:1 @process.command_line:(*nltest\\ /domain_trusts* OR *wmic\\ product\\ get\\ name,identifyingnumber* OR *net\\ group\\ \\\"domain\\ admins\\\"* OR *net\\ group\\ \\\"domain\\ computers\\\"* OR *net\\ group\\ \\\"domain\\ controllers\\\"* OR *quser*)"
  - name: Credential Access
    status: high
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:1 (@process.name:mimikatz.exe OR @process.command_line:*reg*save*hklm\\\\sam* OR @process.command_line:*reg*save*hklm\\\\security*)"
  - name: Defense Evasion - Kill AV
    status: high
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:1 @process.parent.name:vmtools.exe (@process.command_line:*taskkill* OR @process.command_line:*net\\ stop*)"
  - name: Defense Evasion - Malicious Driver
    status: high
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:11 @file.name:googleApiUtil64.sys"
  - name: Command and Control
    status: high
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:1 @process.command_line:*tunnel*run*--token*"
  - name: Lateral Movement
    status: medium
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:1 @process.command_line:*copy*\\\\c$\\\\users\\\\public*"
  - name: Persistence & Defense Evasion - RDP Modification
    status: medium
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:13 (@registry.path:*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Terminal\\ Server\\\\fDenyTSConnections OR @registry.path:*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Terminal\\ Server\\\\WinStations\\\\RDP-Tcp\\\\UserAuthentication) @registry.value.data:0"
  - name: Exfiltration
    status: critical
    query: "source:(sysmon OR xmlwineventlog OR wineventlog) @winlog.event_id:1 @process.parent.name:(rclone.exe OR TrendSecurity.exe) @process.command_line:*copy*--protondrive-username*--protondrive-password*"
signal_correlation:
  rule_id: warlock_ransomware_activity
  group_by_fields:
    - @host
    - @user.name
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 2
    timeframe: 1h
message: "Warlock Ransomware Activity: {distinct_count} distinct tactics on host {@host} by user {@user.name}. Tactics: {case_names}. Evidence: {@process.command_line OR @file.name OR @registry.path}. First activity: {first_activity}, Last activity: {last_activity}"
severity: high
tags:
  - security:attack
  - tactic:TA0001
  - tactic:TA0004
  - tactic:TA0005
  - tactic:TA0007
  - tactic:TA0008
  - tactic:TA0009
  - tactic:TA0010
  - tactic:TA0011
  - technique:T1190
  - technique:T1078
  - technique:T1003
  - technique:T1562
  - technique:T1570
  - technique:T1021
  - technique:T1048
options:
  evaluation_window: 1h
```

### Ivanti Exploitation TTPs
---

Author: RW

Date: 2025-08-14

Description:

A composite rule that detects multiple tactics, techniques, and procedures (TTPs) associated with attacks exploiting Ivanti Connect Secure vulnerabilities, as detailed by JPCERT/CC. This includes DLL side-loading, specific malware artifacts, C2 communication, persistence mechanisms, defense evasion, and lateral movement patterns.

Tactic: Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Command and Control, Lateral Movement

Technique: T1574.001, T1027, T1071.001, T1046, T1018, T1136.002, T1098, T1543.003, T1053.005, T1562.001, T1110.001, T1021.001, T1021.002

False Positive Sensitivity: Medium

```yaml
name: Comprehensive Ivanti Exploitation TTPs
type: signal_correlation
cases:
  - name: DLL Side-Loading
    status: high
    query: "source:sysmon @winlog.event_id:7 (@process.image:*\\rmic.exe @process.image_loaded:*\\jli.dll OR @process.image:*\\push_detect.exe @process.image_loaded:*\\Microsoft.WindowsAppRuntime.Bootstrap.dll OR @process.image:*\\python.exe @process.image_loaded:*\\python311.dll) -@process.image.path:(*\\Program\\ Files\\* OR *\\Windows\\System32\\* OR *\\Program\\ Files\\ \\(x86\\)\\* OR *\\Windows\\SysWOW64\\*)"
  - name: Cobalt Strike & Fscan Artifacts
    status: high
    query: "source:sysmon @winlog.event_id:11 (@file.sha256:(09087fc4f8c261a810479bb574b0ecbf8173d4a8365a73113025bd506b95e3d7 OR 1652ab693512cd4f26cc73e253b5b9b0e342ac70aa767524264fef08706d0e69 OR cff2afc651a9cba84a11a4e275cc9ec49e29af5fd968352d40aeee07fb00445e) OR (@file.target_filename:(*\\update.dat OR *\\config.ini) @process.image:(*\\rmic.exe OR *\\push_detect.exe)))"
  - name: Vshell C2 Communication
    status: high
    query: "source:sysmon @winlog.event_id:3 @network.destination.hostname:proxy.objectlook.com @network.destination.port:80"
  - name: Account Manipulation via CLI
    status: medium
    query: "source:sysmon @winlog.event_id:1 @process.image:(*\\net.exe OR *\\net1.exe) @process.command_line:(*\\ user\\ /add\\ * OR *\\ group\\ /add\\ * OR *\\ localgroup\\ /add\\ *) @process.command_line:(*\\ /domain\\ * OR *\\ Administrators\\ * OR *\\ Domain\\ Admins\\ * OR *\\ Enterprise\\ Admins\\ * OR *\\ Remote\\ Desktop\\ Users\\ *)"
  - name: Suspicious Service Creation
    status: high
    query: "source:sysmon @winlog.event_id:13 @registry.target_object:*\\System\\CurrentControlSet\\Services\\*\\ImagePath @registry.details:(*C:\\Users\\* OR *C:\\ProgramData\\* OR *C:\\Temp\\* OR *C:\\Windows\\Temp\\* OR *\\AppData\\*)"
  - name: Suspicious Scheduled Task
    status: high
    query: "source:sysmon @winlog.event_id:1 @process.image:*\\schtasks.exe @process.command_line:(*/create* OR */change*) @process.command_line:(*C:\\Users\\* OR *C:\\ProgramData\\* OR *C:\\Temp\\* OR *C:\\Windows\\Temp\\* OR *\\AppData\\*)"
  - name: ETW Bypass via ntdll.dll Patching
    status: high
    query: "source:mde @action_type:VirtualProtectApiCall @file.name:ntdll.dll (@memory.new_protection:ExecuteReadWrite OR @memory.new_protection:0x40)"
  - name: Brute-Force Followed by Successful Logon
    status: high
    query: "source:wineventlog @winlog.event_id:(4624 OR 4625) @logon.type:(3 OR 10)"
signal_correlation:
  rule_id: comprehensive_ivanti_exploitation_ttps
  group_by_fields:
    - @host
    - @user.name
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 2
    timeframe: 1h
message: "Comprehensive Ivanti Exploitation TTPs: {distinct_count} distinct techniques on host {@host} by user {@user.name}. Techniques: {case_names}. Details: {@process.image OR @file.target_filename OR @network.destination.hostname OR @process.command_line OR @registry.details OR @file.name}. Timeframe: {first_activity} to {last_activity}"
severity: high
tags:
  - security:attack
  - tactic:TA0003
  - tactic:TA0004
  - tactic:TA0005
  - tactic:TA0006
  - tactic:TA0007
  - tactic:TA0011
  - tactic:TA0008
  - technique:T1574.001
  - technique:T1027
  - technique:T1071.001
  - technique:T1046
  - technique:T1018
  - technique:T1136.002
  - technique:T1098
  - technique:T1543.003
  - technique:T1053.005
  - technique:T1562.001
  - technique:T1110.001
  - technique:T1021.001
  - technique:T1021.002
options:
  evaluation_window: 1h
```

### UNC6384 (Mustang Panda) Campaign IOCs and TTPs
---

description: Detects multiple indicators of compromise (IOCs) and tactics, techniques, and procedures (TTPs) associated with a UNC6384 (Mustang Panda) campaign targeting diplomats, as reported by Google in August 2025. This rule covers file hashes, network indicators, persistence mechanisms, and behavioral patterns related to the STATICPLUGIN, CANONSTAGER, and SOGU.SEC malware families.

author: RW

date: 2025-08-26

```yaml
name: UNC6384 Mustang Panda Campaign IOCs and TTPs
type: signal_correlation
cases:
  - name: Malicious File Hash
    status: high
    query: "source:sysmon @file.sha256:(65c42a7ea18162a92ee982eded91653a5358a7129c7672715ce8ddb6027ec124 OR 3299866538aff40ca85276f87dd0cefe4eafe167bd64732d67b06af4f3349916 OR e787f64af048b9cb8a153a0759555785c8fd3ee1e8efbca312a29f2acb1e4011 OR cc4db3d8049043fa62326d0b3341960f9a0cf9b54c2fbbdffdbd8761d99add79 OR d1626c35ff69e7e5bde5eea9f9a242713421e59197f4b6d77b914ed46976b933)"
  - name: Malicious Network Connection
    status: high
    query: "source:sysmon @winlog.event_id:3 (@network.destination.ip:(103.79.120.72 OR 166.88.2.90) OR @network.destination.hostname:mediareleaseupdates.com)"
  - name: SOGU.SEC User Agent
    status: medium
    query: "source:network @http.user_agent:"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 10.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)""
  - name: CanonPrinter Persistence
    status: high
    query: "source:sysmon @winlog.event_id:(12 OR 13 OR 14) @registry.target_object:*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\CanonPrinter @registry.details:cnmpaui.exe"
  - name: CANONSTAGER DLL Sideloading
    status: high
    query: "source:sysmon @winlog.event_id:7 @process.image:\cnmpaui.exe @process.image_loaded:\cnmpaui.dll"
  - name: Suspicious File Path
    status: high
    query: "source:sysmon @winlog.event_id:1 @process.image:(\DNVjzaXMFO\ OR C:\Users\Public\Intelnet\ OR C:\Users\Public\SecurityScan\)"
signal_correlation:
  rule_id: unc6384_mustang_panda_campaign_iocs_and_ttps
  group_by_fields:
    - @host
    - @user.name
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 2
    timeframe: 1h
message: "UNC6384 Mustang Panda Campaign: {distinct_count} distinct techniques on host {@host} by user {@user.name}. Techniques: {case_names}. Details: {@file.sha256 OR @network.destination.ip OR @network.destination.hostname OR @http.user_agent OR @registry.target_object OR @process.image_loaded OR @process.image}. Timeframe: {first_activity} to {last_activity}"
severity: high
tags:
  - security:attack
  - tactic:TA0001
  - tactic:TA0002
  - tactic:TA0003
  - tactic:TA0005
  - tactic:TA0011
  - technique:T1566
  - technique:T1574
  - technique:T1547.001
  - technique:T1071
  - technique:T1027
options:
  evaluation_window: 1h
```

### CCP Network Device Activity
---

description: Detects TTPs associated with CCP actors targeting network infrastructure, including enabling backdoors, modifying ACLs, creating users, and capturing traffic.

author: RW

date: 2025-08-29

references: https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a

tags: persistence, defense_evasion, credential_access, collection, t1021.004, t1562.004, t1136.001, t1040, t1059.008, t1571

falsepositives: Legitimate administrative activity may trigger command matches. High-port SSH (xxx22) may match legitimate services. Baseline normal activity and filter known good IPs.

level: high

```yaml
name: CCP Network Device Exploitation TTPs
type: signal_correlation
cases:
  - name: SSH Backdoor Activation
    status: high
    query: "source:cisco OR source:paloalto OR source:linux OR source:firewall (\"service sshd_operns start\" OR network.destination.port:57722 OR network.destination.port:/^\\d{3,5}22$/)"
  - name: Suspicious ACL Modifications
    status: high
    query: "source:cisco OR source:paloalto OR source:linux OR source:firewall (\"access-list 10\" OR \"access-list 20\" OR \"access-list 50\")"
  - name: Unauthorized User Creation
    status: high
    query: "source:cisco OR source:paloalto OR source:linux OR source:firewall (\"useradd cisco\" OR \"vi /etc/sudoers\")"
  - name: Packet Capture Activity
    status: high
    query: "source:cisco OR source:paloalto OR source:linux OR source:firewall (\"monitor capture\" OR \"span\" OR \"erspan\" OR \"mycap.pcap\" OR \"tac.pcap\" OR \"1.pcap\")"
signal_correlation:
  rule_id: ccp_network_device_exploitation_ttps
  group_by_fields:
    - host
    - user
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 2
    timeframe: 1h
message: "CCP Network Device Exploitation TTPs: {distinct_count} distinct techniques on host {host} by user {user}. Techniques: {case_names}. Details: {message OR network.destination.ip OR network.destination.port}. Timeframe: {first_activity} to {last_activity}"
severity: high
tags:
  - security:attack
  - tactic:TA0003
  - tactic:TA0005
  - tactic:TA0006
  - tactic:TA0007
  - tactic:TA0011
  - technique:T1021.004
  - technique:T1562.004
  - technique:T1136.001
  - technique:T1040
  - technique:T1059.008
  - technique:T1571
options:
  evaluation_window: 1h
```

### Silver Fox APT Leverages Vulnerable Drivers for Evasion and ValleyRAT Delivery
---

Title: Silver Fox APT Multi-Stage Activity

Description: Detects a combination of TTPs associated with the Silver Fox APT group. This rule correlates persistence mechanisms, vulnerable driver abuse for defense evasion, and C2 communications related to the ValleyRAT backdoor deployment.

References: https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/

Author: RW

Date: 2025-08-30

False Positives: Legitimate installations or use of WatchDog Antimalware might trigger parts of this rule. However, the correlation with the specific vulnerable driver hash and at least one other suspicious activity significantly reduces the likelihood of false positives.

Level: High

```yaml
name: Multi-Stage Activity Detection
type: signal_correlation
cases:
  - name: Vulnerable Driver Loaded
    status: high
    query: >-
      @event_type:module_load @hash.sha256:(
        "12b3d8bc5cc1ea6e2acd741d8a80f56cf2a0a7ebfa0998e3f0743fcf83fabb9e" OR
        "0be8483c2ea42f1ce4c90e84ac474a4e7017bc6d682e06f96dc1e31922a07b10" OR
        "9c394dcab9f711e2bf585edf0d22d2210843885917d409ee56f22a4c24ad225e"
      )
  - name: Suspicious File Written
    status: high
    query: >-
      @event_type:file_write @file.path:"C:\\Program Files\\RunTime\\*"
      @file.name:("RuntimeBroker.exe" OR "Amsdk_Service.sys")
  - name: Suspicious Service Created
    status: high
    query: >-
      @event_type:registry @registry.path:(
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Termaintor*" OR
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Amsdk_Service*"
      )
  - name: C2 Traffic Detected
    status: high
    query: >-
      @event_type:network @destination.ip:(
        "47.239.197.97" OR "8.217.38.238" OR "156.234.58.194" OR
        "156.241.144.66" OR "1.13.249.217"
      ) @destination.port:(52116 OR 52117 OR 8888 OR 52110 OR 52111 OR 52139 OR 52160 OR 9527 OR 9528)
signal_correlation:
  rule_id: multi_stage_activity_detection
  group_by_fields:
    - @host
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 2 AND indicators MATCHES "Vulnerable_Driver_Loaded"
    timeframe: 1h
message: >-
  Multi-Stage Activity Detection: {distinct_count} distinct indicators on host {@host}.
  Techniques: {case_names}. Details: {@hash.sha256 OR @file.path OR @registry.path OR @destination.ip}:{@destination.port}.
  Timeframe: {first_activity} to {last_activity}.
  Note: IOCTL detection (DeviceIoControl to 'amsdk' with codes 0x80002010, 0x80002048) requires specific EDR logs.
  This activity may also be present but is not detected by this query.
severity: high
tags:
  - security:attack
  - tactic:TA0002
  - tactic:TA0005
  - tactic:TA0011
  - technique:T1574
  - technique:T1071
options:
  evaluation_window: 1h
```

### APT28 NotDoor Backdoor Activity Detection
---

Author: RW

Date: 2025-09-03

Description: This rule detects various activities associated with the NotDoor backdoor, used by APT28. It looks for specific file creation events, process command lines, registry modifications, and network communications.

False Positive Sensitivity: Medium

```yaml
name: APT28 NotDoor Backdoor Activity Detection
type: signal_correlation
cases:
  - name: Malicious File Hash Detected
    status: high
    query: >-
      @event.code:11 @file.sha256:(
        "5a88a15a1d764e635462f78a0cd958b17e6d22c716740febc114a408eef66705" OR
        "8f4bca3c62268fff0458322d111a511e0bcfba255d5ab78c45973bd293379901"
      )
  - name: Initial Backdoor File Drop
    status: high
    query: >-
      @event.code:11 @file.path:"C:\\ProgramData\\testtemp.ini"
  - name: Staging File Creation
    status: high
    query: >-
      @event.code:11 @file.path:*\\AppData\\Local\\Temp\\Test\\(report|invoice|contract|photo|scheme|document)_[^\\]+\\.(jpg|jpeg|gif|bmp|ico|png|pdf|doc|docx|xls|xlsx|ppt|pptx|mp3|mp4|xml)$
  - name: Backdoor Macro Installation
    status: high
    query: >-
      @event.code:1 @process.cmd_line:*copy.*c:\\programdata\\testtemp.ini.*\\Microsoft\\Outlook\\VbaProject.OTM
  - name: C2 Verification via nslookup
    status: high
    query: >-
      @event.code:1 @process.name:"nslookup.exe" @process.cmd_line:*.dnshook.site
  - name: C2 Verification via curl
    status: high
    query: >-
      @event.code:1 @process.name:"curl.exe" @process.cmd_line:*webhook.site
  - name: Outlook Persistence
    status: high
    query: >-
      @event.code:13 @registry.target_object:*\\Software\\Microsoft\\Office\\[^\\]+\\Outlook\\LoadMacroProviderOnBoot$ @registry.details:1
  - name: Outlook Macro Security Disabled
    status: high
    query: >-
      @event.code:13 @registry.target_object:*\\Software\\Microsoft\\Office\\[^\\]+\\Outlook\\Security\\Level$ @registry.details:1
  - name: Outlook Macro Warning Disabled
    status: high
    query: >-
      @event.code:13 @registry.target_object:*\\Software\\Microsoft\\Office\\[^\\]+\\Outlook\\Options\\General\\PONT_STRING$ @registry.details:;
  - name: C2 DNS Query
    status: high
    query: >-
      (@event.code:22 OR @sourcetype:stream:dns) @network.dns.query:*.(webhook|dnshook).site$
  - name: C2 HTTP Connection
    status: high
    query: >-
      @sourcetype:stream:http @network.http.dest_host:*.(webhook|dnshook).site$
  - name: Exfiltration Email Sent
    status: high
    query: >-
      @sourcetype:your_email_log_sourcetype @email.to:"a.matti444@proton.me" @email.subject:"Re: 0"
signal_correlation:
  rule_id: apt28_notdoor_backdoor_detection
  group_by_fields:
    - @host
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 2 AND indicators MATCHES "Malicious_File_Hash_Detected"
    timeframe: 1h
message: >-
  APT28 NotDoor Backdoor Activity Detected: {distinct_count} distinct indicators on host {@host}.
  Techniques: {case_names}. Details: {@file.sha256 OR @file.path OR @process.cmd_line OR @registry.target_object OR @network.dns.query OR @network.http.dest_host OR @email.to}:{@email.subject}.
  Timeframe: {first_activity} to {last_activity}.
  Note: Legitimate use of webhook.site/dnshook.site or Outlook macro settings may cause false positives.
severity: high
tags:
  - security:attack
  - tactic:TA0003
  - tactic:TA0005
  - tactic:TA0011
  - tactic:TA0010
  - technique:T1059
  - technique:T1114
options:
  evaluation_window: 1h
```

### MeetC2 C2 Activity via Google Calendar API
---
```yaml
name: MeetC2 C2 Activity via Google Calendar API
type: signal_correlation
cases:
  - name: MeetC2 Command Pattern in Event Summary
    status: medium
    query: >-
      source:(gcp OR google_workspace) AND @name:("calendar.events.insert" OR "calendar.events.update" OR "calendar.acl.create") AND @parameters.summary:"*Meeting from nobody:*[COMMAND]*"
  - name: MeetC2 Output Pattern in Event Description
    status: medium
    query: >-
      source:(gcp OR google_workspace) AND @name:("calendar.events.insert" OR "calendar.events.update" OR "calendar.acl.create") AND @parameters.description:"*[OUTPUT]*" AND @parameters.description:"*[/OUTPUT]*"
  - name: Calendar Shared with Service Account
    status: medium
    query: >-
      source:(gcp OR google_workspace) AND @name:("calendar.events.insert" OR "calendar.events.update" OR "calendar.acl.create") AND @parameters.acl.scope.value:"*gserviceaccount.com"
  - name: Potential C2 Beaconing to Google Calendar API
    status: medium
    query: >-
      source:(proxy OR network) AND @url:"*www.googleapis.com/calendar/v3/calendars/*/events*" AND -@process_path:/(chrome|msedge|firefox|outlook|teams)\.exe$/i
signal_correlation:
  rule_id: meetc2_c2_activity_detection
  group_by_fields:
    - @src_ip
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 10m
message: >-
  MeetC2 C2 Activity via Google Calendar API Detected: {distinct_count} distinct indicators on IP {@src_ip}.
  Techniques: {case_names}. Details: {@parameters.summary OR @parameters.description OR @parameters.acl.scope.value OR @url}.
  Timeframe: {first_activity} to {last_activity}.
  Note: Legitimate applications using the Google Calendar API may generate a high volume of requests. Calendar sharing with service accounts for legitimate automation purposes can also trigger this rule. Tuning of the beaconing threshold and process exclusion list is recommended.
severity: medium
tags:
  - security:attack
  - tactic:TA0011
  - technique:T1071.001
  - technique:T1102.002
options:
  evaluation_window: 10m
```

### APT37 Rustonotto, Chinotto, FadeStealer Activity
---
```yaml
name: APT37 Rust/Python Backdoor Activity Detection
type: signal_correlation
cases:
  - name: File Hash IOC
    status: high
    query: >-
      @event.code:("1" OR "11") @file.hash.md5:(
        "b9900bef33c6cc9911a5cd7eeda8e093" OR
        "7967156e138a66f3ee1bfce81836d8d0" OR
        "77a70e87429c4e552649235a9a2cf11a" OR
        "04b5e068e6f0079c2c205a42df8a3a84" OR
        "d2b34b8bfafd6b17b1cf931bb3fdd3db" OR
        "3d6b999d65c775c1d27c8efa615ee520" OR
        "89986806a298ffd6367cf43f36136311" OR
        "4caa44930e5587a0c9914bda9d240acc"
      )
  - name: Malicious File Artifact
    status: high
    query: >-
      @event.code:11 @file.path:(
        "C:\\ProgramData\\3HNoWZd.exe" OR
        "C:\\ProgramData\\wonder.cab" OR
        "C:\\ProgramData\\tele_update.exe" OR
        "C:\\ProgramData\\tele.conf" OR
        "C:\\ProgramData\\tele.dat" OR
        "C:\\ProgramData\\Password.chm" OR
        "C:\\ProgramData\\1.html" OR
        /\\VSTelems_Fade\\(NgenPdbk|NgenPdbc|NgenPdbm|VSTelems_FadeOut|VSTelems_FadeIn)/i OR
        /(watch_|usb_|data_).+\.rar$/i
      )
  - name: Suspicious Process Execution
    status: high
    query: >-
      @event.code:1 (
        @process.command_line:/schtasks.* \/create .*MicrosoftUpdate.*3HNoWZd\.exe/i OR
        (@process.path:*\\mshta.exe AND @process.command_line:*http*) OR
        (@parent_process.path:*\\cmd.exe AND @process.path:*\\expand.exe AND @process.command_line:*c:\\programdata\\wonder.cab*) OR
        @process.path:"c:\\programdata\\tele_update.exe"
      )
  - name: Registry Run Key Persistence
    status: high
    query: >-
      @event.code:13 @registry.path:/\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OnedriveStandaloneUpdater/i @registry.data:/mshta.*http/i
  - name: C2 Communication Pattern
    status: high
    query: >-
      @url:*U=%* (@url:*R=%* OR @url:*_file=%*)
signal_correlation:
  rule_id: fadestealer_activity_detection
  group_by_fields:
    - @dest_host
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 10m
message: >-
  FadeStealer Activity Detected: {distinct_count} distinct indicators on host {@dest_host}.
  Techniques: {case_names}. Details: {@file.hash.md5 OR @file.path OR @process.command_line OR @registry.path OR @url}.
  Timeframe: {first_activity} to {last_activity}.
  Note: False positives may occur due to legitimate use of similar file paths or process executions. Tune file paths and command line patterns as needed.
severity: high
tags:
  - security:attack
  - tactic:TA0003
  - tactic:TA0005
  - tactic:TA0011
  - technique:T1059
  - technique:T1547.001
options:
  evaluation_window: 10m
```

### Exposed Docker APIs Are Targeted in New Malware Strain
---

author: RW

- This detection rule identifies a multi-stage attack targeting exposed Docker APIs.
- The malware strain aims to establish persistent root access, create a botnet, and perform reconnaissance.
- This rule combines several detection concepts into a single query to provide a broad overview of related malicious activities.

```yaml
name: Exposed Docker APIs Malware Detection
type: signal_correlation
cases:
  - name: Docker API Exploitation
    status: high
    query: >-
      source:(http OR suricata OR zeek) AND @http.method:POST AND @url.path:("/containers/create*" OR "/images/create*") AND @destination.port:2375
  - name: Post-Exploitation Command Execution
    status: high
    query: >-
      source:(linux_audit OR sysmon_linux OR falco) AND (@process.name:("sh" OR "bash") AND @process.args:(*curl* OR *wget*)) OR @process.name:("apk" OR "apt" OR "yum")
  - name: Persistence Techniques
    status: high
    query: >-
      source:(linux_audit OR sysmon_linux OR osquery) AND (@file.path:("/root/.ssh/authorized_keys" OR "/etc/crontab" OR "/etc/cron.d/*" OR "/var/spool/cron/*") AND @file.operation:(write OR create)) OR (@process.name:("firewall-cmd" OR "iptables") AND @process.args:(*--add-rich-rule* OR *--reload* OR *-A INPUT* OR *-p tcp*))
  - name: Discovery and Lateral Movement
    status: high
    query: >-
      source:(linux_audit OR sysmon_linux OR tcp OR suricata OR zeek) AND @process.name:masscan OR @destination.port:(23 OR 9222 OR 2375)
  - name: C2 Communication via Tor
    status: high
    query: >-
      source:(dns OR zeek_dns OR linux_audit OR sysmon_linux) AND (@dns.query:*.onion OR @process.name:torsocks)
signal_correlation:
  rule_id: docker_malware_detection
  group_by_fields:
    - @src_ip
    - @dest_ip
    - @dest_host
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 10m
message: >-
  Exposed Docker APIs Malware Activity Detected: {distinct_count} distinct indicators on host {@dest_host} or IP {@src_ip}/{@dest_ip}.
  Techniques: {case_names}. Details: {@url.path OR @process.name OR @process.args OR @file.path OR @dns.query}.
  Timeframe: {first_activity} to {last_activity}.
  Note: Legitimate Docker API usage, package installations, or network scans may trigger FPs. Filter by known-good IPs, user agents, or baseline legitimate port activity.
severity: high
tags:
  - security:attack
  - tactic:TA0001
  - tactic:TA0002
  - tactic:TA0003
  - tactic:TA0007
  - tactic:TA0011
  - technique:T1190
  - technique:T1059
  - technique:T1547
  - technique:T1018
  - technique:T1071
options:
  evaluation_window: 10m
```