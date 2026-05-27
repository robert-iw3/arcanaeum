### ECScape: Understanding IAM Privilege Boundaries in Amazon ECS
---

The ECScape exploit demonstrates a privilege escalation vulnerability in Amazon ECS on EC2, where a compromised low-privileged container can impersonate the ECS agent to gain access to IAM credentials of all other tasks on the same EC2 instance. This attack highlights that containers on EC2 do not provide a strong security boundary, and the EC2 instance itself is the primary security perimeter.

Recent research on ECScape, presented at Black Hat USA 2025, details a five-step exploit chain allowing a low-privileged ECS task to impersonate the ECS agent and harvest credentials for all co-located tasks, emphasizing the critical need for robust monitoring and stricter isolation in ECS on EC2 environments.

### Actionable Threat Data
---

Unauthorized IMDS Access: Monitor for unexpected or unauthorized attempts by ECS tasks to access the EC2 Instance Metadata Service (IMDS) at http://169.254.169.254/latest/meta-data/iam/security-credentials/. This is the initial step for an attacker to obtain the `ecsInstanceRole` credentials.

Unusual `ecs:DiscoverPollEndpoint` and `ecs:Poll` API Calls: Look for calls to the `ecs:DiscoverPollEndpoint` and `ecs:Poll` APIs originating from sources other than the legitimate ECS agent. These API calls are exclusively used by the ECS agent to communicate with the ECS control plane.

Suspicious AWS API Calls from Low-Privilege Tasks: Detect instances where low-privileged ECS tasks perform AWS API calls that are outside their normal operational scope or indicative of privilege escalation, such as `sts:AssumeRole` or other sensitive IAM actions.

Abnormal Network Connections to 169.254.170.2: Monitor for connections to the container credentials endpoint `169.254.170.2` from unexpected processes or containers within an EC2 instance, especially if the `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` environment variable is not set for the connecting process.

Compromised ECS Agent Behavior: Look for anomalies in the ECS agent's communication patterns, such as a sudden increase in credential requests or attempts to register new container instances from an already registered host.

### AWS ECScape Unauthorized IMDS Credential Access
---
```sql
`tstats` summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*169.254.169.254/latest/meta-data/iam/security-credentials*") AND Processes.process_name!="ecs-agent" by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.container_id | \
`rename Processes.* as *` | \
`drop count` | \
-- Convert timestamps to human-readable format
`fieldformat firstTime = strftime(firstTime, "%Y-%m-%d %H:%M:%S")` | \
`fieldformat lastTime = strftime(lastTime, "%Y-%m-%d %H:%M:%S")` | \
-- Provide context for the alert
`fillnull value="N/A" container_id` | \
-- Comment: This detection identifies processes, excluding the legitimate 'ecs-agent', that are querying the EC2 IMDS for credentials.
-- The presence of a 'container_id' significantly increases the alert's fidelity, as containers should use the ECS-provided credential endpoint (169.254.170.2), not the host's IMDS.
-- False Positives: Custom startup scripts or legacy applications running in containers might perform this action.
-- Tuning: If legitimate processes are flagged, add them to the exclusion list, e.g., `... AND NOT (Processes.process_name IN ("ecs-agent", "your_legit_process"))`
`where isnotnull(container_id) OR process_name!="dockerd"`
```

### Unusual ECS API Calls
---
```sql
`cloudtrail` eventName IN (DiscoverPollEndpoint, Poll) userAgent!="*amazon-ecs-agent*"
| stats count min(_time) as firstTime max(_time) as lastTime by eventName, awsRegion, sourceIPAddress, userIdentity.arn, userAgent
-- Rename fields for clarity in the alert.
| rename userIdentity.arn as principal_arn, sourceIPAddress as src_ip
-- Convert timestamps to a human-readable format.
| fieldformat firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S")
| fieldformat lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
-- Comment: This detection looks for the key API calls used by the ECS agent to communicate with the control plane. A non-standard user agent (e.g., aws-cli, boto3) making these calls is highly suspicious and may indicate an attacker impersonating the agent.
-- False Positives: Custom administrative or monitoring scripts might legitimately make these calls.
-- Tuning: If you have legitimate tools that perform this action, add their user agents to the exclusion list, e.g., `... userAgent!="*amazon-ecs-agent*" AND userAgent!="*MyCustomTool*"`
```

### Suspicious AWS API Calls
---
```sql
`cloudtrail` invokedBy="ecs-tasks.amazonaws.com" eventName IN (
    # STS/IAM Privilege Escalation & Manipulation
    "AssumeRole", "CreatePolicy", "AttachRolePolicy", "PutRolePolicy", "CreateUser", "CreateAccessKey", "UpdateAssumeRolePolicy",
    # ECS Agent Impersonation
    "RegisterContainerInstance", "DeregisterContainerInstance",
    # Data/Resource Creation & Exfiltration
    "CreateSecret", "PutSecretValue", "CreateFunction", "RunInstances"
)
-- Optional: Exclude known benign combinations of task roles and actions via a lookup.
-- | search NOT [| inputlookup known_good_ecs_task_actions.csv | fields task_role_arn eventName]

-- Aggregate events to reduce noise and summarize activity.
| stats count min(_time) as firstTime max(_time) as lastTime values(requestParameters.roleArn) as assumed_role_arn values(requestParameters.policyArn) as policy_arn by eventName, awsRegion, sourceIPAddress, userIdentity.arn, userAgent
-- Rename fields for clarity in the alert.
| rename userIdentity.arn as task_role_arn, sourceIPAddress as src_ip
-- Convert timestamps to a human-readable format.
| fieldformat firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S")
| fieldformat lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
-- Comment: This detection flags sensitive API calls made by an ECS task's IAM role. Such actions are unusual for most application containers and can be an indicator of a container breakout or exploit.
-- False Positives: Legitimate administrative or CI/CD tasks may perform these actions. These should be profiled and added to an allow-list (e.g., a lookup file) to tune the detection.
-- Tuning: Create a lookup file named 'known_good_ecs_task_actions.csv' with columns 'task_role_arn' and 'eventName' to filter out expected activity. Uncomment the search line above to use it.
```

### Abnormal Container Credential Access
---
```sql
`tstats` summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest_ip="169.254.170.2" by All_Traffic.src, All_Traffic.user, All_Traffic.process_name, All_Traffic.container_id
| `drop count`
| `rename All_Traffic.src as src_host, All_Traffic.process_name as process, All_Traffic.container_id as container_id`
-- Convert timestamps to a human-readable format.
| `fieldformat firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S")`
| `fieldformat lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")`
-- Fill null container_id to ensure events on the host itself are not dropped if they occur.
| `fillnull value="N/A" container_id`
-- Comment: This detection flags any network connection to the ECS container credential endpoint. Legitimate applications using an AWS SDK will make these connections. However, an attacker might use tools like 'curl' or custom scripts to probe this endpoint to steal credentials.
-- False Positives: Any application running in ECS that uses an AWS SDK will trigger this. This rule is designed to provide visibility and requires baselining of normal application behavior.
-- Tuning: Create a lookup of known-good combinations of hosts and processes that are expected to access this endpoint and filter them out. For example: | search NOT [| inputlookup allowlist_ecs_credential_access.csv | fields src_host process]
```

### Compromised ECS Agent Behavior
---
```sql
`cloudtrail` eventName=RegisterContainerInstance
-- Group events by day and by the source IP and IAM principal that performed the registration.
| bin _time span=1d
| stats count, dc(userAgent) as distinct_user_agents, values(userAgent) as user_agents, values(requestParameters.cluster) as cluster by _time, sourceIPAddress, userIdentity.arn, awsRegion
-- An instance registering more than once in a day is anomalous.
| where count > 1
-- Rename fields for clarity in the alert.
| rename sourceIPAddress as src_ip, userIdentity.arn as principal_arn
| `fieldformat _time=strftime(_time, "%Y-%m-%d")`
-- Comment: This detection flags an EC2 instance IP that registers with ECS more than once in a 24-hour window. This is abnormal behavior, as a healthy ECS agent registers once and maintains its session. Multiple registrations could indicate an agent crash loop or an attacker attempting to impersonate the agent after compromising the instance role.
-- False Positives: This could be triggered by an unstable ECS agent that is frequently crashing and restarting, or by automated host cycling/replacement logic that reuses IP addresses quickly.
-- Tuning: The time span can be adjusted. If frequent re-registrations are normal in your environment for specific clusters or roles, they can be filtered out. For example: `... | where count > 1 AND principal_arn!="arn:aws:iam::123456789012:role/MyFlappyRole"`
```