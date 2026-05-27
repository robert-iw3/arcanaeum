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
process:*169.254.169.254/latest/meta-data/iam/security-credentials* -process.name:ecs-agent
| group by host, user, parent_process, process.name, process.command_line, container_id
| select min(@timestamp) as firstTime, max(@timestamp) as lastTime
| where container_id is not null OR process.name != "dockerd"
| format_time(firstTime, "%Y-%m-%d %H:%M:%S")
| format_time(lastTime, "%Y-%m-%d %H:%M:%S")
| fill_null(container_id, "N/A")
```

### Unusual ECS API Calls
---
```sql
eventName:(DiscoverPollEndpoint OR Poll) -userAgent:*amazon-ecs-agent*
| group by eventName, awsRegion, sourceIPAddress, userIdentity.arn, userAgent
| select min(@timestamp) as firstTime, max(@timestamp) as lastTime
| rename userIdentity.arn as principal_arn, sourceIPAddress as src_ip
| format_time(firstTime, "%Y-%m-%d %H:%M:%S")
| format_time(lastTime, "%Y-%m-%d %H:%M:%S")
```

### Suspicious AWS API Calls
---
```sql
invokedBy:ecs-tasks.amazonaws.com eventName:(AssumeRole OR CreatePolicy OR AttachRolePolicy OR PutRolePolicy OR CreateUser OR CreateAccessKey OR UpdateAssumeRolePolicy OR RegisterContainerInstance OR DeregisterContainerInstance OR CreateSecret OR PutSecretValue OR CreateFunction OR RunInstances)
| group by eventName, awsRegion, sourceIPAddress, userIdentity.arn, userAgent
| select min(@timestamp) as firstTime, max(@timestamp) as lastTime, values(requestParameters.roleArn) as assumed_role_arn, values(requestParameters.policyArn) as policy_arn
| rename userIdentity.arn as task_role_arn, sourceIPAddress as src_ip
| format_time(firstTime, "%Y-%m-%d %H:%M:%S")
| format_time(lastTime, "%Y-%m-%d %H:%M:%S")
```

### Abnormal Container Credential Access
---
```sql
dest_ip:169.254.170.2
| group by src, user, process.name, container_id
| select min(@timestamp) as firstTime, max(@timestamp) as lastTime
| rename src as src_host, process.name as process
| format_time(firstTime, "%Y-%m-%d %H:%M:%S")
| format_time(lastTime, "%Y-%m-%d %H:%M:%S")
| fill_null(container_id, "N/A")
```

### Compromised ECS Agent Behavior
---
```sql
eventName:RegisterContainerInstance
| bucket(@timestamp, 1d) as _time
| group by _time, sourceIPAddress, userIdentity.arn, awsRegion
| select count() as count, distinct_count(userAgent) as distinct_user_agents, values(userAgent) as user_agents, values(requestParameters.cluster) as cluster
| where count > 1
| rename sourceIPAddress as src_ip, userIdentity.arn as principal_arn
| format_time(_time, "%Y-%m-%d")
```