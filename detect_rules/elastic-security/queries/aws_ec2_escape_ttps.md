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
FROM *
| WHERE event.category == "process"
  AND process.command_line LIKE "*169.254.169.254/latest/meta-data/iam/security-credentials*"
  AND process.name != "ecs-agent"
  AND (container.id IS NOT NULL OR process.name != "dockerd")
| EVAL container_id = COALESCE(container.id, "N/A")
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.id, process.user.name, process.parent.name, process.name, process.command_line, container_id
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd HH:mm:ss")
```

### Unusual ECS API Calls
---
```sql
FROM *
| WHERE event.dataset == "aws.cloudtrail"
  AND event.action IN ("DiscoverPollEndpoint", "Poll")
  AND user_agent.original NOT LIKE "*amazon-ecs-agent*"
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY event.action, aws.cloudtrail.awsRegion, source.ip, aws.cloudtrail.userIdentity.arn, user_agent.original
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd HH:mm:ss")
| RENAME aws.cloudtrail.userIdentity.arn AS principal_arn, source.ip AS src_ip
```

### Suspicious AWS API Calls
---
```sql
FROM *
| WHERE event.dataset == "aws.cloudtrail"
  AND aws.cloudtrail.invokedBy == "ecs-tasks.amazonaws.com"
  AND event.action IN ("AssumeRole", "CreatePolicy", "AttachRolePolicy", "PutRolePolicy", "CreateUser", "CreateAccessKey", "UpdateAssumeRolePolicy", "RegisterContainerInstance", "DeregisterContainerInstance", "CreateSecret", "PutSecretValue", "CreateFunction", "RunInstances")
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), assumed_role_arn = ARRAY_AGG(aws.cloudtrail.requestParameters.roleArn), policy_arn = ARRAY_AGG(aws.cloudtrail.requestParameters.policyArn)
  BY event.action, aws.cloudtrail.awsRegion, source.ip, aws.cloudtrail.userIdentity.arn, user_agent.original
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd HH:mm:ss")
| RENAME aws.cloudtrail.userIdentity.arn AS task_role_arn, source.ip AS src_ip
```

### Abnormal Container Credential Access
---
```sql
FROM *
| WHERE event.category == "network"
  AND destination.ip == "169.254.170.2"
| EVAL container_id = COALESCE(container.id, "N/A")
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY source.ip, user.name, process.name, container_id
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd HH:mm:ss")
| RENAME source.ip AS src_host, process.name AS process
```

### Compromised ECS Agent Behavior
---
```sql
FROM *
| WHERE event.dataset == "aws.cloudtrail"
  AND event.action == "RegisterContainerInstance"
| EVAL _time = DATE_TRUNC("day", @timestamp)
| STATS count = COUNT(*), distinct_user_agents = COUNT(DISTINCT user_agent.original), user_agents = ARRAY_AGG(user_agent.original), cluster = ARRAY_AGG(aws.cloudtrail.requestParameters.cluster)
  BY _time, source.ip, aws.cloudtrail.userIdentity.arn, aws.cloudtrail.awsRegion
| WHERE count > 1
| EVAL _time = TO_STRING(_time, "yyyy-MM-dd")
| RENAME source.ip AS src_ip, aws.cloudtrail.userIdentity.arn AS principal_arn
```