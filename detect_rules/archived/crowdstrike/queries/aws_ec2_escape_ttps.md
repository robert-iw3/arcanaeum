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
event_simpleName=ProcessRollup2
| (ImageFileName="*169.254.169.254/latest/meta-data/iam/security-credentials*" !ImageFileName="*ecs-agent")
| groupBy(aid, UserName, ParentBaseFileName, ImageFileName, CommandLine, ContainerId, min(event_platformTime) as firstTime, max(event_platformTime) as lastTime)
| where (ContainerId!=null || ImageFileName!="dockerd")
| eval firstTime=strftime(firstTime/1000, "%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime/1000, "%Y-%m-%d %H:%M:%S")
| eval ContainerId=if(ContainerId=null, "N/A", ContainerId)
```

### Unusual ECS API Calls
---
```sql
event_simpleName=CloudTrailEvent
| eventName IN ("DiscoverPollEndpoint", "Poll")
| !userAgent="*amazon-ecs-agent*"
| groupBy(eventName, awsRegion, sourceIPAddress, userIdentity_arn, userAgent, min(event_platformTime) as firstTime, max(event_platformTime) as lastTime)
| eval firstTime=strftime(firstTime/1000, "%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime/1000, "%Y-%m-%d %H:%M:%S")
| rename userIdentity_arn as principal_arn, sourceIPAddress as src_ip
```

### Suspicious AWS API Calls
---
```sql
event_simpleName=CloudTrailEvent
| invokedBy="ecs-tasks.amazonaws.com"
| eventName IN ("AssumeRole", "CreatePolicy", "AttachRolePolicy", "PutRolePolicy", "CreateUser", "CreateAccessKey", "UpdateAssumeRolePolicy", "RegisterContainerInstance", "DeregisterContainerInstance", "CreateSecret", "PutSecretValue", "CreateFunction", "RunInstances")
| groupBy(eventName, awsRegion, sourceIPAddress, userIdentity_arn, userAgent, min(event_platformTime) as firstTime, max(event_platformTime) as lastTime, values(requestParameters_roleArn) as assumed_role_arn, values(requestParameters_policyArn) as policy_arn)
| eval firstTime=strftime(firstTime/1000, "%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime/1000, "%Y-%m-%d %H:%M:%S")
| rename userIdentity_arn as task_role_arn, sourceIPAddress as src_ip
```

### Abnormal Container Credential Access
---
```sql
event_simpleName=NetworkConnect
| TargetAddress="169.254.170.2"
| groupBy(SourceAddress, UserName, ProcessName, ContainerId, min(event_platformTime) as firstTime, max(event_platformTime) as lastTime)
| eval firstTime=strftime(firstTime/1000, "%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime/1000, "%Y-%m-%d %H:%M:%S")
| eval ContainerId=if(ContainerId=null, "N/A", ContainerId)
| rename SourceAddress as src_host, ProcessName as process
```

### Compromised ECS Agent Behavior
---
```sql
event_simpleName=CloudTrailEvent
| eventName="RegisterContainerInstance"
| bucket(event_platformTime/1000, span="1d") as _time
| groupBy(_time, sourceIPAddress, userIdentity_arn, awsRegion, count(), distinctCount(userAgent) as distinct_user_agents, values(userAgent) as user_agents, values(requestParameters_cluster) as cluster)
| where count > 1
| eval _time=strftime(_time, "%Y-%m-%d")
| rename sourceIPAddress as src_ip, userIdentity_arn as principal_arn
```