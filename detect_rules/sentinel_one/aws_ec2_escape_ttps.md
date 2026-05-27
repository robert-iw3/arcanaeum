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
EventType=Process
AND (CommandLine="*169.254.169.254/latest/meta-data/iam/security-credentials*" AND ProcessName!="ecs-agent")
AND (ContainerID IS NOT NULL OR ProcessName!="dockerd")
| SELECT MIN(Timestamp) AS firstTime, MAX(Timestamp) AS lastTime, AgentID, UserName, ParentProcessName, ProcessName, CommandLine, IFNULL(ContainerID, "N/A") AS ContainerID
| GROUP BY AgentID, UserName, ParentProcessName, ProcessName, CommandLine, ContainerID
| FORMAT firstTime="%Y-%m-%d %H:%M:%S", lastTime="%Y-%m-%d %H:%M:%S"
```

### Unusual ECS API Calls
---
```sql
EventType=CloudTrail
AND EndpointName IN ("DiscoverPollEndpoint", "Poll")
AND UserAgent NOT LIKE "*amazon-ecs-agent*"
| SELECT MIN(Timestamp) AS firstTime, MAX(Timestamp) AS lastTime, EndpointName, CloudRegion, SrcIP, UserIdentityARN, UserAgent
| GROUP BY EndpointName, CloudRegion, SrcIP, UserIdentityARN, UserAgent
| FORMAT firstTime="%Y-%m-%d %H:%M:%S", lastTime="%Y-%m-%d %H:%M:%S"
| RENAME UserIdentityARN AS principal_arn, SrcIP AS src_ip
```

### Suspicious AWS API Calls
---
```sql
EventType=CloudTrail
AND InvokedBy="ecs-tasks.amazonaws.com"
AND EndpointName IN ("AssumeRole", "CreatePolicy", "AttachRolePolicy", "PutRolePolicy", "CreateUser", "CreateAccessKey", "UpdateAssumeRolePolicy", "RegisterContainerInstance", "DeregisterContainerInstance", "CreateSecret", "PutSecretValue", "CreateFunction", "RunInstances")
| SELECT MIN(Timestamp) AS firstTime, MAX(Timestamp) AS lastTime, EndpointName, CloudRegion, SrcIP, UserIdentityARN, UserAgent, GROUP_CONCAT(RequestParameters_roleArn) AS assumed_role_arn, GROUP_CONCAT(RequestParameters_policyArn) AS policy_arn
| GROUP BY EndpointName, CloudRegion, SrcIP, UserIdentityARN, UserAgent
| FORMAT firstTime="%Y-%m-%d %H:%M:%S", lastTime="%Y-%m-%d %H:%M:%S"
| RENAME UserIdentityARN AS task_role_arn, SrcIP AS src_ip
```

### Abnormal Container Credential Access
---
```sql
EventType=Network
AND DstIP="169.254.170.2"
| SELECT MIN(Timestamp) AS firstTime, MAX(Timestamp) AS lastTime, SrcIP, UserName, ProcessName, IFNULL(ContainerID, "N/A") AS ContainerID
| GROUP BY SrcIP, UserName, ProcessName, ContainerID
| FORMAT firstTime="%Y-%m-%d %H:%M:%S", lastTime="%Y-%m-%d %H:%M:%S"
| RENAME SrcIP AS src_host, ProcessName AS process
```

### Compromised ECS Agent Behavior
---
```sql
EventType=CloudTrail
AND EndpointName="RegisterContainerInstance"
| BUCKET Timestamp BY 1d AS _time
| SELECT COUNT(*) AS count, COUNT(DISTINCT UserAgent) AS distinct_user_agents, GROUP_CONCAT(UserAgent) AS user_agents, GROUP_CONCAT(RequestParameters_cluster) AS cluster, _time, SrcIP, UserIdentityARN, CloudRegion
| GROUP BY _time, SrcIP, UserIdentityARN, CloudRegion
| WHERE count > 1
| FORMAT _time="%Y-%m-%d"
| RENAME SrcIP AS src_ip, UserIdentityARN AS principal_arn
```