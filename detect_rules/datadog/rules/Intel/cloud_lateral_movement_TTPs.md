### Cloud Lateral Movement Techniques and Detections
---

This report details common lateral movement techniques observed in AWS, GCP, and Azure cloud environments, emphasizing how attackers leverage cloud APIs and misconfigurations to pivot between cloud resources and compute instances. Effective defense requires a combined approach of agent-based and agentless security solutions to gain comprehensive visibility into both host-level activities and cloud API calls.

Recent intelligence indicates a significant increase in cloud intrusions, with attackers increasingly using stealthier, malware-free techniques like credential abuse and lateral movement, highlighting the need for robust detection of cloud-native lateral movement. Additionally, the weaponization of AI is accelerating the speed of exploitation, reducing the time between vulnerability discovery and exploitation by 62%.

### Actionable Threat Data
---

AWS EC2 Instance Connect SSH Key Injection: Monitor for `SendSSHPublicKey` and `SendSerialConsoleSSHPublicKey` API calls, especially when originating from unexpected IP addresses or user identities, as these can indicate an attacker pushing SSH keys to gain access to EC2 instances or serial consoles.

GCP Metadata-Based SSH Key Modification: Detect modifications to instance or project metadata that involve adding or changing SSH keys (ssh-keys attribute), as this can grant attackers persistent access to Compute Engine instances.

Azure VMAccess Extension Abuse: Look for suspicious usage of the VMAccess extension, particularly actions that reset SSH public keys or create/reset local user passwords, which attackers can leverage to gain high-privileged access to Azure VMs.

AWS Systems Manager (SSM) Session Initiation: Identify unusual StartSession API calls to EC2 instances via SSM, especially if the initiating user or resource has no prior history of such activity, as this can indicate an attacker establishing an interactive shell session.

AWS Systems Manager (SSM) Command Execution: Monitor for SendCommand API calls, particularly those executing shell scripts (AWS-RunShellScript or AWS-RunPowerShellScript) or targeting a large number of instances, which could signify an attacker running commands at scale for information gathering or further compromise.

### AWS EC2 SSH Key Injection via Instance Connect
---
```sql
source:cloudtrail eventName:(SendSSHPublicKey OR SendSerialConsoleSSHPublicKey) errorCode:null
| select _time, eventName as api_call, awsRegion as region, sourceIPAddress as src_ip, userIdentity.arn as user_arn, requestParameters.instanceId as dest_instance_id, requestParameters.instanceOSUser as dest_os_user
| group by _time, user_arn, src_ip, region, api_call
| aggregate count, collect(dest_instance_id), collect(dest_os_user)
| filter user_arn !contains "known-admin-role" AND src_ip !matches "10.0.0.0/8"
| sort _time desc
```

### GCP Metadata SSH Key Modification
---
```sql
source:gcp.audit protoPayload.serviceName:compute.googleapis.com protoPayload.methodName:(v1.compute.instances.setMetadata OR v1.compute.projects.setCommonInstanceMetadata) protoPayload.status:null protoPayload.request.metadata.items.key:ssh-keys
| select _time, protoPayload.authenticationInfo.principalEmail as user, protoPayload.authenticationInfo.callerIp as src_ip, resource.labels.project_id as project_id, protoPayload.methodName as api_call, if(protoPayload.methodName="v1.compute.projects.setCommonInstanceMetadata", "Project", "Instance") as target_type, coalesce(resource.labels.instance_id, resource.labels.project_id) as target_id, protoPayload.request.metadata.items.value as ssh_key_value
| expand protoPayload.request.metadata.items
| filter user !contains "admin@example.com" AND user !matches "automation-sa@*.iam.gserviceaccount.com"
| sort _time desc
```

### Azure VMAccess Extension Abuse
---
```sql
source:azure.activity operationName.value:MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE resultType:Success resourceId:*extensions/VMAccess* properties.requestbody:*protectedSettings* (properties.requestbody:*ssh_key* OR properties.requestbody:*password*)
| select _time, caller as user, callerIpAddress as src_ip, properties.subscriptionId as subscription_id, regex(resourceId, "virtualMachines/([^/]+)", 1) as target_vm, json(properties.requestbody, properties.protectedSettings.username) as target_user, if(properties.requestbody contains "ssh_key", "SSH Key Reset/Update", properties.requestbody contains "password", "Password Reset/User Create", "Unknown VMAccess Action") as action_type
| filter action_type != "Unknown VMAccess Action" AND user !contains "admin@example.com" AND user !contains "automation-account-id"
| sort _time desc
```

### AWS SSM Session Initiation
---
```sql
source:cloudtrail eventSource:ssm.amazonaws.com eventName:StartSession errorCode:null
| select _time, userIdentity.arn as user_arn, sourceIPAddress as src_ip, requestParameters.target as target_instance_id, awsRegion as region
| filter user_arn !contains "known-admin-role" AND src_ip != "1.2.3.4"
| sort _time desc
```

### AWS SSM Command Execution
---
```sql
source:cloudtrail eventSource:ssm.amazonaws.com eventName:SendCommand errorCode:null requestParameters.documentName:(AWS-RunShellScript OR AWS-RunPowerShellScript)
| select _time, userIdentity.arn as user_arn, sourceIPAddress as src_ip, awsRegion as region, requestParameters.documentName as document_name, mvcount(requestParameters.instanceIds) as target_instance_count, requestParameters.instanceIds as target_instance_ids, requestParameters.parameters.commands as commands_executed
| filter target_instance_count > 5 AND user_arn !contains "known-admin-role" AND src_ip != "1.2.3.4"
| sort _time desc
```