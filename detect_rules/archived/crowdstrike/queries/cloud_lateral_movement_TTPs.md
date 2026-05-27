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
event_platform=AWS event_type IN (SendSSHPublicKey, SendSerialConsoleSSHPublicKey) errorCode=null
| group by _time, eventName, awsRegion, sourceIPAddress, userIdentity_arn
| select _time, eventName as api_call, awsRegion as region, sourceIPAddress as src_ip, userIdentity_arn as user_arn, count() as count, values(requestParameters_instanceId) as dest_instance_id, values(requestParameters_instanceOSUser) as dest_os_user
| filter user_arn !~ "*known-admin-role*" and src_ip !~ "10.0.0.0/8"
| sort _time desc
| project _time, user_arn, src_ip, region, api_call, dest_instance_id, dest_os_user, count
```

### GCP Metadata SSH Key Modification
---
```sql
event_platform=GCP protoPayload_serviceName="compute.googleapis.com" protoPayload_methodName IN ("v1.compute.instances.setMetadata", "v1.compute.projects.setCommonInstanceMetadata") protoPayload_status=null protoPayload_request_metadata_items_key="ssh-keys"
| expand protoPayload_request_metadata_items
| select _time, protoPayload_authenticationInfo_principalEmail as user, protoPayload_authenticationInfo_callerIp as src_ip, resource_labels_project_id as project_id, protoPayload_methodName as api_call, case(protoPayload_methodName="v1.compute.projects.setCommonInstanceMetadata", "Project", "Instance") as target_type, coalesce(resource_labels_instance_id, resource_labels_project_id) as target_id, protoPayload_request_metadata_items_value as ssh_key_value
| filter user !~ "admin@example.com" and user !~ "automation-sa@*.iam.gserviceaccount.com"
| sort _time desc
| project _time, user, src_ip, project_id, api_call, target_type, target_id, ssh_key_value
```

### Azure VMAccess Extension Abuse
---
```sql
event_platform=Azure operationName_value="MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE" resultType="Success" resourceId~"*extensions/VMAccess*" properties_requestbody~"*protectedSettings*" properties_requestbody~"*ssh_key*" OR properties_requestbody~"*password*"
| select _time, caller as user, callerIpAddress as src_ip, properties_subscriptionId as subscription_id, regex(resourceId, "virtualMachines/([^/]+)", 1) as target_vm, json_extract(properties_requestbody, "properties.protectedSettings.username") as target_user, case(properties_requestbody~"*ssh_key*", "SSH Key Reset/Update", properties_requestbody~"*password*", "Password Reset/User Create", true, "Unknown VMAccess Action") as action_type
| filter action_type!="Unknown VMAccess Action" and user!~"admin@example.com" and user!~"automation-account-id"
| sort _time desc
| project _time, user, src_ip, subscription_id, target_vm, target_user, action_type
```

### AWS SSM Session Initiation
---
```sql
event_platform=AWS eventSource="ssm.amazonaws.com" eventName="StartSession" errorCode=null
| select _time, userIdentity_arn as user_arn, sourceIPAddress as src_ip, requestParameters_target as target_instance_id, awsRegion as region
| filter user_arn !~ "*known-admin-role*" and src_ip != "1.2.3.4"
| sort _time desc
| project _time, user_arn, src_ip, region, target_instance_id
```

### AWS SSM Command Execution
---
```sql
event_platform=AWS eventSource="ssm.amazonaws.com" eventName="SendCommand" errorCode=null requestParameters_documentName IN ("AWS-RunShellScript", "AWS-RunPowerShellScript")
| select _time, userIdentity_arn as user_arn, sourceIPAddress as src_ip, awsRegion as region, requestParameters_documentName as document_name, mvcount(requestParameters_instanceIds) as target_instance_count, requestParameters_instanceIds as target_instance_ids, requestParameters_parameters_commands as commands_executed
| filter target_instance_count > 5 and user_arn !~ "*known-admin-role*" and src_ip != "1.2.3.4"
| sort _time desc
| project _time, user_arn, src_ip, region, document_name, target_instance_count, target_instance_ids, commands_executed
```