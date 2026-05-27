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
event_type IN ("SendSSHPublicKey", "SendSerialConsoleSSHPublicKey") AND errorCode IS NULL
| SELECT _time, eventName AS api_call, awsRegion AS region, sourceIPAddress AS src_ip, userIdentity.arn AS user_arn, requestParameters.instanceId AS dest_instance_id, requestParameters.instanceOSUser AS dest_os_user, COUNT(*) AS count
| GROUP BY _time, api_call, region, src_ip, user_arn
| WHERE user_arn NOT LIKE "*known-admin-role*" AND src_ip NOT LIKE "10.0.0.0/8"
| ORDER BY _time DESC
```

### GCP Metadata SSH Key Modification
---
```sql
event_type IN ("v1.compute.instances.setMetadata", "v1.compute.projects.setCommonInstanceMetadata") AND protoPayload_serviceName="compute.googleapis.com" AND protoPayload_status IS NULL AND protoPayload_request_metadata_items_key="ssh-keys"
| SELECT _time, protoPayload_authenticationInfo_principalEmail AS user, protoPayload_authenticationInfo_callerIp AS src_ip, resource_labels_project_id AS project_id, protoPayload_methodName AS api_call, CASE WHEN protoPayload_methodName="v1.compute.projects.setCommonInstanceMetadata" THEN "Project" ELSE "Instance" END AS target_type, COALESCE(resource_labels_instance_id, resource_labels_project_id) AS target_id, protoPayload_request_metadata_items_value AS ssh_key_value
| EXPAND protoPayload_request_metadata_items
| WHERE user NOT LIKE "admin@example.com" AND user NOT LIKE "automation-sa@*.iam.gserviceaccount.com"
| ORDER BY _time DESC
```

### Azure VMAccess Extension Abuse
---
```sql
operationName_value="MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE" AND resultType="Success" AND resourceId LIKE "%/extensions/VMAccess%" AND properties_requestbody LIKE "%protectedSettings%" AND (properties_requestbody LIKE "%ssh_key%" OR properties_requestbody LIKE "%password%")
| SELECT _time, caller AS user, callerIpAddress AS src_ip, properties_subscriptionId AS subscription_id, REGEXP(resourceId, "virtualMachines/([^/]+)", 1) AS target_vm, JSON_EXTRACT(properties_requestbody, "properties.protectedSettings.username") AS target_user, CASE WHEN properties_requestbody LIKE "%ssh_key%" THEN "SSH Key Reset/Update" WHEN properties_requestbody LIKE "%password%" THEN "Password Reset/User Create" ELSE "Unknown VMAccess Action" END AS action_type
| WHERE action_type != "Unknown VMAccess Action" AND user NOT LIKE "admin@example.com" AND user NOT LIKE "automation-account-id"
| ORDER BY _time DESC
```

### AWS SSM Session Initiation
---
```sql
eventSource="ssm.amazonaws.com" AND eventName="StartSession" AND errorCode IS NULL
| SELECT _time, userIdentity_arn AS user_arn, sourceIPAddress AS src_ip, requestParameters_target AS target_instance_id, awsRegion AS region
| WHERE user_arn NOT LIKE "*known-admin-role*" AND src_ip != "1.2.3.4"
| ORDER BY _time DESC
```

### AWS SSM Command Execution
---
```sql
eventSource="ssm.amazonaws.com" AND eventName="SendCommand" AND errorCode IS NULL AND requestParameters_documentName IN ("AWS-RunShellScript", "AWS-RunPowerShellScript")
| SELECT _time, userIdentity_arn AS user_arn, sourceIPAddress AS src_ip, awsRegion AS region, requestParameters_documentName AS document_name, MVCOUNT(requestParameters_instanceIds) AS target_instance_count, requestParameters_instanceIds AS target_instance_ids, requestParameters_parameters_commands AS commands_executed
| WHERE target_instance_count > 5 AND user_arn NOT LIKE "*known-admin-role*" AND src_ip != "1.2.3.4"
| ORDER BY _time DESC
```