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
FROM * -- <index or data-stream for cloudtrail logs>
| WHERE event.action IN ("SendSSHPublicKey", "SendSerialConsoleSSHPublicKey") AND error.code IS NULL
| EVAL api_call = event.action, region = aws.cloudtrail.aws_region, src_ip = source.ip, user_arn = aws.cloudtrail.user_identity.arn, dest_instance_id = aws.cloudtrail.request_parameters.instanceId, dest_os_user = aws.cloudtrail.request_parameters.instanceOSUser
| STATS count = COUNT(*), dest_instance_id = VALUES(dest_instance_id), dest_os_user = VALUES(dest_os_user) BY @timestamp, api_call, region, src_ip, user_arn
| WHERE user_arn NOT LIKE "%known-admin-role%" AND src_ip NOT LIKE "10.0.0.0/8"
| KEEP @timestamp, user_arn, src_ip, region, api_call, dest_instance_id, dest_os_user, count
| SORT @timestamp DESC
```

### GCP Metadata SSH Key Modification
---
```sql
FROM * -- <index or data-stream for gcp audit logs>
| WHERE event.provider == "compute.googleapis.com" AND event.action IN ("v1.compute.instances.setMetadata", "v1.compute.projects.setCommonInstanceMetadata") AND error.code IS NULL AND gcp.audit.request.metadata.items.key == "ssh-keys"
| DISSECT gcp.audit.request.metadata.items
| EVAL user = gcp.audit.authentication_info.principalEmail, src_ip = source.ip, project_id = gcp.resource.labels.project_id, api_call = event.action, target_type = CASE(event.action == "v1.compute.projects.setCommonInstanceMetadata", "Project", "Instance"), target_id = COALESCE(gcp.resource.labels.instance_id, gcp.resource.labels.project_id), ssh_key_value = gcp.audit.request.metadata.items.value
| WHERE user NOT LIKE "admin@example.com" AND user NOT LIKE "automation-sa@%.iam.gserviceaccount.com"
| KEEP @timestamp, user, src_ip, project_id, api_call, target_type, target_id, ssh_key_value
| SORT @timestamp DESC
```

### Azure VMAccess Extension Abuse
---
```sql
FROM * -- <index or data-stream for azure activity logs>
| WHERE event.action == "MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE" AND event.outcome == "Success" AND azure.resource_id LIKE "%/extensions/VMAccess%" AND azure.activity.request_body LIKE "%protectedSettings%" AND (azure.activity.request_body LIKE "%ssh_key%" OR azure.activity.request_body LIKE "%password%")
| EVAL user = azure.caller.identity, src_ip = source.ip, subscription_id = azure.subscription_id, target_vm = REGEXP_SUBSTR(azure.resource_id, "virtualMachines/([^/]+)", 1), target_user = JSON_EXTRACT(azure.activity.request_body, "properties.protectedSettings.username"), action_type = CASE(azure.activity.request_body LIKE "%ssh_key%", "SSH Key Reset/Update", azure.activity.request_body LIKE "%password%", "Password Reset/User Create", TRUE, "Unknown VMAccess Action")
| WHERE action_type != "Unknown VMAccess Action" AND user NOT LIKE "admin@example.com" AND user NOT LIKE "automation-account-id"
| KEEP @timestamp, user, src_ip, subscription_id, target_vm, target_user, action_type
| SORT @timestamp DESC
```

### AWS SSM Session Initiation
---
```sql
FROM * -- <index or data-stream for cloudtrail logs>
| WHERE event.provider == "ssm.amazonaws.com" AND event.action == "StartSession" AND error.code IS NULL
| EVAL user_arn = aws.cloudtrail.user_identity.arn, src_ip = source.ip, target_instance_id = aws.cloudtrail.request_parameters.target, region = aws.cloudtrail.aws_region
| WHERE user_arn NOT LIKE "%known-admin-role%" AND src_ip != "1.2.3.4"
| KEEP @timestamp, user_arn, src_ip, region, target_instance_id
| SORT @timestamp DESC
```

### AWS SSM Command Execution
---
```sql
FROM * -- <index or data-stream for cloudtrail logs>
| WHERE event.provider == "ssm.amazonaws.com" AND event.action == "SendCommand" AND error.code IS NULL AND aws.cloudtrail.request_parameters.documentName IN ("AWS-RunShellScript", "AWS-RunPowerShellScript")
| EVAL user_arn = aws.cloudtrail.user_identity.arn, src_ip = source.ip, region = aws.cloudtrail.aws_region, document_name = aws.cloudtrail.request_parameters.documentName, target_instance_count = MULTI_VALUE_COUNT(aws.cloudtrail.request_parameters.instanceIds), target_instance_ids = aws.cloudtrail.request_parameters.instanceIds, commands_executed = aws.cloudtrail.request_parameters.parameters.commands
| WHERE target_instance_count > 5 AND user_arn NOT LIKE "%known-admin-role%" AND src_ip != "1.2.3.4"
| KEEP @timestamp, user_arn, src_ip, region, document_name, target_instance_count, target_instance_ids, commands_executed
| SORT @timestamp DESC
```