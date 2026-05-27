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
`cloudtrail`
# Search for AWS CloudTrail events. The `cloudtrail` macro should be defined to specify the correct index and sourcetype, e.g., (index=aws sourcetype=aws:cloudtrail).

# Filter for the specific API calls that push an SSH key to an instance.
| search eventName IN (SendSSHPublicKey, SendSerialConsoleSSHPublicKey)

# Focus on successful API calls, indicated by the absence of an error code.
| where isnull(errorCode)

# Aggregate events to summarize the activity by the initiating user and source IP.
| stats
    count,
    values(requestParameters.instanceId) as dest_instance_id,
    values(requestParameters.instanceOSUser) as dest_os_user
    by
    _time,
    eventName,
    awsRegion,
    sourceIPAddress,
    userIdentity.arn

# Rename fields for better readability in the final alert.
| rename
    eventName as api_call,
    awsRegion as region,
    sourceIPAddress as src_ip,
    userIdentity.arn as user_arn

# Format the final output table for analysts.
| table
    _time,
    user_arn,
    src_ip,
    region,
    api_call,
    dest_instance_id,
    dest_os_user,
    count

# This is a placeholder for environment-specific tuning to reduce false positives.
# For example, you can filter out known administrative roles or trusted IP addresses.
# e.g., | search NOT (user_arn="*known-admin-role*" OR src_ip="10.0.0.0/8")
| `aws_ec2_ssh_key_injection_filter`
```

### GCP Metadata SSH Key Modification
---
```sql
`gcp_audit`
# The `gcp_audit` macro should be defined to specify the correct index and sourcetype, e.g., (index=gcp sourcetype=google:gcp:audit)

# Filter for API calls that modify instance or project-wide metadata in Compute Engine.
| search protoPayload.serviceName="compute.googleapis.com" protoPayload.methodName IN ("v1.compute.instances.setMetadata", "v1.compute.projects.setCommonInstanceMetadata")

# Focus on successful API calls.
| where isnull(protoPayload.status)

# Expand the list of metadata items to inspect each one individually.
| mvexpand protoPayload.request.metadata.items

# Filter for events where the metadata key being modified is "ssh-keys".
| where 'protoPayload.request.metadata.items.key'="ssh-keys"

# Create fields to identify the scope (Instance or Project) and the specific target.
| eval target_type=if(protoPayload.methodName=="v1.compute.projects.setCommonInstanceMetadata", "Project", "Instance")
| eval target_id=coalesce(resource.labels.instance_id, resource.labels.project_id)

# Rename fields for better readability in the final alert.
| rename
    protoPayload.authenticationInfo.principalEmail as user,
    protoPayload.authenticationInfo.callerIp as src_ip,
    protoPayload.methodName as api_call,
    resource.labels.project_id as project_id,
    'protoPayload.request.metadata.items.value' as ssh_key_value

# Format the final output table for analysts.
| table
    _time,
    user,
    src_ip,
    project_id,
    api_call,
    target_type,
    target_id,
    ssh_key_value

# This is a placeholder for environment-specific tuning to reduce false positives.
# For example, you can filter out known administrative users or trusted service accounts.
# e.g., | search NOT user IN ("admin@example.com", "automation-sa@*.iam.gserviceaccount.com")
| `gcp_metadata_ssh_key_mod_filter`
```

### Azure VMAccess Extension Abuse
---
```sql
`azure_activity_logs`
# The `azure_activity_logs` macro should be defined to specify the correct index and sourcetype, e.g., (index=azure sourcetype=azure:monitor:activity)

# Filter for successful VM extension creation/update events.
| search operationName.value="MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE" resultType="Success"

# Isolate events specifically involving the VMAccess extension.
| where like(resourceId, "%/extensions/VMAccess%")

# Ensure the request involves modifying protected settings where credentials/keys are stored.
| search properties.requestbody=*protectedSettings*

# Parse the target username from the JSON request body.
| spath input=properties.requestbody path=properties.protectedSettings.username output=target_user

# Determine the action type (SSH key vs. password reset) based on the request body content.
| eval action_type=case(
    like(properties.requestbody, "%\"ssh_key\"%"), "SSH Key Reset/Update",
    like(properties.requestbody, "%\"password\"%"), "Password Reset/User Create",
    1=1, "Unknown VMAccess Action"
  )
| where action_type!="Unknown VMAccess Action"

# Extract the target VM name from the resourceId for easier analysis.
| rex field=resourceId "virtualMachines\/(?<target_vm>[^\/]+)"

# Rename fields for clarity in the final alert.
| rename
    caller as user,
    callerIpAddress as src_ip,
    properties.subscriptionId as subscription_id

# Format the final output table for analysts.
| table
    _time,
    user,
    src_ip,
    subscription_id,
    target_vm,
    target_user,
    action_type

# This is a placeholder for environment-specific tuning to reduce false positives.
# For example, you can filter out known administrative users or trusted service principals.
# e.g., | search NOT user IN ("admin@example.com", "automation-account-id")
| `azure_vmaccess_abuse_filter`
```

### AWS SSM Session Initiation
---
```sql
`cloudtrail`
# The `cloudtrail` macro should be defined to specify the correct index and sourcetype, e.g., (index=aws sourcetype=aws:cloudtrail).

# Filter for StartSession API calls from the Systems Manager service.
| search eventSource="ssm.amazonaws.com" eventName="StartSession"

# Focus on successful API calls.
| where isnull(errorCode)

# Rename fields for better readability in the final alert.
| rename
    userIdentity.arn as user_arn,
    sourceIPAddress as src_ip,
    requestParameters.target as target_instance_id,
    awsRegion as region

# Format the final output table for analysts.
| table
    _time,
    user_arn,
    src_ip,
    region,
    target_instance_id

# This is a placeholder for environment-specific tuning to reduce false positives.
# For example, you can filter out known administrative roles or trusted IP addresses.
# e.g., | search NOT (user_arn="*known-admin-role*" OR src_ip="1.2.3.4")
| `aws_ssm_start_session_filter`
```

### AWS SSM Command Execution
---
```sql
`cloudtrail`
# The `cloudtrail` macro should be defined to specify the correct index and sourcetype, e.g., (index=aws sourcetype=aws:cloudtrail).

# Filter for SendCommand API calls from the Systems Manager service.
| search eventSource="ssm.amazonaws.com" eventName="SendCommand"

# Focus on successful API calls and common remote execution documents.
| where isnull(errorCode) AND requestParameters.documentName IN ("AWS-RunShellScript", "AWS-RunPowerShellScript")

# Calculate the number of instances targeted in a single command.
| eval target_instance_count=mvcount(requestParameters.instanceIds)

# Set a threshold for what is considered "at scale". This value should be tuned for the specific environment.
# A low threshold increases detection but may also increase false positives from legitimate admin activity.
| where target_instance_count > 5

# Rename fields for better readability in the final alert.
| rename
    userIdentity.arn as user_arn,
    sourceIPAddress as src_ip,
    awsRegion as region,
    requestParameters.documentName as document_name,
    requestParameters.instanceIds as target_instance_ids,
    requestParameters.parameters.commands{} as commands_executed

# Format the final output table for analysts.
| table
    _time,
    user_arn,
    src_ip,
    region,
    document_name,
    target_instance_count,
    target_instance_ids,
    commands_executed

# This is a placeholder for environment-specific tuning to reduce false positives.
# For example, you can filter out known administrative roles or trusted IP addresses.
# e.g., | search NOT (user_arn="*known-admin-role*" OR src_ip="1.2.3.4")
| `aws_ssm_sendcommand_at_scale_filter`
```