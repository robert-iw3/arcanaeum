### AWS Delegated Admin Exploit & Org Takeover Risk
---

This report details how misconfigured AWS delegated administration and a flaw in a legacy AWS-managed policy (AmazonGuardDutyFullAccess v1) can lead to full AWS Organization compromise. Attackers can leverage these vulnerabilities to escalate privileges, achieve persistence, and move laterally across all accounts, including the management account.

A significant finding is the specific vulnerability in the AmazonGuardDutyFullAccess v1 policy, which, when attached to a principal in the management account, allowed for the delegation of any supported service to any account, not just GuardDuty. This over-scoped permission, now addressed by AWS with the release of v2 of the policy, presented a critical path to full organizational takeover by enabling attackers to delegate highly privileged services like IAM Identity Center (SSO) or CloudFormation StackSets to a compromised member account.

### Actionable Threat Data
---

Monitor for suspicious AWS Organizations API calls: Alert on `organizations:RegisterDelegatedAdministrator` and `organizations:EnableOrganizationAdminAccount` events, especially if initiated from unexpected users, roles, or IP addresses, or if the delegated service is highly sensitive (e.g., sso.amazonaws.com, cloudformation.amazonaws.com).

Identify and remediate use of AmazonGuardDutyFullAccess v1: Actively search for and update any IAM users or roles in the management account that still have the AmazonGuardDutyFullAccess (version 1) policy attached. Replace it with AmazonGuardDutyFullAccess_v2 or a custom `least-privilege` policy.

Audit and classify delegated administrator accounts: Regularly review all delegated administrator accounts and classify them based on the sensitivity of the services they administer. Treat accounts delegated for services like IAM Identity Center as Tier 0 assets due to their potential for organization-wide privilege escalation.

Implement CloudTrail logging for all accounts: Ensure that AWS CloudTrail is enabled across all accounts in the organization, including the management account, and that logs are centrally aggregated to a secure, dedicated logging account. This provides a comprehensive audit trail for all API activity, including
delegation events.

Restrict permissions for organizations:RegisterDelegatedAdministrator: Apply the principle of least privilege to any IAM identities in the management account that possess the `organizations:RegisterDelegatedAdministrator` permission, limiting its scope as much as possible.

### Delegated Admin Abuse
---
```sql
sourcetype:aws:cloudtrail eventName:(RegisterDelegatedAdministrator OR *EnableOrganizationAdminAccount)
| eval delegated_service=coalesce(requestParameters.servicePrincipal, eventSource)
| eval recipient_account_id=coalesce(requestParameters.accountId, requestParameters.adminAccountId)
| where delegated_service:(sso.amazonaws.com OR cloudformation.amazonaws.com OR guardduty.amazonaws.com OR securityhub.amazonaws.com OR iam-access-analyzer.amazonaws.com OR config.amazonaws.com)
| group by @timestamp, eventName, aws_account_id, userIdentity.type, userIdentity.arn, sourceIPAddress, recipient_account_id
| select values(delegated_service) as delegated_services
| rename aws_account_id as source_account_id, userIdentity.arn as actor_arn, sourceIPAddress as source_ip_address
| fields @timestamp as _time, eventName, source_account_id, userIdentity.type, actor_arn, source_ip_address, recipient_account_id, delegated_services
```

### AmazonGuardDutyFullAccess v1 Use
---
```sql
sourcetype:aws:cloudtrail eventName:(AttachUserPolicy OR AttachRolePolicy) requestParameters.policyArn:"arn:aws:iam::aws:policy/AmazonGuardDutyFullAccess"
| eval target_principal_name=coalesce(requestParameters.userName, requestParameters.roleName)
| group by @timestamp, eventName, aws_account_id, userIdentity.arn, sourceIPAddress, target_principal_name, requestParameters.policyArn
| select count() as count
| rename aws_account_id as target_account_id, userIdentity.arn as actor_arn, sourceIPAddress as source_ip_address, requestParameters.policyArn as policy_arn
| fields @timestamp as _time, eventName, target_account_id, actor_arn, source_ip_address, target_principal_name, policy_arn, count
```

### Sensitive Delegated Admin Access
---
```sql
sourcetype:aws:cloudtrail aws_account_id:(<sensitive_delegated_admin_account_id_1> OR <sensitive_delegated_admin_account_id_2>)
eventName:(CreateAccountAssignment OR DeleteAccountAssignment OR UpdatePermissionSet OR ProvisionPermissionSet OR CreatePermissionSet OR CreateStackSet OR UpdateStackSet OR DeleteStackSet OR Attach*Policy OR CreatePolicy* OR CreateRole OR CreateUser OR DeletePolicy* OR DeleteRole* OR DeleteUser* OR Detach*Policy OR Put* OR UpdateRole* OR UpdateUser* OR RegisterDelegatedAdministrator)
-eventName:(PutRolePolicy OR PutUserPolicy OR PutGroupPolicy)
| group by @timestamp, eventName, eventSource, aws_account_id, userIdentity.arn, sourceIPAddress
| select count() as count
| rename aws_account_id as source_account_id, userIdentity.arn as actor_arn, sourceIPAddress as source_ip_address
| fields @timestamp as _time, eventName, eventSource, source_account_id, actor_arn, source_ip_address, count
```

### CloudTrail Logging Disabled/Modified
---
```sql
sourcetype:aws:cloudtrail eventName:(StopLogging OR DeleteTrail OR UpdateTrail OR PutEventSelectors OR DeleteEventDataStore)
| group by @timestamp, eventName, aws_account_id, userIdentity.arn, sourceIPAddress, requestParameters.name
| select count() as count
| rename aws_account_id as target_account_id, userIdentity.arn as actor_arn, sourceIPAddress as source_ip_address, requestParameters.name as trail_name
| fields @timestamp as _time, eventName, target_account_id, actor_arn, source_ip_address, trail_name, count
```

### Over-privileged RegisterDelegatedAdministrator
---
```sql
sourcetype:aws:cloudtrail eventName:(CreatePolicy OR CreatePolicyVersion OR PutUserPolicy OR PutRolePolicy OR PutGroupPolicy)
requestParameters.policyDocument:*organizations:RegisterDelegatedAdministrator*
requestParameters.policyDocument:*"Resource":"*"*
requestParameters.policyDocument:*"Effect":"Allow"*
| eval target_name=coalesce(requestParameters.policyName, requestParameters.userName, requestParameters.roleName, requestParameters.groupName)
| group by @timestamp, eventName, aws_account_id, userIdentity.arn, sourceIPAddress, target_name
| select count() as count
| rename aws_account_id as target_account_id, userIdentity.arn as actor_arn, sourceIPAddress as source_ip_address, target_name as modified_policy_or_principal
| fields @timestamp as _time, eventName, target_account_id, actor_arn, source_ip_address, modified_policy_or_principal, count
```