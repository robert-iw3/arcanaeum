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
event_type=CloudTrailEvent
| where eventName in ("RegisterDelegatedAdministrator") or eventName LIKE "*EnableOrganizationAdminAccount"
| eval delegated_service=coalesce(requestParameters_servicePrincipal, eventSource)
| eval recipient_account_id=coalesce(requestParameters_accountId, requestParameters_adminAccountId)
| where delegated_service in ("sso.amazonaws.com", "cloudformation.amazonaws.com", "guardduty.amazonaws.com", "securityhub.amazonaws.com", "iam-access-analyzer.amazonaws.com", "config.amazonaws.com")
| group by timestamp, eventName, AWSAccountId, UserIdentityType, UserIdentityArn, SourceIPAddress, recipient_account_id, values(delegated_service) as delegated_services
| rename AWSAccountId as source_account_id, UserIdentityArn as actor_arn, SourceIPAddress as source_ip_address
| select timestamp as _time, eventName, source_account_id, UserIdentityType, actor_arn, source_ip_address, recipient_account_id, delegated_services
```

### AmazonGuardDutyFullAccess v1 Use
---
```sql
event_type=CloudTrailEvent
| where eventName in ("AttachUserPolicy", "AttachRolePolicy")
| where requestParameters_policyArn="arn:aws:iam::aws:policy/AmazonGuardDutyFullAccess"
| eval target_principal_name=coalesce(requestParameters_userName, requestParameters_roleName)
| group by timestamp, eventName, AWSAccountId, UserIdentityArn, SourceIPAddress, target_principal_name, requestParameters_policyArn, count()
| rename AWSAccountId as target_account_id, UserIdentityArn as actor_arn, SourceIPAddress as source_ip_address, requestParameters_policyArn as policy_arn
| select timestamp as _time, eventName, target_account_id, actor_arn, source_ip_address, target_principal_name, policy_arn, count
```

### Sensitive Delegated Admin Access
---
```sql
event_type=CloudTrailEvent
| where AWSAccountId in ("<sensitive_delegated_admin_account_id_1>", "<sensitive_delegated_admin_account_id_2>")
| where eventName in ("CreateAccountAssignment", "DeleteAccountAssignment", "UpdatePermissionSet", "ProvisionPermissionSet", "CreatePermissionSet", "CreateStackSet", "UpdateStackSet", "DeleteStackSet", "CreateRole", "CreateUser", "RegisterDelegatedAdministrator") or eventName LIKE "Attach%Policy" or eventName LIKE "CreatePolicy%" or eventName LIKE "DeletePolicy%" or eventName LIKE "DeleteRole%" or eventName LIKE "DeleteUser%" or eventName LIKE "Detach%Policy" or eventName LIKE "Put%" or eventName LIKE "UpdateRole%" or eventName LIKE "UpdateUser%"
| where not(eventName in ("PutRolePolicy", "PutUserPolicy", "PutGroupPolicy"))
| group by timestamp, eventName, eventSource, AWSAccountId, UserIdentityArn, SourceIPAddress, count()
| rename AWSAccountId as source_account_id, UserIdentityArn as actor_arn, SourceIPAddress as source_ip_address
| select timestamp as _time, eventName, eventSource, source_account_id, actor_arn, source_ip_address, count
```

### CloudTrail Logging Disabled/Modified
---
```sql
event_type=CloudTrailEvent
| where eventName in ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteEventDataStore")
| group by timestamp, eventName, AWSAccountId, UserIdentityArn, SourceIPAddress, requestParameters_name, count()
| rename AWSAccountId as target_account_id, UserIdentityArn as actor_arn, SourceIPAddress as source_ip_address, requestParameters_name as trail_name
| select timestamp as _time, eventName, target_account_id, actor_arn, source_ip_address, trail_name, count
```

### Over-privileged RegisterDelegatedAdministrator
---
```sql
event_simpleName=CloudTrailEvent
| eventName IN ("CreatePolicy", "CreatePolicyVersion", "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy")
| requestParameters_policyDocument="*organizations:RegisterDelegatedAdministrator*"
| requestParameters_policyDocument="*\"Resource\":\"*\"*"
| requestParameters_policyDocument="*\"Effect\":\"Allow\"*"
| eval target_name=coalesce(requestParameters_policyName, requestParameters_userName, requestParameters_roleName, requestParameters_groupName)
| groupBy(event_platformTime, eventName, awsAccountId, userIdentity_arn, sourceIPAddress, target_name, count())
| rename awsAccountId as target_account_id, userIdentity_arn as actor_arn, sourceIPAddress as source_ip_address, target_name as modified_policy_or_principal
| select event_platformTime as _time, eventName, target_account_id, actor_arn, source_ip_address, modified_policy_or_principal, count
```