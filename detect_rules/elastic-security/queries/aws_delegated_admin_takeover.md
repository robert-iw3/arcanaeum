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
FROM *
| WHERE event.dataset == "aws.cloudtrail"
  AND event.action IN ("RegisterDelegatedAdministrator", "*EnableOrganizationAdminAccount")
| EVAL delegated_service = COALESCE(aws.cloudtrail.requestParameters.servicePrincipal, event.provider)
| EVAL recipient_account_id = COALESCE(aws.cloudtrail.requestParameters.accountId, aws.cloudtrail.requestParameters.adminAccountId)
| WHERE delegated_service IN ("sso.amazonaws.com", "cloudformation.amazonaws.com", "guardduty.amazonaws.com", "securityhub.amazonaws.com", "iam-access-analyzer.amazonaws.com", "config.amazonaws.com")
| STATS count = COUNT(*), delegated_services = ARRAY_AGG(delegated_service)
  BY @timestamp, event.action, aws.cloudtrail.aws_account_id, aws.cloudtrail.userIdentity.type, aws.cloudtrail.userIdentity.arn, source.ip, recipient_account_id
| RENAME @timestamp AS _time, event.action AS eventName, aws.cloudtrail.aws_account_id AS source_account_id, aws.cloudtrail.userIdentity.type AS user_identity_type, aws.cloudtrail.userIdentity.arn AS actor_arn, source.ip AS source_ip_address
| KEEP _time, eventName, source_account_id, user_identity_type, actor_arn, source_ip_address, recipient_account_id, delegated_services
```

### AmazonGuardDutyFullAccess v1 Use
---
```sql
FROM *
| WHERE event.dataset == "aws.cloudtrail"
  AND event.action IN ("AttachUserPolicy", "AttachRolePolicy")
  AND aws.cloudtrail.requestParameters.policyArn == "arn:aws:iam::aws:policy/AmazonGuardDutyFullAccess"
| EVAL target_principal_name = COALESCE(aws.cloudtrail.requestParameters.userName, aws.cloudtrail.requestParameters.roleName)
| STATS count = COUNT(*)
  BY @timestamp, event.action, aws.cloudtrail.aws_account_id, aws.cloudtrail.userIdentity.arn, source.ip, target_principal_name, aws.cloudtrail.requestParameters.policyArn
| RENAME @timestamp AS _time, event.action AS eventName, aws.cloudtrail.aws_account_id AS target_account_id, aws.cloudtrail.userIdentity.arn AS actor_arn, source.ip AS source_ip_address, aws.cloudtrail.requestParameters.policyArn AS policy_arn
| KEEP _time, eventName, target_account_id, actor_arn, source_ip_address, target_principal_name, policy_arn, count
```

### Sensitive Delegated Admin Access
---
```sql
FROM *
| WHERE event.dataset == "aws.cloudtrail"
  AND aws.cloudtrail.aws_account_id IN ("<sensitive_delegated_admin_account_id_1>", "<sensitive_delegated_admin_account_id_2>")
  AND event.action IN ("CreateAccountAssignment", "DeleteAccountAssignment", "UpdatePermissionSet", "ProvisionPermissionSet", "CreatePermissionSet", "CreateStackSet", "UpdateStackSet", "DeleteStackSet", "Attach*Policy", "CreatePolicy*", "CreateRole", "CreateUser", "DeletePolicy*", "DeleteRole*", "DeleteUser*", "Detach*Policy", "Put*", "UpdateRole*", "UpdateUser*", "RegisterDelegatedAdministrator")
  AND event.action NOT IN ("PutRolePolicy", "PutUserPolicy", "PutGroupPolicy")
| STATS count = COUNT(*)
  BY @timestamp, event.action, event.provider, aws.cloudtrail.aws_account_id, aws.cloudtrail.userIdentity.arn, source.ip
| RENAME @timestamp AS _time, event.action AS eventName, event.provider AS eventSource, aws.cloudtrail.aws_account_id AS source_account_id, aws.cloudtrail.userIdentity.arn AS actor_arn, source.ip AS source_ip_address
| KEEP _time, eventName, eventSource, source_account_id, actor_arn, source_ip_address, count
```

### CloudTrail Logging Disabled/Modified
---
```sql
FROM *
| WHERE event.dataset == "aws.cloudtrail"
  AND event.action IN ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteEventDataStore")
| STATS count = COUNT(*)
  BY @timestamp, event.action, aws.cloudtrail.aws_account_id, aws.cloudtrail.userIdentity.arn, source.ip, aws.cloudtrail.requestParameters.name
| RENAME @timestamp AS _time, event.action AS eventName, aws.cloudtrail.aws_account_id AS target_account_id, aws.cloudtrail.userIdentity.arn AS actor_arn, source.ip AS source_ip_address, aws.cloudtrail.requestParameters.name AS trail_name
| KEEP _time, eventName, target_account_id, actor_arn, source_ip_address, trail_name, count
```

### Over-privileged RegisterDelegatedAdministrator
---
```sql
FROM *
| WHERE event.dataset == "aws.cloudtrail"
  AND event.action IN ("CreatePolicy", "CreatePolicyVersion", "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy")
  AND aws.cloudtrail.requestParameters.policyDocument LIKE "*organizations:RegisterDelegatedAdministrator*"
  AND aws.cloudtrail.requestParameters.policyDocument LIKE "*\"Resource\":\"*\"*"
  AND aws.cloudtrail.requestParameters.policyDocument LIKE "*\"Effect\":\"Allow\"*"
| EVAL target_name = COALESCE(aws.cloudtrail.requestParameters.policyName, aws.cloudtrail.requestParameters.userName, aws.cloudtrail.requestParameters.roleName, aws.cloudtrail.requestParameters.groupName)
| STATS count = COUNT(*)
  BY @timestamp, event.action, aws.cloudtrail.aws_account_id, aws.cloudtrail.userIdentity.arn, source.ip, target_name
| RENAME @timestamp AS _time, event.action AS eventName, aws.cloudtrail.aws_account_id AS target_account_id, aws.cloudtrail.userIdentity.arn AS actor_arn, source.ip AS source_ip_address, target_name AS modified_policy_or_principal
| KEEP _time, eventName, target_account_id, actor_arn, source_ip_address, modified_policy_or_principal, count
```