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
EventType=CloudTrail
AND EndpointName IN ("RegisterDelegatedAdministrator", "*EnableOrganizationAdminAccount")
| LET delegated_service = COALESCE(RequestParameters_servicePrincipal, EventSource)
| LET recipient_account_id = COALESCE(RequestParameters_accountId, RequestParameters_adminAccountId)
| WHERE delegated_service IN ("sso.amazonaws.com", "cloudformation.amazonaws.com", "guardduty.amazonaws.com", "securityhub.amazonaws.com", "iam-access-analyzer.amazonaws.com", "config.amazonaws.com")
| SELECT COUNT(*) AS count, GROUP_CONCAT(delegated_service) AS delegated_services, Timestamp, EndpointName, AccountID, UserIdentityType, UserIdentityARN, SrcIP, recipient_account_id
| GROUP BY Timestamp, EndpointName, AccountID, UserIdentityType, UserIdentityARN, SrcIP, recipient_account_id
| RENAME Timestamp AS _time, EndpointName AS eventName, AccountID AS source_account_id, UserIdentityType AS user_identity_type, UserIdentityARN AS actor_arn, SrcIP AS source_ip_address
| SELECT _time, eventName, source_account_id, user_identity_type, actor_arn, source_ip_address, recipient_account_id, delegated_services
```

### AmazonGuardDutyFullAccess v1 Use
---
```sql
EventType=CloudTrail
AND EndpointName IN ("AttachUserPolicy", "AttachRolePolicy")
AND RequestParameters_policyArn="arn:aws:iam::aws:policy/AmazonGuardDutyFullAccess"
| LET target_principal_name = COALESCE(RequestParameters_userName, RequestParameters_roleName)
| SELECT COUNT(*) AS count, Timestamp, EndpointName, AccountID, UserIdentityARN, SrcIP, target_principal_name, RequestParameters_policyArn
| GROUP BY Timestamp, EndpointName, AccountID, UserIdentityARN, SrcIP, target_principal_name, RequestParameters_policyArn
| RENAME Timestamp AS _time, EndpointName AS eventName, AccountID AS target_account_id, UserIdentityARN AS actor_arn, SrcIP AS source_ip_address, RequestParameters_policyArn AS policy_arn
| SELECT _time, eventName, target_account_id, actor_arn, source_ip_address, target_principal_name, policy_arn, count
```

### Sensitive Delegated Admin Access
---
```sql
EventType=CloudTrail
AND AccountID IN ("<sensitive_delegated_admin_account_id_1>", "<sensitive_delegated_admin_account_id_2>")
AND EndpointName IN ("CreateAccountAssignment", "DeleteAccountAssignment", "UpdatePermissionSet", "ProvisionPermissionSet", "CreatePermissionSet", "CreateStackSet", "UpdateStackSet", "DeleteStackSet", "Attach*Policy", "CreatePolicy*", "CreateRole", "CreateUser", "DeletePolicy*", "DeleteRole*", "DeleteUser*", "Detach*Policy", "Put*", "UpdateRole*", "UpdateUser*", "RegisterDelegatedAdministrator")
AND EndpointName NOT IN ("PutRolePolicy", "PutUserPolicy", "PutGroupPolicy")
| SELECT COUNT(*) AS count, Timestamp, EndpointName, EventSource, AccountID, UserIdentityARN, SrcIP
| GROUP BY Timestamp, EndpointName, EventSource, AccountID, UserIdentityARN, SrcIP
| RENAME Timestamp AS _time, EndpointName AS eventName, AccountID AS source_account_id, UserIdentityARN AS actor_arn, SrcIP AS source_ip_address
| SELECT _time, eventName, eventSource, source_account_id, actor_arn, source_ip_address, count
```

### CloudTrail Logging Disabled/Modified
---
```sql
EventType=CloudTrail
AND EndpointName IN ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteEventDataStore")
| SELECT COUNT(*) AS count, Timestamp, EndpointName, AccountID, UserIdentityARN, SrcIP, RequestParameters_name
| GROUP BY Timestamp, EndpointName, AccountID, UserIdentityARN, SrcIP, RequestParameters_name
| RENAME Timestamp AS _time, EndpointName AS eventName, AccountID AS target_account_id, UserIdentityARN AS actor_arn, SrcIP AS source_ip_address, RequestParameters_name AS trail_name
| SELECT _time, eventName, target_account_id, actor_arn, source_ip_address, trail_name, count
```

### Over-privileged RegisterDelegatedAdministrator
---
```sql
EventType=CloudTrail
AND EndpointName IN ("CreatePolicy", "CreatePolicyVersion", "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy")
AND RequestParameters_policyDocument LIKE "*organizations:RegisterDelegatedAdministrator*"
AND RequestParameters_policyDocument LIKE "*\"Resource\":\"*\"*"
AND RequestParameters_policyDocument LIKE "*\"Effect\":\"Allow\"*"
| LET target_name = COALESCE(RequestParameters_policyName, RequestParameters_userName, RequestParameters_roleName, RequestParameters_groupName)
| SELECT COUNT(*) AS count, Timestamp, EndpointName, AccountID, UserIdentityARN, SrcIP, target_name
| GROUP BY Timestamp, EndpointName, AccountID, UserIdentityARN, SrcIP, target_name
| RENAME Timestamp AS _time, EndpointName AS eventName, AccountID AS target_account_id, UserIdentityARN AS actor_arn, SrcIP AS source_ip_address, target_name AS modified_policy_or_principal
| SELECT _time, eventName, target_account_id, actor_arn, source_ip_address, modified_policy_or_principal, count
```