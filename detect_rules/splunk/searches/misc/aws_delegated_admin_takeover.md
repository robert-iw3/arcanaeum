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
sourcetype="aws:cloudtrail"
-- This detection rule identifies when a new delegated administrator is registered for a sensitive AWS service.
-- An attacker with sufficient permissions in the management account can abuse this to escalate privileges across the entire AWS Organization.
-- This activity is uncommon and should be investigated.

-- Filter for the specific API calls used to delegate administrative control.
eventName IN (RegisterDelegatedAdministrator, *EnableOrganizationAdminAccount)

-- Normalize the delegated service and the account receiving the delegation into common fields for easier processing.
| eval delegated_service = coalesce(requestParameters.servicePrincipal, eventSource)
| eval recipient_account_id = coalesce(requestParameters.accountId, requestParameters.adminAccountId)

-- Focus on delegation of sensitive services that could be used for privilege escalation or persistence.
-- TUNE: Add or remove services based on your organization's definition of sensitive services.
| search delegated_service IN (
    "sso.amazonaws.com",
    "cloudformation.amazonaws.com",
    "guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
    "iam-access-analyzer.amazonaws.com",
    "config.amazonaws.com"
)

-- TUNE: To reduce potential false positives, consider filtering out known administrative users/roles or automation IPs that perform these actions legitimately.
-- For example:
-- | search NOT (user_identity.arn IN ("<known_admin_role_arn_1>", "<known_admin_role_arn_2>") OR src_ip IN ("10.0.0.1", "..."))

-- Aggregate results and format for alerting, providing context about the actor, source, and delegated service.
| stats count values(delegated_service) as delegated_services by _time, eventName, aws_account_id, user_identity.type, user_identity.arn, src_ip, recipient_account_id
| rename aws_account_id as source_account_id, user_identity.arn as actor_arn, src_ip as source_ip_address
| fields _time, eventName, source_account_id, user_identity.type, actor_arn, source_ip_address, recipient_account_id, delegated_services
```

### AmazonGuardDutyFullAccess v1 Use
---
```sql
sourcetype="aws:cloudtrail"
-- This rule detects when the legacy, vulnerable AmazonGuardDutyFullAccess (v1) policy is attached to an IAM user or role.
-- This policy contains overly permissive 'organizations' permissions that can be abused for privilege escalation across an entire AWS Organization.
-- AWS has released a v2 of this policy to remediate the issue. Any use of the v1 policy should be investigated immediately.

-- Filter for events where a policy is attached to a user or role.
eventName IN (AttachUserPolicy, AttachRolePolicy)

-- Filter for the specific ARN of the vulnerable v1 policy.
| search requestParameters.policyArn="arn:aws:iam::aws:policy/AmazonGuardDutyFullAccess"

-- TUNE: The highest risk is when this policy is attached to a principal in the management account.
-- If you know your management account ID, you can filter for it here to increase fidelity.
-- For example:
-- | search aws_account_id="<your_management_account_id>"

-- Normalize the name of the principal the policy was attached to.
| eval target_principal_name = coalesce(requestParameters.userName, requestParameters.roleName)

-- Format the results for alerting.
| stats count by _time, eventName, aws_account_id, user_identity.arn, src_ip, target_principal_name, requestParameters.policyArn
| rename aws_account_id as target_account_id, user_identity.arn as actor_arn, src_ip as source_ip_address, requestParameters.policyArn as policy_arn
| fields _time, eventName, target_account_id, actor_arn, source_ip_address, target_principal_name, policy_arn, count
```

### Sensitive Delegated Admin Access
---
```sql
sourcetype="aws:cloudtrail"
-- This rule detects potentially malicious or high-impact activity originating from a sensitive delegated administrator account.
-- Compromise of these accounts (e.g., one that manages IAM Identity Center) can lead to full organization compromise.

-- TUNE: This is the most critical part of the rule. You must populate this list with the AWS Account IDs
-- of your known delegated administrator accounts for sensitive services like IAM Identity Center, CloudFormation StackSets, etc.
| search aws_account_id IN ("<sensitive_delegated_admin_account_id_1>", "<sensitive_delegated_admin_account_id_2>")

-- Filter for high-impact events that modify permissions, identities, or configurations.
-- This list includes general IAM changes as well as service-specific changes for sensitive delegated services.
| search eventName IN (
    # IAM Identity Center (SSO)
    "CreateAccountAssignment", "DeleteAccountAssignment", "UpdatePermissionSet", "ProvisionPermissionSet", "CreatePermissionSet",
    # CloudFormation StackSets
    "CreateStackSet", "UpdateStackSet", "DeleteStackSet",
    # General IAM & Organizations
    "Attach*Policy", "CreatePolicy*", "CreateRole", "CreateUser", "DeletePolicy*", "DeleteRole*", "DeleteUser*", "Detach*Policy", "Put*", "UpdateRole*", "UpdateUser*", "RegisterDelegatedAdministrator"
)
-- Exclude common, lower-risk events to reduce noise.
| search eventName!="PutRolePolicy" AND eventName!="PutUserPolicy" AND eventName!="PutGroupPolicy"

-- TUNE: Filter out known benign activity, such as changes made by specific automation roles or from known admin IPs.
-- For example:
-- | search NOT (user_identity.arn="<known_automation_role_arn>" AND src_ip="<known_ip>")

-- Aggregate and format the results for alerting.
| stats count by _time, eventName, eventSource, aws_account_id, user_identity.arn, src_ip
| rename aws_account_id as source_account_id, user_identity.arn as actor_arn, src_ip as source_ip_address
| fields _time, eventName, eventSource, source_account_id, actor_arn, source_ip_address, count
```

### CloudTrail Logging Disabled/Modified
---
```sql
sourcetype="aws:cloudtrail"
-- This rule detects attempts to disable or tamper with AWS CloudTrail logging, a common defense evasion technique.
-- Such actions are highly suspicious as they can blind security monitoring and should be investigated immediately.

-- Filter for API calls that stop, delete, or modify a CloudTrail configuration.
eventName IN (
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
    "PutEventSelectors",
    "DeleteEventDataStore"
)

-- TUNE: Filter out known benign changes made by specific automation roles or from known admin IPs to reduce noise.
-- For example:
-- | search NOT (user_identity.arn="<known_automation_role_arn>" AND src_ip="<known_ip>")

-- TUNE: To increase fidelity, you can focus on changes to specific, critical trails, such as an organization-wide trail.
-- For example:
-- | search requestParameters.name="<critical_trail_name>"

-- Aggregate and format the results for alerting.
| stats count by _time, eventName, aws_account_id, user_identity.arn, src_ip, requestParameters.name
| rename aws_account_id as target_account_id, user_identity.arn as actor_arn, src_ip as source_ip_address, requestParameters.name as trail_name
| fields _time, eventName, target_account_id, actor_arn, source_ip_address, trail_name, count
```

### Over-privileged RegisterDelegatedAdministrator
---
```sql
sourcetype="aws:cloudtrail"
-- This rule detects the creation or modification of an IAM policy that grants broad permissions to delegate administrators.
-- An attacker can abuse this permission within the management account to escalate privileges across the entire AWS Organization.
-- This is a key component of the attack path described in the research.

-- Filter for events that create or modify IAM policies.
eventName IN (CreatePolicy, CreatePolicyVersion, PutUserPolicy, PutRolePolicy, PutGroupPolicy)

-- Search for the specific combination of a permissive action and a wildcard resource within the policy document.
-- This indicates the policy is not scoped to a specific service, which is a high-risk configuration.
| search requestParameters.policyDocument="*organizations:RegisterDelegatedAdministrator*" AND requestParameters.policyDocument="*\"Resource\":\"*\"*" AND requestParameters.policyDocument="*\"Effect\":\"Allow\"*"

-- TUNE: This permission is most dangerous when applied in the AWS Organization's management account.
-- Filter for your management account ID to increase fidelity.
-- | search aws_account_id="<your_management_account_id>"

-- Normalize the name of the principal or policy being modified.
| eval target_name = coalesce(requestParameters.policyName, requestParameters.userName, requestParameters.roleName, requestParameters.groupName)

-- Aggregate and format the results for alerting.
| stats count by _time, eventName, aws_account_id, user_identity.arn, src_ip, target_name
| rename aws_account_id as target_account_id, user_identity.arn as actor_arn, src_ip as source_ip_address, target_name as modified_policy_or_principal
| fields _time, eventName, target_account_id, actor_arn, source_ip_address, modified_policy_or_principal, count
```