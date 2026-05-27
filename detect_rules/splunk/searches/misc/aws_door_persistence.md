### AWSDoor: Advanced Persistence Techniques in AWS Environments
---

AWSDoor is a tool that automates sophisticated persistence techniques in AWS, enabling adversaries to maintain long-term access by manipulating IAM configurations, abusing native AWS services like Lambda and EC2, and impairing security monitoring. These methods allow attackers to operate stealthily, often blending malicious activity with legitimate administrative actions, making detection challenging for traditional security measures.

Recent intelligence highlights AWSDoor's focus on configuration-based persistence, moving away from traditional malware deployments, and its ability to bypass MFA during AccessKey injection, making it a significant threat that requires updated detection strategies.

### Actionable Threat Data
---

IAM Access Key Creation (T1136.003): Monitor for the CreateAccessKey event in AWS CloudTrail logs, especially for privileged users or users who typically use AWS SSO.

IAM Role Trust Policy Modification (T1136.001): Detect changes to IAM role trust policies by monitoring UpdateAssumeRolePolicy events in CloudTrail. Pay close attention to policies that allow external AWS accounts or roles to assume roles within your environment.

IAM Policy with NotAction or NotResource (T1098): Implement AWS Config rules or CloudWatch alarms to identify IAM policies containing NotAction or NotResource with an Allow effect, as these can grant broad, hidden privileges.

Malicious Lambda Layer Deployment (T1550.002): Monitor UpdateFunctionConfiguration events in CloudTrail for the attachment of new Lambda layers to functions. Investigate layers from unusual sources or those attached to critical Lambda functions.

CloudTrail Logging Impairment (T1562.001): Alert on StopLogging and PutEventSelectors events in CloudTrail. A sudden stop in log volume or modification of event selectors to exclude management events can indicate an attacker attempting to hide their activity.

S3 Lifecycle Policy for Data Destruction (T1485): Monitor for PutBucketLifecycleConfiguration events in CloudTrail. Scrutinize new or modified lifecycle policies that set object expiration to a very short duration (e.g., 1 day) or apply broadly to all objects, as this can indicate an attempt at silent data destruction.

AWS Organizations LeaveOrganization Attempt (T1136.001): Create CloudWatch alarms for LeaveOrganization events in CloudTrail. Even if blocked by SCPs, an attempt to leave the organization is a critical indicator of compromise.

### Consolidated Search
---
```sql

-- title: AWS Persistence and Defense Evasion Techniques (AWSDoor)
-- description: Detects a variety of persistence, privilege escalation, and defense evasion techniques commonly associated with the AWSDoor toolkit. This includes creating IAM access keys, modifying role trust policies, using deceptive IAM policies (`NotAction`), attaching malicious Lambda layers, impairing CloudTrail logging, setting destructive S3 lifecycle policies, and attempting to detach an account from an AWS Organization.
-- author: RW
-- date: 2025-09-21
-- tags:
--   - attack.persistence
--   - attack.privilege_escalation
--   - attack.defense_evasion
--   - attack.impact
--   - attack.t1136.001
--   - attack.t1136.003
--   - attack.t1098
--   - attack.t1574.013
--   - attack.t1562.001
--   - attack.t1485
-- logsource:
--   product: aws
--   service: cloudtrail
-- detection:
--   splunk:
--     search: '| search sourcetype=aws:cloudtrail ((eventName=CreateAccessKey responseElements.accessKey.status="Active"
--       errorCode=null) OR (eventName=UpdateAssumeRolePolicy errorCode=null) OR (eventName
--       IN (CreatePolicy, CreatePolicyVersion, PutGroupPolicy, PutRolePolicy, PutUserPolicy)
--       errorCode=null requestParameters.policyDocument="*\"Effect\":\"Allow\"*" AND
--       (requestParameters.policyDocument="*\"NotAction\"*" OR requestParameters.policyDocument="*\"NotResource\"*"))
--       OR (eventName=UpdateFunctionConfiguration requestParameters.layers=* errorCode=null)
--       OR (eventName IN (StopLogging, PutEventSelectors) errorCode=null) OR (eventName=PutBucketLifecycleConfiguration
--       requestParameters.lifecycleConfiguration.rules{}.status="Enabled" requestParameters.lifecycleConfiguration.rules{}.expiration.days=1
--       errorCode=null) OR (eventName=LeaveOrganization)) | eval detection_technique=case(eventName="CreateAccessKey",
--       "IAM Access Key Creation", eventName="UpdateAssumeRolePolicy", "IAM Role Trust
--       Policy Modified", eventName IN ("CreatePolicy", "CreatePolicyVersion", "PutGroupPolicy",
--       "PutRolePolicy", "PutUserPolicy"), "IAM Policy with NotAction or NotResource",
--       eventName="UpdateFunctionConfiguration", "Lambda Layer Attached or Modified",
--       eventName IN ("StopLogging", "PutEventSelectors"), "CloudTrail Logging Impaired",
--       eventName="PutBucketLifecycleConfiguration", "S3 Lifecycle Policy for Rapid
--       Data Deletion", eventName="LeaveOrganization", "Account Attempted to Leave
--       Organization") | eval object_affected=coalesce(requestParameters.userName,
--       requestParameters.roleName, requestParameters.policyName, requestParameters.functionName,
--       requestParameters.name, requestParameters.trailName, requestParameters.bucketName,
--       aws_account_id) | stats count values(object_affected) as object_affected by
--       detection_technique, eventName, aws_account_id, userIdentity.arn, sourceIPAddress,
--       errorCode, errorMessage | rename userIdentity.arn as user, sourceIPAddress
--       as src_ip'
-- fields:
--   - detection_technique
--   - eventName
--   - aws_account_id
--   - user
--   - src_ip
--   - object_affected
--   - errorCode
--   - errorMessage
-- falsepositives:
--   - This rule combines multiple high-fidelity alerts. However, false positives can occur from legitimate administrative or automated (CI/CD) activities. For example, creating access keys, modifying role trusts, or updating Lambda layers are common actions. It is recommended to baseline normal activity and filter out events from known administrative principals or automation roles to improve fidelity. Each `detection_technique` should be evaluated in the context of your environment's normal operations.
-- level: high

(sourcetype=aws:cloudtrail)
--- Selects multiple suspicious AWS events associated with persistence and evasion ---
(
  -- 1. IAM Access Key Creation: Attacker creates credentials for persistence.
  (eventName=CreateAccessKey responseElements.accessKey.status="Active" errorCode=null) OR

  -- 2. IAM Role Trust Policy Modification: Attacker allows their external account to assume a role.
  (eventName=UpdateAssumeRolePolicy errorCode=null) OR

  -- 3. IAM Policy with NotAction/NotResource: Attacker creates a deceptive policy for privilege escalation.
  (eventName IN (CreatePolicy, CreatePolicyVersion, PutGroupPolicy, PutRolePolicy, PutUserPolicy) errorCode=null requestParameters.policyDocument="*\"Effect\":\"Allow\"*" AND (requestParameters.policyDocument="*\"NotAction\"*" OR requestParameters.policyDocument="*\"NotResource\"*")) OR

  -- 4. Malicious Lambda Layer Deployment: Attacker hides malicious code in a Lambda layer.
  (eventName=UpdateFunctionConfiguration requestParameters.layers=* errorCode=null) OR

  -- 5. CloudTrail Logging Impairment: Attacker disables or modifies logging to hide their tracks.
  (eventName IN (StopLogging, PutEventSelectors) errorCode=null) OR

  -- 6. S3 Lifecycle Policy for Data Destruction: Attacker sets a 1-day expiration to silently delete all data in a bucket.
  (eventName=PutBucketLifecycleConfiguration requestParameters.lifecycleConfiguration.rules{}.status="Enabled" requestParameters.lifecycleConfiguration.rules{}.expiration.days=1 errorCode=null) OR

  -- 7. AWS Organizations LeaveOrganization Attempt: Attacker tries to detach an account from central governance. Includes failed attempts.
  (eventName=LeaveOrganization)
)
--- Enrich and Format the Output ---
| eval detection_technique=case(
    eventName="CreateAccessKey", "IAM Access Key Creation",
    eventName="UpdateAssumeRolePolicy", "IAM Role Trust Policy Modified",
    eventName IN ("CreatePolicy", "CreatePolicyVersion", "PutGroupPolicy", "PutRolePolicy", "PutUserPolicy"), "IAM Policy with NotAction or NotResource",
    eventName="UpdateFunctionConfiguration", "Lambda Layer Attached or Modified",
    eventName IN ("StopLogging", "PutEventSelectors"), "CloudTrail Logging Impaired",
    eventName="PutBucketLifecycleConfiguration", "S3 Lifecycle Policy for Rapid Data Deletion",
    eventName="LeaveOrganization", "Account Attempted to Leave Organization"
  )
--- Identify the primary resource affected by the action ---
| eval object_affected=coalesce(requestParameters.userName, requestParameters.roleName, requestParameters.policyName, requestParameters.functionName, requestParameters.name, requestParameters.trailName, requestParameters.bucketName, aws_account_id)
--- Aggregate results for a cleaner summary ---
| stats count values(object_affected) as object_affected by detection_technique, eventName, aws_account_id, userIdentity.arn, sourceIPAddress, errorCode, errorMessage
| rename userIdentity.arn as user, sourceIPAddress as src_ip
| fields detection_technique, eventName, aws_account_id, user, src_ip, object_affected, errorCode, errorMessage
```