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
-- falsepositives:
--   - This rule combines multiple high-fidelity alerts. However, false positives can occur from legitimate administrative or automated (CI/CD) activities. For example, creating access keys, modifying role trusts, or updating Lambda layers are common actions. It is recommended to baseline normal activity and filter out events from known administrative principals or automation roles to improve fidelity. Each `detection_technique` should be evaluated in the context of your environment's normal operations.
-- level: high

-- Log Explorer Query (for Logs > Search, filter: service:cloudtrail)
(@eventName:CreateAccessKey @responseElements.accessKey.status:"Active" -@errorCode:*) OR
(@eventName:UpdateAssumeRolePolicy -@errorCode:*) OR
(@eventName:(CreatePolicy OR CreatePolicyVersion OR PutGroupPolicy OR PutRolePolicy OR PutUserPolicy) -@errorCode:* @requestParameters.policyDocument:*"\"Effect\":\"Allow\""* (@requestParameters.policyDocument:*"\"NotAction\""* OR @requestParameters.policyDocument:*"\"NotResource\"*")) OR
(@eventName:UpdateFunctionConfiguration @requestParameters.layers:* -@errorCode:*) OR
(@eventName:(StopLogging OR PutEventSelectors) -@errorCode:*) OR
(@eventName:PutBucketLifecycleConfiguration @requestParameters.lifecycleConfiguration.rules.status:"Enabled" @requestParameters.lifecycleConfiguration.rules.expiration.days:1 -@errorCode:*) OR
(@eventName:LeaveOrganization)

-- Pipeline Processor for Enrichments (Logs > Pipelines):

-- Detection Technique (Grok or Remapper):

-- Condition: Matches the query above.
-- Grok Pattern: %{DATA:eventName} (extract @eventName).
-- Remap to @detection_technique with rules:
if @eventName == "CreateAccessKey" then "IAM Access Key Creation"
else if @eventName == "UpdateAssumeRolePolicy" then "IAM Role Trust Policy Modified"
else if @eventName in ["CreatePolicy", "CreatePolicyVersion", "PutGroupPolicy", "PutRolePolicy", "PutUserPolicy"] then "IAM Policy with NotAction or NotResource"
else if @eventName == "UpdateFunctionConfiguration" then "Lambda Layer Attached or Modified"
else if @eventName in ["StopLogging", "PutEventSelectors"] then "CloudTrail Logging Impaired"
else if @eventName == "PutBucketLifecycleConfiguration" then "S3 Lifecycle Policy for Rapid Data Deletion"
else if @eventName == "LeaveOrganization" then "Account Attempted to Leave Organization"
else "Unknown"
```