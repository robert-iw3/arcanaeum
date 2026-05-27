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

FROM logs-aws.cloudtrail-*
| WHERE (
  (aws.cloudtrail.event_name = "CreateAccessKey" AND aws.cloudtrail.flattened.response_elements.access_key.status = "Active" AND aws.cloudtrail.error_code IS NULL) OR
  (aws.cloudtrail.event_name = "UpdateAssumeRolePolicy" AND aws.cloudtrail.error_code IS NULL) OR
  (aws.cloudtrail.event_name IN ("CreatePolicy", "CreatePolicyVersion", "PutGroupPolicy", "PutRolePolicy", "PutUserPolicy") AND aws.cloudtrail.error_code IS NULL AND aws.cloudtrail.flattened.request_parameters.policy_document LIKE '*\"Effect\":\"Allow\"*' AND (aws.cloudtrail.flattened.request_parameters.policy_document LIKE '*\"NotAction\"*' OR aws.cloudtrail.flattened.request_parameters.policy_document LIKE '*\"NotResource\"*')) OR
  (aws.cloudtrail.event_name = "UpdateFunctionConfiguration" AND aws.cloudtrail.flattened.request_parameters.layers IS NOT NULL AND aws.cloudtrail.error_code IS NULL) OR
  (aws.cloudtrail.event_name IN ("StopLogging", "PutEventSelectors") AND aws.cloudtrail.error_code IS NULL) OR
  (aws.cloudtrail.event_name = "PutBucketLifecycleConfiguration" AND aws.cloudtrail.flattened.request_parameters.lifecycle_configuration.rules.status = "Enabled" AND aws.cloudtrail.flattened.request_parameters.lifecycle_configuration.rules.expiration.days = 1 AND aws.cloudtrail.error_code IS NULL) OR
  (aws.cloudtrail.event_name = "LeaveOrganization")
)
| EVAL detection_technique = CASE(
    aws.cloudtrail.event_name = "CreateAccessKey", "IAM Access Key Creation",
    aws.cloudtrail.event_name = "UpdateAssumeRolePolicy", "IAM Role Trust Policy Modified",
    aws.cloudtrail.event_name IN ("CreatePolicy", "CreatePolicyVersion", "PutGroupPolicy", "PutRolePolicy", "PutUserPolicy"), "IAM Policy with NotAction or NotResource",
    aws.cloudtrail.event_name = "UpdateFunctionConfiguration", "Lambda Layer Attached or Modified",
    aws.cloudtrail.event_name IN ("StopLogging", "PutEventSelectors"), "CloudTrail Logging Impaired",
    aws.cloudtrail.event_name = "PutBucketLifecycleConfiguration", "S3 Lifecycle Policy for Rapid Data Deletion",
    aws.cloudtrail.event_name = "LeaveOrganization", "Account Attempted to Leave Organization",
    true, "Unknown"
)
| EVAL object_affected = COALESCE(
    aws.cloudtrail.flattened.request_parameters.userName,
    aws.cloudtrail.flattened.request_parameters.roleName,
    aws.cloudtrail.flattened.request_parameters.policyName,
    aws.cloudtrail.flattened.request_parameters.functionName,
    aws.cloudtrail.flattened.request_parameters.name,
    aws.cloudtrail.flattened.request_parameters.trailName,
    aws.cloudtrail.flattened.request_parameters.bucketName,
    cloud.account.id
)
| STATS count = COUNT(*) BY detection_technique, aws.cloudtrail.event_name, cloud.account.id, aws.cloudtrail.user_identity.arn, aws.cloudtrail.source_ip_address, aws.cloudtrail.error_code, aws.cloudtrail.error_message, object_affected
| RENAME aws.cloudtrail.user_identity.arn AS user, aws.cloudtrail.source_ip_address AS src_ip
| KEEP detection_technique, aws.cloudtrail.event_name, cloud.account.id, user, src_ip, object_affected, aws.cloudtrail.error_code, aws.cloudtrail.error_message, count
```