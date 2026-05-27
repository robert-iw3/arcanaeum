<p align="center">
  <img src="https://www.elastic.co/security-labs/grid.svg" />
</p>

## AWS SNS Abuse: Data Exfiltration and Phishing

Data Exfiltration via SNS

Exfiltration via SNS starts with creating a topic that serves as a proxy for receiving stolen data and delivering it to the external media source, such as email or mobile. Adversaries would then subscribe that media source to the topic so that any data received is forwarded to them. After this is staged, it is only a matter of packaging data and publishing it to the SNS topic, which handles the distribution. This method allows adversaries to bypass traditional data protection mechanisms such as network ACLs, and exfiltrate information to unauthorized external destinations.

Example Workflow:

    Land on EC2 instance and perform discovery of sensitive data, stage it for later

    Leverage IMDSv2 and STS natively with the installed AWS CLI to get temporary creds

    Create a topic in SNS and attach an external email address as a subscriber

    Publish sensitive information to the topic, encoded in Base64 (or plaintext)

    The external email address receives the exfiltrated data

https://www.elastic.co/docs/solutions/security/detect-and-alert/create-detection-rule#create-new-terms-rule

## SNS Topic Created by Rare User

Detection Rule Source
Hunting Query Source
MITRE ATT&CK: T1608

```sql
event.dataset: "aws.cloudtrail"
    and event.provider: "sns.amazonaws.com"
    and event.action: "Publish"
    and aws.cloudtrail.user_identity.type: "AssumedRole"
    and aws.cloudtrail.user_identity.arn: *i-*
```

##

Hunting Query (ES|QL)

Our hunting query focuses on the CreateTopic API action from an entity whose identity type is an assumed role. We also parse the ARN to ensure that it is an EC2 instance this request is sourcing from. We can then aggregate on cloud account, entity (EC2 instance ID), assumed role name, region and user agent. If it is unusual for the EC2 instance reported to be creating SNS topics randomly, then it may be a good anomalous signal to investigate.

```sql
from logs-aws.cloudtrail-*
| where @timestamp > now() - 7 day
| WHERE
    event.dataset == "aws.cloudtrail" AND
    event.provider == "sns.amazonaws.com" AND
    event.action == "Publish"
    and aws.cloudtrail.user_identity.type == "AssumedRole"
| DISSECT aws.cloudtrail.request_parameters "{%{?message_key}=%{message}, %{?topic_key}=%{topic_arn}}"
| DISSECT aws.cloudtrail.user_identity.arn "%{?}:assumed-role/%{assumed_role_name}/%{entity}"
| DISSECT user_agent.original "%{user_agent_name} %{?user_agent_remainder}"
| WHERE STARTS_WITH(entity, "i-")
| STATS regional_topic_publish_count = COUNT(*) by cloud.account.id, entity, assumed_role_name, topic_arn, cloud.region, user_agent_name
| SORT regional_topic_publish_count ASC
```

Hunting Notes:

    It is unusual already for credentials from an assumed role for an EC2 instance to be creating SNS topics randomly.

    If a user identity access key (aws.cloudtrail.user_identity.access_key_id) exists in the CloudTrail audit log,
    then this request was accomplished via the CLI or programmatically. These keys could be compromised and warrant further investigation.

    An attacker could pivot into Publish API actions being called to this specific topic to identify which AWS resource is
    publishing messages. With access to the topic, the attacker could then further investigate the subscribers list to identify unauthorized subscribers.

## SNS Topic Subscription with Email by Rare User

Detection Rule Source
Hunting Query Source
MITRE ATT&CK: T1567, T1530

```sql
event.dataset: "aws.cloudtrail"
    and event.provider: "sns.amazonaws.com"
    and event.action: "Subscribe"
    and aws.cloudtrail.request_parameters: *protocol=email*
```

##

Hunting Query (ES|QL)

Our hunting query leverages ES|QL but parses the Subscribe API action parameters to filter further on the email protocol being specified. It also parses out the name of the user-agent, but relies further on aggregations to potentially identify other anomalous user-agent attributes. We've also included the region where the subscription occurred, as it may be uncommon for certain regions to be subscribed to others, depending on the specific business context of an organization.

```sql
from logs-aws.cloudtrail-*
| where @timestamp > now() - 7 day
| WHERE
    event.dataset == "aws.cloudtrail" AND
    event.provider == "sns.amazonaws.com" AND
    event.action == "Subscribe"
| DISSECT aws.cloudtrail.request_parameters "%{?protocol_key}=%{protocol}, %{?endpoint_key}=%{redacted}, %{?return_arn}=%{return_bool}, %{?topic_arn_key}=%{topic_arn}}"
| DISSECT user_agent.original "%{user_agent_name} %{?user_agent_remainder}"
| WHERE protocol == "email"
| STATS regional_topic_subscription_count = COUNT(*) by aws.cloudtrail.user_identity.arn, cloud.region, source.address, user_agent_name
| WHERE regional_topic_subscription_count == 1
| SORT regional_topic_subscription_count ASC
```

Hunting Notes:

    If a user identity access key (aws.cloudtrail.user_identity.access_key_id) exists in the CloudTrail audit log,
    then this request was accomplished via the CLI or programmatically. These keys could be compromised and warrant further investigation.

    Ignoring the topic ARN during aggregation is important to identify first occurrence anomalies of subscribing to SNS topic with an email.
    By not grouping subscriptions by topic ARN, we ensure that the query focuses on detecting unexpected or infrequent subscriptions only,
    regardless of specific topics already established.

    Another query may be required with the user identity ARN as an inclusion filter to identify which topic they subscribed to.
    If an anomalous user-agent name is observed, a secondary investigation into the user-agent string may be required to determine
    if it's associated with automated scripts, uncommon browsers, or mismatched platforms. While it is simple to fake these,
    adversaries have been known not to for undisclosed reasons.

## SNS Topic Message Published by Rare User

```sql
event.dataset: "aws.cloudtrail"
    and event.provider: "sns.amazonaws.com"
    and event.action: "Publish"
    and aws.cloudtrail.user_identity.type: "AssumedRole"
    and aws.cloudtrail.user_identity.arn: *i-*
```
##

Hunting Query (ES|QL)

Our hunting query leverages ES|QL and also focused on SNS logs where the API action is Publish. This only triggers if the user identity type is an assumed role and the user identity ARN is an EC2 instance ID. Aggregating on account ID, entity, assumed role, SNS topic and region help us identify any further anomalies based on expectancy of this activity. We can leverage the user agent to identify these calls being made by unusual tools or software as well.

```sql
from logs-aws.cloudtrail-*
| where @timestamp > now() - 7 day
| WHERE
    event.dataset == "aws.cloudtrail" AND
    event.provider == "sns.amazonaws.com" AND
    event.action == "Publish"
    and aws.cloudtrail.user_identity.type == "AssumedRole"
| DISSECT aws.cloudtrail.request_parameters "{%{?message_key}=%{message}, %{?topic_key}=%{topic_arn}}"
| DISSECT aws.cloudtrail.user_identity.arn "%{?}:assumed-role/%{assumed_role_name}/%{entity}"
| DISSECT user_agent.original "%{user_agent_name} %{?user_agent_remainder}"
| WHERE STARTS_WITH(entity, "i-")
| STATS regional_topic_publish_count = COUNT(*) by cloud.account.id, entity, assumed_role_name, topic_arn, cloud.region, user_agent_name
| SORT regional_topic_publish_count ASC
```

## SNS Direct-to-Phone Messaging Spike

Hunting Query Source
MITRE ATT&CK: T1660

##

Hunting Query (ES|QL)

This query detects a spike in direct SNS messages, which may indicate smishing campaigns from compromised AWS accounts.

```sql
from logs-aws.cloudtrail-*
| WHERE @timestamp > now() - 7 day
| EVAL target_time_window = DATE_TRUNC(10 seconds, @timestamp)
| WHERE
    event.dataset == "aws.cloudtrail" AND
    event.provider == "sns.amazonaws.com" AND
    event.action == "Publish" AND
    event.outcome == "success" AND
    aws.cloudtrail.request_parameters LIKE "*phoneNumber*"
| DISSECT user_agent.original "%{user_agent_name} %{?user_agent_remainder}"
| STATS sms_message_count = COUNT(*) by target_time_window, cloud.account.id, aws.cloudtrail.user_identity.arn, cloud.region, source.address, user_agent_name
| WHERE sms_message_count > 30
```

## Key Takeaways:

    AWS SNS is a powerful service, but can be misused for malicious purposes, including phishing (smishing) and data exfiltration.

    Adversaries may abuse production SNS permissions using pre-approved Sender IDs, Origination IDs, or long/short codes to send
    messages outside an organization.

    Threat actors may weaponize misconfigurations in IAM policies, CloudTrail logging gaps and SNS API limitations to fly under the radar.

    While in-the-wild (ItW) abuse of SNS is not frequently reported, we are confident that its weaponization and targeted exploitation
    are already occurring or will emerge eventually.

    AWS CloudTrail does not capture phone numbers or messages in SNS logs, making CloudWatch third-party monitoring essential for deeper analysis
    Threat hunting queries can help detect SNS topics being created, subscribed to, or receiving a spike in direct messages, signaling potential abuse.

    Detection strategies include monitoring SNS API actions, identifying unusual SNS message spikes and flagging anomalies from EC2 or Lambda sources.
    Defensive measures should include IAM policy hardening, CloudTrail & SNS logging, anomaly-based detections and security best practices as recommended by AWS to reduce attack surface.
