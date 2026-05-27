<p align="center">
  <img src="https://www.elastic.co/security-labs/grid.svg" />
</p>

## Monitoring Okta threats with Elastic Security

Setup the Okta integration in the fleet agent policy.

## Enable Okta detection rules

Elastic has 1000+ pre-built detection rules not only for Windows, Linux, and macOS endpoints, but also for several integrations, including Okta. You can view our current existing Okta rules and corresponding MITRE ATT&CK coverage.

To enable Okta rules, complete the following in the Elastic Stack:

    1 Navigation menu > Security > Manage > Rules
    2 Select “Load Elastic prebuilt rules and timeline templates"
    3 Once all rules are loaded: a. Select “Tags" dropdown b. Search “Okta" c. Select all rules > Build actions dropdown > Enable

We can start by navigating to Security > Detection Rules (SIEM) > Create new rules. We can then select ES|QL as the rule type.

## ES|QL

```sql
from logs-okta* [metadata _id, _version, _index]
    | WHERE event.dataset == "okta.system" and (okta.event_type LIKE "system*" or okta.event_type LIKE "user*") and okta.debug_context.debug_data.dt_hash IS NOT NULL and okta.actor.id != "unknown"
    | STATS count = COUNT_DISTINCT(okta.actor.id) by okta.debug_context.debug_data.dt_hash
    | WHERE count >= 2
    | SORT count DESC
```