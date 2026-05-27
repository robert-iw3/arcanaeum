<p align="center">
  <img src="https://www.elastic.co/security-labs/grid.svg" />
</p>

## The DPRK strikes using a new variant of RUSTBUCKET

Key takeaways

    The RUSTBUCKET malware family is in an active development phase, adding built-in persistence and focusing on signature reduction.

    REF9135 actors are continually shifting their infrastructure to evade detection and response.

    The DPRK continues financially motivated attacks against cryptocurrency service providers.

    If you are running Elastic Defend, you are protected from REF9135

## Hunting queries

The events for EQL are provided with the Elastic Agent using the Elastic Defend integration. Hunting queries could return high signals or false positives. These queries are used to identify potentially suspicious behavior, but an investigation is required to validate the findings.
EQL queries

Using the Timeline section of the Security Solution in Kibana under the “Correlation" tab, you can use the below EQL queries to hunt for behaviors observed in REF9135.

##

Suspicious Curl File Download via Osascript

```sql
process where process.parent.name : "osascript" and process.name : "curl" and process.args : "-o"
```

##

Suspicious URL as argument to Self-Signed Binary
```sql
process where event.type == "start" and event.action == "exec" and
 process.code_signature.trusted == false and
 process.code_signature.signing_id regex~ """[A-Za-z0-9\_\s]{2,}\-[a-z0-9]{40}""" and
 process.args : "http*" and process.args_count <= 3
```