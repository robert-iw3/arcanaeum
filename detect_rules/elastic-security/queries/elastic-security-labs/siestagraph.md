<p align="center">
  <img src="https://www.elastic.co/security-labs/grid.svg" />
</p>

## SiestaGraph: New implant uncovered in ASEAN member foreign ministry


    Likely multiple threat actors are accessing and performing live on-net operations against the Foreign Affairs Office of an ASEAN member using a likely vulnerable, and internet-connected, Microsoft Exchange server. Once access was achieved and secured, the mailboxes of targeted individuals were exported.

    Threat actors deployed a custom malware backdoor that leverages the Microsoft Graph API for command and control, which we're naming SiestaGraph.

    A modified version of an IIS backdoor called DoorMe was leveraged with new functionality to allocate shellcode and load additional implants.

## Hunting queries

The events for both KQL and EQL are provided with the Elastic Agent using the Elastic Defend integration. Hunting queries could return high signals or false positives. These queries are used to identify potentially suspicious behavior, but an investigation is required to validate the findings.

##

KQL query

Using the Discover app in Kibana, the below query will identify loaded IIS modules that have been identified as malicious by Elastic Defend (even if Elastic Defend is in “Detect Only" mode).

The proceeding and preceding wildcards (*) can be an expensive search over a large number of events.

```sql
event.code : “malicious_file" and event.action : "load" and process.name : “w3wp.exe" and process.command_line.wildcard : (*MSExchange* or *SharePoint*)
```

##

EQL queries

Using the Timeline section of the Security Solution in Kibana under the “Correlation" tab, you can use the below EQL queries to hunt for behaviors similar to the SiestaGraph backdoor and the observed DLL side-loading patterns.

Hunt for DLL Sideloading using the observed DLLs:

```sql
library where
 dll.code_signature.exists == false and
 process.code_signature.trusted == true and
 dll.name : ("log.dll", "APerfectDayBase.dll") and
 process.executable :
           ("?:\\Windows\\Tasks\\*",
            "?:\\Users\\*",
            "?:\\ProgramData\\*")
```

Hunt for scheduled task or service from a suspicious path:

```sql
process where event.type == "start" and
 process.executable : ("?:\\Windows\\Tasks\\*", "?:\\Users\\Public\\*", "?:\\ProgramData\\Microsoft\\*") and
 (process.parent.args : "Schedule" or process.parent.name : "services.exe")
```

Hunt for the SiestaGraph compiled file name and running as a scheduled task:

```sql
process where event.type == "start" and
 process.pe.original_file_name : "windowss.exe" and not process.name : "windowss.exe" and process.parent.args : "Schedule"
```

Hunt for unsigned executable using Microsoft Graph API:

```sql
network where event.action == "lookup_result" and
 dns.question.name : "graph.microsoft.com" and process.code_signature.exists == false
```