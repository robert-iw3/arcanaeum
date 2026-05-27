### Phishing Domain Activity Detection

    T1566 - Phishing
    T1566.002 - Spearphishing Link
    T1204 - User Execution
    T1204.001 - Malicious Link
    T1189 - Drive-by Compromise
    TA0001 - Initial Access
    TA0002 - Execution

```sql
| inputlookup unit42phishingcampaign.csv
| where Type = "domain"
| fields Value
| rename Value as PhishDomain
| map search="search index=email sourcetype=email earliest=-30d UrlDomain=$PhishDomain$ | fields _time, UrlDomain, sender, recipient, subject | eval SourceType=\"EmailUrlInfo\"" maxsearches=1000
| append [
    | inputlookup unit42phishingcampaign.csv
    | where Type = "domain"
    | fields Value
    | rename Value as PhishDomain
    | map search="search index=edr sourcetype=device_network_events earliest=-30d ActionType=ConnectionSuccess RemoteUrl=$PhishDomain$ | fields _time, RemoteUrl, DeviceName, UserName | eval SourceType=\"DeviceNetworkEvents_ConnectionSuccess\"" maxsearches=1000
]
| append [
    | inputlookup unit42phishingcampaign.csv
    | where Type = "domain"
    | fields Value
    | rename Value as PhishDomain
    | map search="search index=edr sourcetype=device_network_events earliest=-30d ActionType=HttpConnectionInspected | spath input=AdditionalFields output=HttpHost path=host | where HttpHost=$PhishDomain$ | fields _time, HttpHost, DeviceName, UserName | eval SourceType=\"DeviceNetworkEvents_HttpConnectionInspected\"" maxsearches=1000
]
```