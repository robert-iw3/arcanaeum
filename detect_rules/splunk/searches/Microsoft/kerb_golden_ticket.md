### Possible Golden Ticket Usage Detected via Kerberos Anomalies

This detection identifies potential Golden Ticket attacks by correlating multiple Windows Security Event IDs that are indicative of forged Kerberos TGT usage. Specifically, it focuses on accounts requesting TGTs using uncommon or high-privilege encryption types (0x17, 0x18, 0x12), interacting with the krbtgt service, and logging in using elevated privileges and interactive logon types (4624, 4672). The rule filters out computer accounts and performs deduplication and correlation across a series of Kerberos-related activities, aiming to surface accounts that could be using forged Kerberos tickets for lateral movement or privilege escalation.

```sql
index=* (sourcetype=WinEventLog:Security OR sourcetype=WinEventLog:ForwardedEvents)
| search EventCode=4768
| where Ticket_Encryption_Type IN ("0x17", "0x18", "0x12")
| search NOT Account_Name=*$*
| eval Account_Name=lower(replace(Account_Name, "@.*", ""))
| dedup Account_Name, _time
    | search [ search index=* (sourcetype=WinEventLog:Security OR sourcetype=WinEventLog:ForwardedEvents)
    | search EventCode=4769
    | where Ticket_Encryption_Type IN ("0x17", "0x18", "0x12")
    | search NOT Account_Name=*$*
    | search Service_Name=krbtgt
    | search Ticket_Options IN ("0x40810000", "0x60810010")
    | eval Account_Name=lower(replace(Account_Name, "@.*", ""))
    | table Account_Name ]
| search [ search index=* (sourcetype=WinEventLog:Security OR sourcetype=WinEventLog:ForwardedEvents)
    | search EventCode=4672
    | search NOT Account_Name=*$*
    | eval Account_Name=lower(Account_Name)
    | table Account_Name ]
| search [ search index=* (sourcetype=WinEventLog:Security OR sourcetype=WinEventLog:ForwardedEvents)
    | search EventCode=4624
    | search NOT Account_Name=*$*
    | eval Account_Name=lower(Account_Name)
    | where Logon_Type IN ("3", "10")
    | table Account_Name ]
| stats count, earliest(_time) as FirstSeen, latest(_time) as LastSeen, values(ComputerName) as InvolvedHosts by Account_Name
| eval FirstSeen=strftime(FirstSeen, "%Y-%m-%d %H:%M:%S")
| eval LastSeen=strftime(LastSeen, "%Y-%m-%d %H:%M:%S")
| where count > 1
| rename Account_Name as "Potentially Compromised Account", count as "Event Count", FirstSeen as "First Seen", LastSeen as "Last Seen", InvolvedHosts as "Involved Hosts"
| table "Potentially Compromised Account", "Event Count", "First Seen", "Last Seen", "Involved Hosts"
```