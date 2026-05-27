### SERPENTINE#CLOUD: Abuse of Cloudflare Tunnels and Python Payloads
---

The SERPENTINE#CLOUD campaign is a multi-stage infection chain that utilizes Cloudflare Tunnel infrastructure to host and deliver stealthy Python-based malware via malicious .LNK files. The attack culminates in the memory-only execution of Donut-packed payloads, such as AsyncRAT or RevengeRAT, while using advanced obfuscation and "vibe coding" script techniques to evade traditional defenses.

Beyond the use of Cloudflare Tunnels, recent research indicates a refinement in "vibe coding" (using LLM-generated code comments) to make malicious scripts appear as benign development tasks, and a shift toward Early Bird APC injection for process hijacking. This is noteworthy because it targets the gap between automated EDR detection and manual analyst review, where descriptive, "friendly" code comments may bypass initial scrutiny.

### Actionable Threat Data
---

Cloudflare Tunnel Detection: Monitor for outbound network connections to *.trycloudflare.com and *.duckdns.org, especially from native Windows utilities like cmd.exe, robocopy.exe, or cscript.exe.

WebDAV Ingress Monitoring: Detect the use of the DavWWWRoot or @SSL strings in command-line arguments, which indicates the mounting of remote WebDAV shares for payload staging.

Python Execution Anomalies: Alert on python.exe or pythonw.exe executing scripts from non-standard, writable user directories such as %USERPROFILE%\Contacts\ or %TEMP%\.

Early Bird APC Injection: Monitor for the sequence of a process (e.g., notepad.exe) being created in a CREATE_SUSPENDED state followed immediately by VirtualAllocEx and QueueUserAPC calls from a Python parent process.

Stealth Persistence Indicators: Search for VBScript files in the Startup folder (e.g., pws1.vbs) that execute infinite loops using WshShell.SendKeys("+") to simulate user activity and prevent system idling/locking.

Specific IOCs for Splunk Hunting:

    C2 IP: 51.89.212.145

    Malicious Domains: nhvncpure.shop, nhvncpure.sbs, nhvncpure.click, nhvncpure.duckdns.org

    Registry/File Paths: Monitoring for new .vbs or .bat files dropped into \Microsoft\Windows\Start Menu\Programs\Startup\ coinciding with robocopy activity.

### Layered Search
---

```sql
| union
    [
        | tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process_name=robocopy.exe AND Processes.process="*@SSL\\DavWWWRoot*" AND Processes.process="*trycloudflare.com*" by _time Processes.dest Processes.user Processes.process Processes.parent_process
        | rename Processes.* as *
        | eval detection_stage="Initial Access: Robocopy WebDAV Download"
    ]
    [
        | tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process_name=python.exe AND (Processes.process="*\\Contacts\\Extracted\\*" OR Processes.process="*\\Contacts\\Print\\*") by _time Processes.dest Processes.user Processes.process Processes.parent_process
        | rename Processes.* as *
        | eval detection_stage="Execution: Suspicious Python Execution"
    ]
    [
        | tstats `summariesonly` count from datamodel=Endpoint.Processes where (Processes.process_name IN ("wscript.exe", "cscript.exe")) AND Processes.process="*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*.vbs" by _time Processes.dest Processes.user Processes.process Processes.parent_process
        | rename Processes.* as *
        | eval detection_stage="Persistence: VBS in Startup Folder"
    ]
    [
        | tstats `summariesonly` count from datamodel=Network_Traffic where (All_Traffic.dest_ip="51.89.212.145" OR All_Traffic.query IN ("nhvncpure.shop", "nhvncpure.sbs", "nhvncpure.click", "*.duckdns.org", "*.trycloudflare.com")) by _time All_Traffic.src All_Traffic.user All_Traffic.process_name All_Traffic.dest_ip All_Traffic.query
        | rename All_Traffic.src as dest, All_Traffic.process_name as parent_process
        | eval detection_stage="C2: Known Malicious Communication"
    ]
`comment("The union command combines results from the four different detection stanzas.")`
| rename dest as host
`comment("Group all observed activities by host to correlate different stages of the attack chain.")`
| stats
    dc(detection_stage) as distinct_stage_count,
    values(detection_stage) as stages_observed,
    earliest(_time) as first_seen,
    latest(_time) as last_seen,
    values(user) as users,
    values(parent_process) as parent_processes,
    values(process) as processes_and_commands,
    values(dest_ip) as c2_ips,
    values(query) as c2_queries
    by host
`comment("Convert epoch timestamps to a human-readable format.")`
| convert ctime(first_seen)
| convert ctime(last_seen)
`comment("Filtering for hosts with more than one distinct stage significantly increases fidelity, but may miss hosts where only one stage was observed. Adjust as needed.")`
| where distinct_stage_count > 1
`comment("Sort results to show the most suspicious hosts first.")`
| sort - distinct_stage_count
`comment("Provide a final, clean table of results.")`
| table host, distinct_stage_count, stages_observed, first_seen, last_seen, users, parent_processes, processes_and_commands, c2_ips, c2_queries
| `serpentine_cloud_multi_stage_activity`
```

### Updated for observed 2026 TTPs
---

```sql
| union
    [
        // Stage 1: Initial Access - Robocopy WebDAV download from Cloudflare Tunnel (unchanged + added more patterns)
        | tstats `summariesonly` count from datamodel=Endpoint.Processes
          where Processes.process_name=robocopy.exe
          AND (Processes.process="*\\SSL\\DavWWWRoot*" OR Processes.process="*WebDAV*")
          AND Processes.process IN ("*trycloudflare.com*", "*ngrok.io*", "*ngrok-free.app*")
          by _time Processes.dest Processes.user Processes.process Processes.parent_process Processes.process_id
        | rename Processes.* as *
        | eval detection_stage="1-Initial_Access: Robocopy WebDAV Download (Cloudflare/ngrok)"
        | eval stage_weight=3
    ]
    [
        // Stage 1b: New - Suspicious LNK execution (common initial vector in 2025-2026 campaigns)
        | tstats `summariesonly` count from datamodel=Endpoint.Processes
          where Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","rundll32.exe")
          AND (Processes.process="*\\*.lnk" OR Processes.process="*file://*" OR Processes.original_file_name="cmd.exe" AND Processes.process="*shortcut.lnk*")
          AND Processes.parent_process_name IN ("explorer.exe","winword.exe","outlook.exe","iexplore.exe")
          by _time Processes.dest Processes.user Processes.process Processes.parent_process Processes.process_id Processes.file_hash
        | rename Processes.* as *
        | eval detection_stage="1b-Initial_Access: Suspicious LNK Execution"
        | eval stage_weight=4
    ]
    [
        // Stage 2: Execution - Obfuscated WSF/BAT (jun*.bat style) or suspicious Python spawn
        | tstats `summariesonly` count from datamodel=Endpoint.Processes
          where (Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe"))
          AND (Processes.process="*jun*.bat" OR Processes.process="*.wsf" OR Processes.process="*obfuscated*" OR Processes.process="*base64*" OR Processes.process="*from base64*")
          AND Processes.process IN ("*Temp*" OR "*AppData*" OR "*Startup*")
          by _time Processes.dest Processes.user Processes.process Processes.parent_process Processes.process_id
        | rename Processes.* as *
        | eval detection_stage="2-Execution: Obfuscated WSF/BAT Execution"
        | eval stage_weight=5
    ]
    [
        // Stage 2b: Execution - Suspicious Python execution (Contacts paths + in-memory/evasion)
        | tstats `summariesonly` count from datamodel=Endpoint.Processes
          where Processes.process_name=python.exe
          AND (Processes.process="*\\Contacts\\Extracted\\*" OR Processes.process="*\\Contacts\\Print\\*" OR Processes.process="*__pycache__*" OR Processes.process="*reflective*")
          AND Processes.parent_process_name IN ("notepad.exe","explorer.exe","cmd.exe")   // common injection targets
          by _time Processes.dest Processes.user Processes.process Processes.parent_process Processes.process_id
        | rename Processes.* as *
        | eval detection_stage="2b-Execution: Suspicious In-Memory Python (Evasion)"
        | eval stage_weight=6
    ]
    [
        // Stage 3: Persistence - VBS/Startup + new common RAT persistence patterns
        | tstats `summariesonly` count from datamodel=Endpoint.Processes
          where (Processes.process_name IN ("wscript.exe","cscript.exe"))
          AND Processes.process="*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*.vbs"
          OR Processes.process="*\\AppData\\Roaming\\*\\*.vbs"
          by _time Processes.dest Processes.user Processes.process Processes.parent_process
        | rename Processes.* as *
        | eval detection_stage="3-Persistence: VBS/Startup Folder"
        | eval stage_weight=5
    ]
    [
        // Stage 4: C2 - Expanded IOCs (DuckDNS + ngrok + known 2025-2026 examples)
        | tstats `summariesonly` count from datamodel=Network_Traffic
          where (All_Traffic.dest_ip IN ("51.89.212.145")
               OR All_Traffic.query IN ("*.duckdns.org", "nhvncpure.shop", "nhvncpure.sbs", "nhvncpure.click",
                                        "*trycloudflare.com", "*.ngrok.io", "*.ngrok-free.app",
                                        "deadpoolstart2025.duckdns.org", "ncmomenthv.duckdns.org", "asyncmoney.duckdns.org"))
          by _time All_Traffic.src All_Traffic.user All_Traffic.process_name All_Traffic.dest_ip All_Traffic.query All_Traffic.user_agent
        | rename All_Traffic.src as dest, All_Traffic.process_name as parent_process
        | eval detection_stage="4-C2: Known Malicious Communication (2025-2026 IOCs)"
        | eval stage_weight=8
    ]

| rename dest as host
| eval time_bucket = relative_time(_time, "-5m@m")
| stats
    dc(detection_stage) as distinct_stage_count,
    values(detection_stage) as stages_observed,
    values(stage_weight) as stage_weights,
    sum(stage_weight) as risk_score,
    earliest(_time) as first_seen,
    latest(_time) as last_seen,
    values(user) as users,
    values(parent_process) as parent_processes,
    values(process) as processes_and_commands,
    values(file_hash) as file_hashes,
    values(dest_ip) as c2_ips,
    values(query) as c2_queries,
    values(user_agent) as user_agents
  by host time_bucket
| where distinct_stage_count >= 3   // Default high-fidelity; tune to >=2 for more sensitivity (higher FPs)
| eval risk_level=case(risk_score>=20, "High", risk_score>=12, "Medium", true(), "Low")
| convert ctime(first_seen) ctime(last_seen)
| sort - risk_score, -distinct_stage_count
| table host, risk_score, risk_level, distinct_stage_count, stages_observed, first_seen, last_seen, users, parent_processes, processes_and_commands, file_hashes, c2_ips, c2_queries, user_agents
| `serpentine_cloud_multi_stage_activity`   // Keep your macro if it adds extra formatting/alerting
```