### North Korean Linux Stealth Rootkit Analysis
---

This report details a stealthy Linux Loadable Kernel Module (LKM) rootkit, recently exposed through a data dump from a suspected North Korean hacking group, likely Kimsuky. The rootkit leverages the khook library to hide its presence, processes, network activity, and persistence mechanisms, enabling sophisticated and covert operations on compromised Linux systems.

Recent intelligence indicates that North Korean threat actors, including Kimsuky, continue to evolve their TTPs, with a focus on supply chain attacks and the use of novel loaders like XORIndex to deliver infostealers and backdoors. This highlights a broader trend of North Korean groups diversifying their attack vectors beyond traditional spear-phishing to compromise a wider range of targets and maintain persistent access.

### Actionable Threat Data
---

Kernel Taint Detection: Monitor for kernel taint flags, specifically the 'E' flag (unsigned module loaded) and 'O' flag (out-of-tree module loaded), which indicate the presence of potentially malicious LKMs. This can be observed by checking /proc/sys/kernel/tainted or analyzing dmesg and kern.log output for "Tainted:" messages.

Hidden File and Directory Detection: Look for files and directories that are present on the filesystem but are hidden from standard listing commands (ls). Specifically, investigate the existence of /usr/lib64/tracker-fs, /usr/include/tracker-fs/tracker-efs, and persistence files under /etc/init.d and /etc/rc*.d that are not visible through normal directory listings but can be accessed directly (e.g., using stat or file commands).

Hidden Process and Network Activity Detection: Identify processes that are running but are not visible through standard process listing tools (ps) or network connections that are active but lack associated process information (ss). This rootkit hides its backdoor process (tracker-efs) and its network activity.

Suspicious Kernel Module Activity: Monitor for the loading of new or unrecognized kernel modules, especially those that are unsigned or not part of the standard operating system distribution. While the specific module name vmwfxs can be changed, any unexpected LKM loading should be investigated.

Anti-Forensic Environment Variables: Detect processes with environment variables set to unusual values, particularly those related to command history (e.g., HISTFILE=/dev/null, HISTORY=/dev/null, BASH_HISTORY=/dev/null) or shell timeouts, as these are used by the rootkit's backdoor to evade forensic analysis.

### Search
---
Name: Linux Rootkit and Anti-Forensic Activity (DPRK Stealth Rootkit)

Author: RW

Date: 2025-08-14

References:

- https://sandflysecurity.com/blog/leaked-north-korean-linux-stealth-rootkit-analysis

- https://www.kernel.org/doc/html/latest/admin-guide/tainted-kernels.html

MITRE TTPs: T1564.001, T1547.006, T1070.004, T1070.006, T1562.003

Splunk Prerequisites:

    - Splunk Common Information Model (CIM) add-on installed and data mapped.

    - Endpoint data (e.g., Sysmon, Crowdstrike, Carbon Black) populating the Endpoint data model.

    - Linux syslog data (specifically kern.log messages) available, typically sourcetype=syslog.

```sql
-- Pattern 1: Hidden Rootkit Artifacts (IOCs)
-- Detects file or process events related to known malicious paths from the rootkit.
`comment("This search requires the Endpoint.Processes and Endpoint.Filesystem data models.")`
(from datamodel=Endpoint.Processes) OR (from datamodel=Endpoint.Filesystem)
| eval process_path=coalesce(Processes.process_path, Filesystem.file_path), process=coalesce(Processes.process, Filesystem.file_name), user=coalesce(Processes.user, Filesystem.user), parent_process=Processes.parent_process, action=Filesystem.action
| where (
    (match(process_path, /(?i)(\/usr\/lib64\/tracker-fs|\/usr\/include\/tracker-fs\/tracker-efs|\/etc\/init.d\/tracker-fs|\/etc\/rc[235]\.d\/S55tracker-fs|\/proc\/acpi\/pcicard)/)) OR
    (match(process, /(?i)(\/usr\/lib64\/tracker-fs|\/usr\/include\/tracker-fs\/tracker-efs|\/etc\/init.d\/tracker-fs|\/etc\/rc[235]\.d\/S55tracker-fs|\/proc\/acpi\/pcicard)/))
)
-- FP Tuning: These paths are highly specific. FPs are unlikely but attackers can change these IOCs.
| eval
    DetectionPattern = "Hidden Rootkit Artifact Detected",
    Details = case(
        isnotnull(process), process,
        isnotnull(action), action + " file: " + process_path,
        true(), "N/A"
    ),
    AccountName = coalesce(user, "N/A"),
    SuspiciousProcess = coalesce(Processes.process_name, Filesystem.file_name, "N/A"),
    SuspiciousCommandLine = coalesce(process, "N/A"),
    ParentProcess = coalesce(parent_process, "N/A"),
    HostName = dest
| table _time, DetectionPattern, HostName, AccountName, SuspiciousProcess, SuspiciousCommandLine, ParentProcess, Details

| append [
    -- Pattern 2: Kernel Tainted by Unsigned Module
    -- Detects when the Linux kernel is tainted by an unsigned kernel module.
    `comment("This search requires syslog data, typically from kern.log.")`
    (index=* sourcetype=syslog process="kernel" "tainting kernel")
    -- FP Tuning: Add legitimate, unsigned kernel modules to the NOT clause to prevent FPs.
    | where NOT (searchmatch("message IN (*nvidia*, *vboxdrv*, *zfs*)"))
    | eval
        DetectionPattern = "Kernel Tainted by Unsigned Module",
        Details = _raw,
        AccountName = "N/A",
        SuspiciousProcess = process,
        SuspiciousCommandLine = "N/A",
        ParentProcess = "N/A",
        HostName = host
    | table _time, DetectionPattern, HostName, AccountName, SuspiciousProcess, SuspiciousCommandLine, ParentProcess, Details
]

| append [
    -- Pattern 3: Network Connection Without Associated Process
    -- Detects network activity without a corresponding process, a key sign of a process-hiding rootkit.
    `comment("This search requires the Endpoint.Network_Traffic data model.")`
    from datamodel=Endpoint.Network_Traffic
    | where All_Traffic.os="Linux" AND All_Traffic.action IN ("allowed", "success") AND (isnull(All_Traffic.process_name) OR All_Traffic.process_id=0)
    -- FP Tuning: Some legitimate low-level kernel or container networking tasks might trigger this. Exclude known ports/IPs if needed.
    | where NOT (cidrmatch("127.0.0.0/8", All_Traffic.dest_ip) OR cidrmatch("10.0.0.0/8", All_Traffic.dest_ip) OR cidrmatch("172.16.0.0/12", All_Traffic.dest_ip) OR cidrmatch("192.168.0.0/16", All_Traffic.dest_ip))
    | eval
        DetectionPattern = "Network Connection Without Associated Process",
        Details = "Action: " . All_Traffic.action . ", LocalPort: " . All_Traffic.dest_port . ", RemoteIP: " . All_Traffic.src_ip . ", RemotePort: " . All_Traffic.src_port,
        AccountName = "N/A",
        SuspiciousProcess = "Unknown (Hidden)",
        SuspiciousCommandLine = "N/A",
        ParentProcess = "N/A",
        HostName = All_Traffic.dest
    | table _time, DetectionPattern, HostName, AccountName, SuspiciousProcess, SuspiciousCommandLine, ParentProcess, Details
]

| append [
    -- Pattern 4: Anti-Forensic History Disabling
    -- Detects attempts to disable shell command history logging.
    `comment("This search requires the Endpoint.Processes data model.")`
    from datamodel=Endpoint.Processes
    | where Processes.os="Linux" AND (
        (Processes.process_name IN ("sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh") AND match(Processes.process, /(?i)(--noprofile|--norc|HISTFILE=\/dev\/null|HISTORY=\/dev\/null|BASH_HISTORY=\/dev\/null|unset HISTFILE|unset HISTORY|TMOUT=0)/))
        OR
        (Processes.process_name="ln" AND match(Processes.process, /(?i)-sf.*\/dev\/null/) AND match(Processes.process, /(?i)(\.bash_history|\.zsh_history|\.zhistory|\.history|\.sh_history)/))
    )
    -- FP Tuning: Legitimate scripts may use --noprofile or --norc. Exclude known benign parent processes if they cause noise.
    | eval
        DetectionPattern = "Anti-Forensic History Disabling",
        Details = Processes.process,
        AccountName = Processes.user,
        SuspiciousProcess = Processes.process_name,
        SuspiciousCommandLine = Processes.process,
        ParentProcess = Processes.parent_process,
        HostName = Processes.dest
    | table _time, DetectionPattern, HostName, AccountName, SuspiciousProcess, SuspiciousCommandLine, ParentProcess, Details
]

-- Final projection of combined results
| rename _time as TimeGenerated
| table TimeGenerated, DetectionPattern, HostName, AccountName, SuspiciousProcess, SuspiciousCommandLine, ParentProcess, Details
```