### ESXi VM Escape via Multi-CVE Chain
---

A sophisticated threat actor is leveraging a chain of three vulnerabilities (CVE-2025-22226, CVE-2025-22224, CVE-2025-22225) to achieve a full VM escape, moving from a guest virtual machine to gain complete control of the underlying ESXi hypervisor. The attack culminates in the deployment of a stealthy backdoor that uses VMware's own Virtual Sockets (VSOCK) for command and control, rendering its traffic invisible to traditional network security monitoring.

While the core article details a specific VM escape toolchain, broader threat intelligence reveals that PRC state-sponsored actors are deploying other sophisticated backdoors like BRICKSTORM, which also utilizes VSOCK for C2 in virtualized environments. This indicates a growing trend among advanced adversaries to leverage hypervisor-specific communication channels for stealthy persistence and command execution, moving beyond the specific exploit kit detailed in the report.

### Actionable Threat Data
---

Monitor for the execution of devcon.exe with command-line arguments disabling VMware-specific devices, such as devcon.exe disable "PCI\VEN_15AD&DEV_0740" or devcon.exe disable "ROOT\VMWVMCIHOSTDEV".

Detect the use of the Kernel Driver Utility (kdu.exe), a known "Bring Your Own Vulnerable Driver" tool, particularly when used with the -map argument to load an unsigned driver into kernel memory.

Flag sequences of netsh advfirewall commands that create outbound block rules for all IP addresses (remoteip=0.0.0.0-255.255.255.255) while simultaneously creating allow rules for internal network ranges (e.g., 10.0.0.0/8, 172.16.0.0/12).

On ESXi hosts, monitor the file /var/run/inetd.conf for modifications that add new services, especially those that execute files from temporary locations like /var/run/ or /tmp/. Also, watch for SIGHUP signals sent to the inetd process ID, which forces it to reload its configuration.

On ESXi hosts, periodically run lsof -a -i @2:10000 or similar commands to inspect for processes listening on high-numbered VSOCK ports. The backdoor VSOCKpuppet specifically listens on CID 2 (hypervisor) and port 10000.

Monitor Windows event logs for the installation of VMware drivers vmci.inf and vsock.inf via InfDefaultInstall.exe on systems where they are not typically expected, as this is a prerequisite for the client-side tool to communicate with the hypervisor backdoor.

### Layered Query
---

```sql
// ESXi VM Escape Toolkit - Multi-Stage Detection Chain
// High-fidelity indicators of compromise related to ESXi hypervisor escape / ransomware prep

FROM "winlogbeat-*", "endpoint-*" , "logs-endpoint.events.*"
| WHERE
    // Important: adjust time window according to your needs (this is just an example)
    @timestamp >= NOW() - 1 hours

    AND (
        // Layer 1 - Known malicious file hashes (very high fidelity)
        file.hash.SHA256 IN (
            "37972a232ac6d8c402ac4531430967c1fd458b74a52d6d1990688d88956791a7",
            "4614346fc1ff74f057d189db45aa7dc25d6e7f3d9b68c287a409a53c86dca25e",
            "c3f8da7599468c11782c2332497b9e5013d98a1030034243dfed0cf072469c89",
            "2bc5d02774ac1778be22cace51f9e35fe7b53378f8d70143bf646b68d2c0f94c"
        )
        -- ... WHERE
        --file.hash.SHA256 IN (...)
        --OR process.name == "kdu.exe"
        --OR (
        --    process.name == "devcon.exe"
        --    AND process.command_line RLIKE "(?i)disable.*(VMWVMCIHOSTDEV|PCI\\\\VEN_15AD&DEV_0740)"
        --)
        OR

        // Layer 2 - Disabling VMware VMCI devices (very characteristic of this TTP)
        (
            process.name == "devcon.exe"
            AND process.command_line RLIKE "(?i)disable.*(PCI\\\\VEN_15AD&DEV_0740|ROOT\\\\VMWVMCIHOSTDEV)"
        )

        OR

        // Layer 3 - Kernel Driver Utility (KDU) - strong BYOVD indicator
        process.name == "kdu.exe"

        OR

        // Layer 4 - Aggressive host-wide outbound block (common ransomware/ESXi prep step)
        (
            process.name == "netsh.exe"
            AND process.command_line RLIKE "(?i)advfirewall\\s+firewall\\s+add\\s+rule.*action=block.*dir=out.*remoteip=(any|0\\.0\\.0\\.0-255\\.255\\.255\\.255)"
        )

        OR

        // Layer 5 - Modification of critical ESXi inetd.conf (backdoor/service hijack)
        (
            file.path RLIKE "(?i)/var/run/inetd\\.conf"
            AND event.action IN ("creation", "overwrite", "modification", "changed")
        )
    )

| EVAL
    detection_reason = CASE(
        file.hash.SHA256 IN ("37972a232ac6d8c402ac4531430967c1fd458b74a52d6d1990688d88956791a7","4614346fc1ff74f057d189db45aa7dc25d6e7f3d9b68c287a409a53c86dca25e","c3f8da7599468c11782c2332497b9e5013d98a1030034243dfed0cf072469c89","2bc5d02774ac1778be22cace51f9e35fe7b53378f8d70143bf646b68d2c0f94c"),
            "Known ESXi Exploit Toolkit file hash",

        process.name == "devcon.exe" AND process.command_line RLIKE "(?i)disable.*(PCI\\\\VEN_15AD&DEV_0740|ROOT\\\\VMWVMCIHOSTDEV)",
            "VMware VMCI device disabled via devcon.exe",

        process.name == "kdu.exe",
            "Kernel Driver Utility (KDU) execution",

        process.name == "netsh.exe" AND process.command_line RLIKE "(?i)action=block.*dir=out.*remoteip.*(any|0\\.0\\.0\\.0-255\\.255\\.255\\.255)",
            "Host network isolation via netsh (outbound block)",

        file.path RLIKE "(?i)/var/run/inetd\\.conf" AND event.action IN ("creation","overwrite","modification"),
            "ESXi inetd.conf file modified/created",

        true, "Multiple/unknown trigger"
    )

| STATS
    first_occurrence = MIN(@timestamp),
    last_occurrence  = MAX(@timestamp),
    event_count      = COUNT(*),
    processes        = VALUES(process.name),
    command_lines    = VALUES(process.command_line),
    parent_processes = VALUES(process.parent.name),
    file_paths       = VALUES(file.path),
    file_names       = VALUES(file.name),
    file_hashes      = VALUES(file.hash.SHA256),
    file_actions     = VALUES(event.action)
  BY
    host.name,
    user.name,
    detection_reason

| EVAL
    firstTime = TO_DATETIME(first_occurrence),
    lastTime  = TO_DATETIME(last_occurrence)

| SORT first_occurrence DESC

| KEEP
    firstTime,
    lastTime,
    host.name,
    user.name,
    detection_reason,
    event_count,
    processes,
    command_lines,
    parent_processes,
    file_paths,
    file_names,
    file_hashes,
    file_actions
```