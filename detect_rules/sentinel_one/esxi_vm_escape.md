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
/*
 * title: ESXi VM Escape Toolkit Attack Chain
 * author: RW
 * date: 2026-01-11
 * description: Detects a multi-layered attack chain associated with an ESXi VM Escape toolkit. This rule identifies known malicious file hashes, specific defense evasion techniques like disabling VMware drivers and isolating the host network, and the execution of a kernel driver loading utility.
 * tags:
 *     - attack.privilege_escalation
 *     - attack.defense_evasion
 *     - attack.persistence
 *     - attack.t1562.001
 *     - attack.t1547.006
 *     - attack.t1210
 * false_positives:
 *     - The use of 'devcon.exe' or 'netsh.exe' by system administrators for legitimate purposes could cause false positives. Tuning may be required based on parent processes or specific user activity. The execution of 'kdu.exe' is highly suspicious.
 * level: critical
 */
(
    #hash in (
        "37972a232ac6d8c402ac4531430967c1fd458b74a52d6d1990688d88956791a7",
        "4614346fc1ff74f057d189db45aa7dc25d6e7f3d9b68c287a409a53c86dca25e",
        "c3f8da7599468c11782c2332497b9e5013d98a1030034243dfed0cf072469c89",
        "2bc5d02774ac1778be22cace51f9e35fe7b53378f8d70143bf646b68d2c0f94c"
    )
)
OR
(
    src.process.name matches "devcon\\.exe$"
    AND src.process.cmdline contains "disable"
    AND src.process.cmdline contains ("PCI\\VEN_15AD&DEV_0740", "ROOT\\VMWVMCIHOSTDEV")
)
OR
(
    src.process.name matches "kdu\\.exe$"
)
OR
(
    src.process.name matches "netsh\\.exe$"
    AND src.process.cmdline contains "advfirewall"
    AND src.process.cmdline contains "add"
    AND src.process.cmdline contains "rule"
    AND src.process.cmdline contains "action=block"
    AND src.process.cmdline contains "dir=out"
    AND src.process.cmdline contains "remoteip=0.0.0.0-255.255.255.255"
)
OR
(
    event.type in ("File Creation", "File Modification")
    AND tgt.file.path = "/var/run/inetd.conf"
)
```