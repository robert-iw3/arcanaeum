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
`comment("This detection rule identifies multiple stages of the ESXi VM Escape toolkit attack chain. It combines high-fidelity indicators like file hashes with specific behavioral patterns, such as disabling VMware devices and isolating the host network.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process_name) as process_name, values(Processes.process) as process, values(Processes.parent_process_name) as parent_process, values(Filesystem.file_path) as file_path, values(Filesystem.file_name) as file_name, values(Filesystem.file_hash) as file_hash, values(Filesystem.action) as file_action from datamodel=Endpoint
where (
    -- Layer 1: Known malicious file hashes from the ESXi exploit toolkit. This is a high-fidelity indicator.
    (nodename=Endpoint.Filesystem AND Filesystem.file_hash IN ("37972a232ac6d8c402ac4531430967c1fd458b74a52d6d1990688d88956791a7", "4614346fc1ff74f057d189db45aa7dc25d6e7f3d9b68c287a409a53c86dca25e", "c3f8da7599468c11782c2332497b9e5013d98a1030034243dfed0cf072469c89", "2bc5d02774ac1778be22cace51f9e35fe7b53378f8d70143bf646b68d2c0f94c"))
    OR
    -- Layer 2: Disabling of VMware VMCI devices via devcon.exe, a key preparatory step for the exploit.
    (nodename=Endpoint.Processes AND Processes.process_name=devcon.exe AND (Processes.process="*disable*PCI\\VEN_15AD&DEV_0740*" OR Processes.process="*disable*ROOT\\VMWVMCIHOSTDEV*"))
    OR
    -- Layer 3: Execution of the Kernel Driver Utility (KDU), a known BYOVD tool used to load the malicious driver.
    (nodename=Endpoint.Processes AND Processes.process_name=kdu.exe)
    OR
    -- Layer 4: Host network isolation using netsh to block all outbound traffic.
    (nodename=Endpoint.Processes AND Processes.process_name=netsh.exe AND Processes.process="*advfirewall*add*rule*action=block*dir=out*remoteip=0.0.0.0-255.255.255.255*")
    OR
    -- Layer 5: Modification of the ESXi inetd.conf file to hijack a network service for the backdoor.
    (nodename=Endpoint.Filesystem AND Filesystem.file_path="/var/run/inetd.conf" AND (Filesystem.action=created OR Filesystem.action=modified))
)
by All_Host.dest, All_Host.user
`drop_dm_object_name("All_Host")`
`drop_dm_object_name("Processes")`
`drop_dm_object_name("Filesystem")`
| `ctime(firstTime)`
| `ctime(lastTime)`
-- Create a field to explain which part of the logic triggered the alert.
| eval detection_reason = case(
    mvfilter(match(file_hash, "37972a232ac6d8c402ac4531430967c1fd458b74a52d6d1990688d88956791a7|4614346fc1ff74f057d189db45aa7dc25d6e7f3d9b68c287a409a53c86dca25e|c3f8da7599468c11782c2332497b9e5013d98a1030034243dfed0cf072469c89|2bc5d02774ac1778be22cace51f9e35fe7b53378f8d70143bf646b68d2c0f94c")), "Known ESXi Exploit Toolkit file hash detected.",
    mvfilter(process_name=="devcon.exe" AND (like(process, "%disable%PCI\\VEN_15AD&DEV_0740%") OR like(process, "%disable%ROOT\\VMWVMCIHOSTDEV%"))), "VMware VMCI device disabled via devcon.exe.",
    mvfilter(process_name=="kdu.exe"), "Kernel Driver Utility (KDU) execution detected.",
    mvfilter(process_name=="netsh.exe" AND like(process, "%action=block%remoteip=0.0.0.0-255.255.255.255%")), "Host network isolation via netsh detected.",
    mvfilter(like(file_path, "/var/run/inetd.conf")), "ESXi inetd.conf file modified.",
    1=1, "Unknown trigger"
)
-- False Positive Tuning: The use of 'devcon.exe' or 'netsh.exe' might be legitimate in some admin scripts.
-- To reduce noise, consider adding parent process or user filtering, for example: `... AND parent_process!="legit_script.exe"`.
-- The execution of 'kdu.exe' is highly suspicious and unlikely to be a false positive.
| table firstTime, lastTime, dest, user, detection_reason, process_name, process, parent_process, file_name, file_path, file_hash, file_action, count
```