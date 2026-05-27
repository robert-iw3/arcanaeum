### Windows Kernel Shadow Stack Mitigation Analysis
---

This report analyzes the Windows kernel shadow stack mitigation, a hardware-based security feature designed to prevent control-flow hijacking attacks like Return-Oriented Programming (ROP). It details the implementation of this mitigation within the Windows kernel and explores potential bypass techniques.

Recent research indicates that while kernel shadow stack mitigation is effective against traditional ROP attacks, advanced techniques like Counterfeit Object-Oriented Programming (COOP) can still bypass Intel CET by chaining existing valid functions, even without directly corrupting return addresses.

### Actionable Threat Data
---

Registry Modification for Kernel Shadow Stack: Monitor for modifications to the registry keys associated with enabling or disabling kernel shadow stack protection, specifically `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks` and `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`.

MSR Register Writes (IA32_S_CET): Detect attempts to write to Model Specific Registers (MSRs), particularly `IA32_S_CET (0x6a2)`, which configures Supervisor Mode CET. Unauthorized modifications could indicate an attempt to disable or alter shadow stack behavior.

#CP Faults and Bugchecks: Look for instances of #CP (Control Protection) faults, which indicate a mismatch between the normal stack and the shadow stack. While legitimate software can trigger these, repeated or unusual occurrences, especially followed by system bugchecks (e.g., `KERNEL_SECURITY_CHECK_FAILURE` with argument `0x39`), could signal an attempted control-flow hijack.

vmcall Instruction Usage: Monitor for the use of the vmcall instruction with `rcx = 0x11` or `rcx = 0xc`, as these are used by the regular kernel to request secure kernel operations related to shadow stack allocation and protection.

ETW Log Generation for Audit Mode: In audit mode, an Event Tracing for Windows (ETW) log is generated when a shadow stack mismatch occurs. Monitor ETW logs for events related to `KiFixupControlProtectionKernelModeReturnMismatch` or similar control protection events.

Driver Incompatibilities with Kernel-mode Hardware-enforced Stack Protection: Be aware of and monitor for drivers that are incompatible with Kernel-mode Hardware-enforced Stack Protection, as these might be added to a vulnerable driver blocklist or cause system instability.

### Registry Key Modification
---
```sql
FROM *
| WHERE event.action="registry_value_set" AND (win.registry.path="HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\KernelShadowStacks\\Enabled" OR win.registry.path="HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\\Enabled")
| STATS count=COUNT(*), firstTime=MIN(@timestamp), lastTime=MAX(@timestamp) BY host.name AS dest, user.name AS user, process.name AS process_name, win.registry.path AS registry_path, win.registry.data AS registry_value_data
| KEEP firstTime, lastTime, dest, user, process_name, registry_path, registry_value_data, count
```

### MSR Register Write
---
```sql
FROM *
| WHERE event.code="1001" AND event.kind="event" AND event.provider="Microsoft-Windows-WER-SystemErrorReporting" AND winlog.event_data.BugcheckCode="0x0000003b" AND winlog.event_data.BugcheckParameter1="0x00000000c0000096"
| STATS count=COUNT(*), firstTime=MIN(@timestamp), lastTime=MAX(@timestamp) BY host.name AS Endpoint, winlog.event_data.BugcheckCode AS Bugcheck_Code, winlog.event_data.BugcheckParameter1 AS Exception_Code, message
| KEEP firstTime, lastTime, Endpoint, Bugcheck_Code, Exception_Code, message, count
```

### #CP Faults and Bugchecks
---
```sql
FROM *
| WHERE event.code="1001" AND event.kind="event" AND event.provider="Microsoft-Windows-WER-SystemErrorReporting" AND winlog.event_data.BugcheckCode="0x00000139" AND winlog.event_data.BugcheckParameter1="0x0000000000000039"
| STATS count=COUNT(*), firstTime=MIN(@timestamp), lastTime=MAX(@timestamp) BY host.name AS Endpoint, winlog.event_data.BugcheckCode AS Bugcheck_Code, winlog.event_data.BugcheckParameter1 AS Violation_Code, message
| KEEP firstTime, lastTime, Endpoint, Bugcheck_Code, Violation_Code, message, count
```

### ETW Log for Shadow Stack Mismatch
---
```sql
FROM *
| WHERE event.code="5" AND event.kind="event" AND event.provider="Microsoft-Windows-Threat-Intelligence" AND winlog.channel="Microsoft-Windows-Threat-Intelligence/Operational"
| STATS count=COUNT(*), firstTime=MIN(@timestamp), lastTime=MAX(@timestamp), ProcessName=COLLECT(process.name), ReturnAddress=COLLECT(winlog.event_data.ReturnAddress), TargetAddress=COLLECT(winlog.event_data.TargetAddress) BY host.name AS Endpoint, user.name AS user
| KEEP firstTime, lastTime, Endpoint, user, ProcessName, ReturnAddress, TargetAddress, count
```

### Incompatible Driver Loading
---
```sql
FROM *
| WHERE event.code="6" AND event.kind="event" AND event.module="sysmon"
| EVAL loaded_driver_name=GETPATH(file.path, -1)
| LOOKUP kernel_incompatible_driver_blocklist.csv ON loaded_driver_name=driver_filename OUTPUT description AS reason
| WHERE reason IS NOT NULL
| STATS count=COUNT(*), firstTime=MIN(@timestamp), lastTime=MAX(@timestamp), FullPath=COLLECT(file.path), Hashes=COLLECT(file.hash.sha256) BY host.name AS Endpoint, loaded_driver_name AS IncompatibleDriver, reason AS Reason
| KEEP firstTime, lastTime, Endpoint, IncompatibleDriver, Reason, FullPath, Hashes, count
```