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
event_simpleName=RegSetValue (TargetObject="HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\KernelShadowStacks\\Enabled" OR TargetObject="HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnstruent"
| select earliest(event_timestamp) as firstTime, latest(event_timestamp) as lastTime, ComputerName as dest, UserName as user, ProcessName as process_name, TargetObject as registry_path, NewValue as registry_value_data, count(*) as count
| group by ComputerName, UserName, ProcessName, TargetObject, NewValue
```

### MSR Register Write
---
```sql
event_simpleName=SystemCrash EventCode=1001 BugcheckCode="0x0000003b" Parameter1="0x00000000c0000096"
| select earliest(event_timestamp) as firstTime, latest(event_timestamp) as lastTime, ComputerName as Endpoint, BugcheckCode as Bugcheck_Code, Parameter1 as Exception_Code, Message, count(*) as count
| group by ComputerName, BugcheckCode, Parameter1, Message
```

### #CP Faults and Bugchecks
---
```sql
event_simpleName=SystemCrash EventCode=1001 BugcheckCode="0x00000139" Parameter1="0x0000000000000039"
| select earliest(event_timestamp) as firstTime, latest(event_timestamp) as lastTime, ComputerName as Endpoint, BugcheckCode as Bugcheck_Code, Parameter1 as Violation_Code, Message, count(*) as count
| group by ComputerName, BugcheckCode, Parameter1, Message
```

### ETW Log for Shadow Stack Mismatch
---
```sql
event_simpleName=ETWEvent EventCode=5 ProviderName="Microsoft-Windows-Threat-Intelligence"
| select earliest(event_timestamp) as firstTime, latest(event_timestamp) as lastTime, ComputerName as Endpoint, UserName as user, list(ProcessName) as ProcessName, list(ReturnAddress) as ReturnAddress, list(TargetAddress) as TargetAddress, count(*) as count
| group by ComputerName, UserName
```

### Incompatible Driver Loading
---
```sql
event_simpleName=DriverLoad EventCode=6
| eval loaded_driver_name=split(ImageLoaded, "\\")[-1]
| lookup kernel_incompatible_driver_blocklist.csv driver_filename=loaded_driver_name output description as reason
| where reason IS NOT NULL
| select earliest(event_timestamp) as firstTime, latest(event_timestamp) as lastTime, ComputerName as Endpoint, loaded_driver_name as IncompatibleDriver, reason as Reason, list(ImageLoaded) as FullPath, list(Hashes) as Hashes, count(*) as count
| group by ComputerName, loaded_driver_name, reason
```