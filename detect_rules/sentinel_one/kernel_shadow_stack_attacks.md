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
EventType="RegistryValueSet" AND (RegistryKeyPath="HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\KernelShadowStacks\\Enabled" OR RegistryKeyPath="HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\\Enabled")
| SELECT MIN(Timestamp) AS firstTime, MAX(Timestamp) AS lastTime, AgentName AS dest, User AS user, ProcessName AS process_name, RegistryKeyPath AS registry_path, RegistryValueData AS registry_value_data, COUNT(*) AS count
| GROUP BY AgentName, User, ProcessName, RegistryKeyPath, RegistryValueData
```

### MSR Register Write
---
```sql
EventType="SystemCrash" AND EventCode="1001" AND BugcheckCode="0x0000003b" AND BugcheckParameter1="0x00000000c0000096"
| SELECT MIN(Timestamp) AS firstTime, MAX(Timestamp) AS lastTime, AgentName AS Endpoint, BugcheckCode AS Bugcheck_Code, BugcheckParameter1 AS Exception_Code, Message, COUNT(*) AS count
| GROUP BY AgentName, BugcheckCode, BugcheckParameter1, Message
```

### #CP Faults and Bugchecks
---
```sql
EventType="SystemCrash" AND EventCode="1001" AND BugcheckCode="0x00000139" AND BugcheckParameter1="0x0000000000000039"
| SELECT MIN(Timestamp) AS firstTime, MAX(Timestamp) AS lastTime, AgentName AS Endpoint, BugcheckCode AS Bugcheck_Code, BugcheckParameter1 AS Violation_Code, Message, COUNT(*) AS count
| GROUP BY AgentName, BugcheckCode, BugcheckParameter1, Message
```

### ETW Log for Shadow Stack Mismatch
---
```sql
EventType="ETWEvent" AND EventCode="5" AND ProviderName="Microsoft-Windows-Threat-Intelligence"
| SELECT MIN(Timestamp) AS firstTime, MAX(Timestamp) AS lastTime, AgentName AS Endpoint, User AS user, LIST(ProcessName) AS ProcessName, LIST(ReturnAddress) AS ReturnAddress, LIST(TargetAddress) AS TargetAddress, COUNT(*) AS count
| GROUP BY AgentName, User
```

### Incompatible Driver Loading
---
```sql
EventType="DriverLoad" AND EventCode="6"
| SELECT loaded_driver_name=LAST(SPLIT(ImageLoaded, "\\")), MIN(Timestamp) AS firstTime, MAX(Timestamp) AS lastTime, AgentName AS Endpoint, loaded_driver_name AS IncompatibleDriver, reason AS Reason, LIST(ImageLoaded) AS FullPath, LIST(Hashes) AS Hashes, COUNT(*) AS count
| LOOKUP kernel_incompatible_driver_blocklist.csv driver_filename=loaded_driver_name OUTPUT description AS reason
| WHERE reason IS NOT NULL
| GROUP BY AgentName, loaded_driver_name, reason
```