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
`comment("This detection rule identifies modifications to registry keys that control Windows Kernel-mode Hardware-enforced Stack Protection (Kernel Shadow Stack). An attacker may modify these keys to disable this security feature, bypassing a critical defense against return-oriented programming (ROP) attacks. This rule requires endpoint data with registry activity, such as from the Splunk CIM Endpoint.Registry data model, typically populated by Sysmon (EventID 13) or other EDR solutions.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_path="*\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\KernelShadowStacks\\Enabled" OR Registry.registry_path="*\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\\Enabled") by Registry.dest, Registry.user, Registry.process_name, Registry.registry_path, Registry.registry_value_data
`comment("The tstats command efficiently searches for modifications to the specific registry paths associated with Kernel Shadow Stack.")`
| rename "Registry.*" as "*"
`comment("Renaming fields for better readability.")`
| convert ctime(firstTime) ctime(lastTime)
`comment("Converting timestamps to a human-readable format.")`
| table firstTime, lastTime, dest, user, process_name, registry_path, registry_value_data, count
`comment("Known False Positives: Legitimate system configuration changes by administrators or automated tools (e.g., SCCM, GPO) may trigger this alert. Tuning may be required to filter out known benign processes or administrative activity.")`
```

### MSR Register Write
---
```sql
`comment("This detection rule identifies a specific system crash (bugcheck) that can be indicative of an attempt to write to a protected Model-Specific Register (MSR), such as IA32_S_CET (0x6a2). This action is often performed by malicious kernel drivers to disable security features like Kernel Shadow Stack. This detection requires Windows System Event Logs.")`
`wineventlog_system` EventCode=1001
`comment("Filter for bugcheck events (EventCode 1001) from the System event log.")`
| rex field=Message "The bugcheck was: (?<bugcheck_code>0x[0-9a-fA-F]+)\s+\((?<param1>0x[0-9a-fA-F]+)"
`comment("Extract the bugcheck code and the first parameter from the event message.")`
| where bugcheck_code = "0x0000003b" AND param1 = "0x00000000c0000096"
`comment("Filter for SYSTEM_SERVICE_EXCEPTION (0x3b) where the exception code is STATUS_PRIVILEGED_INSTRUCTION (0xc0000096). This specific combination is triggered when Hyper-V blocks a wrmsr instruction to a protected MSR.")`
| stats count min(_time) as firstTime max(_time) as lastTime by dest, bugcheck_code, param1, Message
`comment("Aggregate results for reporting.")`
| convert ctime(firstTime) ctime(lastTime)
| rename dest as "Endpoint", bugcheck_code as "Bugcheck_Code", param1 as "Exception_Code"
`comment("FP Tuning: While this is a high-fidelity indicator for this attack, a legitimate but faulty driver could theoretically cause a similar crash. Analysis of the associated crash dump is recommended for confirmation.")`
```

### #CP Faults and Bugchecks
---
```sql
`comment("This detection rule identifies a KERNEL_SECURITY_CHECK_FAILURE (0x139) bugcheck with a first argument of 0x39. This specific combination indicates a shadow stack violation, where a mismatch between the regular stack and the hardware-enforced shadow stack was detected. This is a strong indicator of a control-flow hijack attempt, such as Return-Oriented Programming (ROP), being blocked by the Kernel Shadow Stack mitigation. This detection requires Windows System Event Logs.")`
`wineventlog_system` EventCode=1001
`comment("Filter for bugcheck events (EventCode 1001).")`
| rex field=Message "The bugcheck was: (?<bugcheck_code>0x[0-9a-fA-F]+)\s+\((?<param1>0x[0-9a-fA-F]+)"
`comment("Extract the bugcheck code and the first parameter from the event message.")`
| where bugcheck_code = "0x00000139" AND param1 = "0x0000000000000039"
`comment("Filter for KERNEL_SECURITY_CHECK_FAILURE (0x139) where the first argument is a shadow stack violation (0x39).")`
| stats count min(_time) as firstTime max(_time) as lastTime by dest, bugcheck_code, param1, Message
`comment("Aggregate results for reporting.")`
| convert ctime(firstTime) ctime(lastTime)
| rename dest as "Endpoint", bugcheck_code as "Bugcheck_Code", param1 as "Violation_Code"
`comment("FP Tuning: While this is a high-fidelity indicator, a legitimate but faulty driver could theoretically cause this specific crash. Analysis of the associated crash dump is recommended for confirmation.")`
```

### ETW Log for Shadow Stack Mismatch
---
```sql
`comment("This detection rule identifies Control-flow Enforcement Technology (CET) Shadow Stack violation events logged via ETW. This event is generated when Kernel-mode Hardware-enforced Stack Protection is in audit mode and a return address mismatch occurs. This is a strong indicator of a potential control-flow hijack attempt, such as Return-Oriented Programming (ROP), being audited instead of blocked, which aligns with the behavior of nt!KiFixupControlProtectionKernelModeReturnMismatch. This detection requires the Microsoft-Windows-Threat-Intelligence/Operational ETW log channel.")`
sourcetype="WinEventLog:Microsoft-Windows-Threat-Intelligence/Operational" EventCode=5
`comment("Filter for CET Shadow Stack violation events (EventCode 5) from the Threat-Intelligence ETW provider.")`
| stats count min(_time) as firstTime max(_time) as lastTime values(ProcessName) as ProcessName values(ReturnAddress) as ReturnAddress values(TargetAddress) as TargetAddress by dest, user
`comment("Aggregate events by host and user, listing the involved processes and mismatched addresses.")`
| convert ctime(firstTime) ctime(lastTime)
| rename dest as Endpoint
`comment("FP Tuning: Legitimate but buggy applications or drivers could potentially cause these violations. Investigate the triggering process to determine if it is malicious or benign. This is generally a high-fidelity indicator of anomalous behavior that warrants investigation.")`
```

### Incompatible Driver Loading
---
```sql
`comment("This detection rule identifies the loading of drivers known to be incompatible with Kernel-mode Hardware-enforced Stack Protection. Attackers may intentionally load vulnerable or incompatible drivers to create system instability or bypass this security feature. This rule requires Sysmon logs (EventCode 6) and a maintained lookup file of incompatible drivers.")`
`sysmon` EventCode=6
`comment("Filter for Sysmon driver load events (EventCode 6).")`
| eval loaded_driver_name = mvindex(split(ImageLoaded, "\\"), -1)
`comment("Extract the driver filename from the full path.")`
| lookup kernel_incompatible_driver_blocklist.csv driver_filename AS loaded_driver_name OUTPUT description AS reason
`comment("Use a lookup to check if the loaded driver is on the known incompatible list. The lookup file 'kernel_incompatible_driver_blocklist.csv' should contain at least 'driver_filename' and 'description' fields. This list is maintained by Microsoft for Windows Defender Application Control.")`
| where isnotnull(reason)
`comment("Filter for events where the loaded driver was found in the blocklist lookup.")`
| stats count min(_time) as firstTime max(_time) as lastTime values(ImageLoaded) as full_path values(Hashes) as hashes by dest, loaded_driver_name, reason
`comment("Aggregate alerts by host and driver, providing details for investigation.")`
| convert ctime(firstTime) ctime(lastTime)
| rename dest as Endpoint, loaded_driver_name as IncompatibleDriver, reason as Reason, full_path as FullPath, hashes as Hashes
`comment("FP Tuning: The blocklist lookup must be kept up-to-date with Microsoft's latest recommendations. Legitimate administrative actions involving legacy hardware may also trigger this alert. Consider adding known-good drivers or specific administrative hosts to an exclusion list if necessary.")`
```