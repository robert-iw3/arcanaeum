### Patchless AMSI Bypass Attacks
---

This report details advanced patchless Anti-Malware Scan Interface (AMSI) bypass techniques, specifically focusing on the VEH2 method, which leverages hardware breakpoints and vectored exception handlers to silently evade detection. These techniques represent a significant evolution in adversary tradecraft, moving beyond noisy memory patching to more stealthy execution flow manipulation.

The most significant new finding is the VEH2 technique, which bypasses AMSI without triggering `NtSetContextThread` ETW events, making it much harder to detect compared to previous hardware breakpoint-based AMSI bypasses. This method achieves stealth by manipulating the thread's context directly within a vectored exception handler, avoiding direct calls to `NtSetContextThread` for setting debug registers.

### Actionable Threat Data
---

Monitor for the registration of multiple Vectored Exception Handlers (VEHs) within a process, especially if they handle `EXCEPTION_BREAKPOINT` (0x80000003) and `EXCEPTION_SINGLE_STEP` (0x80000004) in sequence.

Implement detection for processes that call `NtSetContextThread` to modify debug registers (`DR0-DR3`) of other threads or their own, as this is a common precursor to hardware breakpoint-based AMSI bypasses.

Focus on behavioral analysis that identifies suspicious execution flow manipulation, such as unexpected jumps or modifications to the instruction pointer (`RIP`) within exception handling routines, even if direct API calls are not observed.

Analyze `Microsoft-Windows-Kernel-Audit-API-Calls` ETW provider events, specifically Event ID 4 (`KERNEL_AUDIT_API_SETCONTEXTTHREAD`), to identify processes that are calling `NtSetContextThread`, even if the target thread is local.

Be aware that adversaries like PUNK SPIDER (Akira ransomware) and VENOMOUS BEAR (Turla) have been observed attempting AMSI bypasses as a preliminary step before deploying further malicious payloads.

### AMSI Bypass via Memory Patching
---
```sql
`comment("This search detects a common AMSI bypass technique where an adversary patches the AmsiScanBuffer function in memory. This is achieved by changing the memory permissions of amsi.dll to be writable and executable, and then overwriting the function's instructions.")`
`comment("This detection requires an EDR or similar data source that logs API calls related to memory protection changes (e.g., VirtualProtect) and identifies the module associated with the target memory address.")`
sourcetype IN (<edr_sourcetypes_for_api_monitoring>) (api_function="VirtualProtect" OR api_function="NtProtectVirtualMemory") target_module_path="*\\amsi.dll" (new_memory_protection="PAGE_EXECUTE_READWRITE" OR new_memory_protection="0x40")

`comment("Group the results by the affected host and process to create a single alert.")`
| stats count min(_time) as firstTime max(_time) as lastTime by dest, user, parent_process_name, process_name, process_guid, target_module_path, new_memory_protection

`comment("Rename fields for consistency with other detections.")`
| rename dest as host, process_name as process, parent_process_name as parent_process
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

`comment("Potential False Positives: Some legitimate security tools or debuggers may perform this action. Use the filter macro below to exclude known benign processes by name or parent process.")`
| `amsi_bypass_via_memory_patching_filter`
```

### AMSI Bypass via NtSetContextThread
---
```sql
`comment("This detection requires logs from the Microsoft-Windows-Kernel-Audit-API-Calls ETW provider (Event ID 4) or an EDR source that logs NtSetContextThread API calls.")`
(sourcetype="WinEventLog:Microsoft-Windows-Kernel-Audit-API-Calls/Operational" EventCode=4) OR (sourcetype IN (<edr_sourcetypes_for_api_monitoring>) (api_function="NtSetContextThread" OR api_function="SetThreadContext"))

`comment("Group events by host, process, and user to identify the source of the suspicious API call.")`
| stats count min(_time) as firstTime max(_time) as lastTime by dest, user, process_name, parent_process_name, process_guid

`comment("Rename fields for consistency and CIM compliance.")`
| rename dest as host, process_name as process, parent_process_name as parent_process
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

`comment("False Positives: Legitimate applications like debuggers, some games, or security software may use SetThreadContext. Filter out known benign processes using the macro below.")`
| `amsi_bypass_via_ntsetcontextthread_filter`
```

### AMSI Bypass via VEH2
---
```sql
`comment("This search requires EDR data sources that log API calls and module loads.")`
(sourcetype IN (<edr_sourcetypes_for_api_monitoring>) (api_function="AddVectoredExceptionHandler" OR api_function="DebugBreak")) OR (sourcetype IN (<edr_sourcetypes_for_dll_loads>) module_path="*\\amsi.dll")

`comment("Aggregate events by process to identify suspicious combinations of activity.")`
| stats min(_time) as firstTime max(_time) as lastTime count(eval(api_function="AddVectoredExceptionHandler")) as veh_registration_count count(eval(api_function="DebugBreak")) as debug_break_count count(eval(like(module_path, "%amsi.dll"))) as amsi_load_count by dest, user, parent_process_name, process_name, process_guid

`comment("The core of the VEH2 technique involves registering multiple VEHs, triggering a debug break, and targeting AMSI.")`
| where veh_registration_count > 1 AND debug_break_count > 0 AND amsi_load_count > 0

`comment("Rename fields for consistency and CIM compliance.")`
| rename dest as host, process_name as process, parent_process_name as parent_process
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

`comment("Potential False Positives: This behavior may be seen in debuggers or security research tools. Filter known benign processes using the macro below.")`
| `amsi_bypass_via_veh2_filter`
```