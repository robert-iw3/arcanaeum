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
source IN (<edr_sourcetypes_for_api_monitoring>) --  <-------- replace with correct source type!
| where (api_function="VirtualProtect" OR api_function="NtProtectVirtualMemory") AND target_module_path=".*\\\\amsi\.dll" AND (new_memory_protection="PAGE_EXECUTE_READWRITE" OR new_memory_protection="0x40")
| stats count min(timestamp)=firstTime max(timestamp)=lastTime by dest, user, parent_process_name, process_name, process_guid, target_module_path, new_memory_protection
| rename dest=host, process_name=process, parent_process_name=parent_process
| fields firstTime, lastTime, host, user, parent_process, process, process_guid, target_module_path, new_memory_protection, count
```

### AMSI Bypass via NtSetContextThread
---
```sql
source IN ("WinEventLog:Microsoft-Windows-Kernel-Audit-API-Calls/Operational", <edr_sourcetypes_for_api_monitoring>) --  <-------- replace with correct source type!
| where (EventID=4 OR api_function IN ("NtSetContextThread", "SetThreadContext"))
| stats count min(timestamp)=firstTime max(timestamp)=lastTime by dest, user, process_name, parent_process_name, process_guid
| rename dest=host, process_name=process, parent_process_name=parent_process
| fields firstTime, lastTime, host, user, parent_process, process, process_guid, count
```

### AMSI Bypass via VEH2
---
```sql
source IN (<edr_sourcetypes_for_api_monitoring>, <edr_sourcetypes_for_dll_loads>) --  <-------- replace with correct source
| where api_function IN ("AddVectoredExceptionHandler", "DebugBreak") OR module_path=".*\\\\amsi\.dll"
| stats min(timestamp)=firstTime max(timestamp)=lastTime count(eval(api_function="AddVectoredExceptionHandler"))=veh_registration_count count(eval(api_function="DebugBreak"))=debug_break_count count(eval(module_path=~".*\\\\amsi\.dll"))=amsi_load_count by dest, user, parent_process_name, process_name, process_guid
| where veh_registration_count > 1 AND debug_break_count > 0 AND amsi_load_count > 0
| rename dest=host, process_name=process, parent_process_name=parent_process
| fields firstTime, lastTime, host, user, parent_process, process, process_guid, veh_registration_count, debug_break_count, amsi_load_count
```