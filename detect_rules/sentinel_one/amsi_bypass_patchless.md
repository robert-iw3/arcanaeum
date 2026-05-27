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
AgentName IS NOT EMPTY
AND (
  EventType IN ("VirtualProtect", "NtProtectVirtualMemory")
  AND TargetModulePath LIKE "*\\amsi.dll"
  AND NewMemoryProtection IN ("PAGE_EXECUTE_READWRITE", "0x40")
)
| SELECT AgentName, User, ParentProcessName, ProcessName, PID, TargetModulePath, NewMemoryProtection, COUNT(*) AS count, MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime
| GROUP BY AgentName, User, ParentProcessName, ProcessName, PID, TargetModulePath, NewMemoryProtection
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```

### AMSI Bypass via NtSetContextThread
---
```sql
AgentName IS NOT EMPTY
AND (
  (EventSource = "Microsoft-Windows-Kernel-Audit-API-Calls" AND EventId = 4)
  OR (
    EventType IN ("NtSetContextThread", "SetThreadContext")
  )
)
| SELECT AgentName, User, ProcessName, ParentProcessName, PID, COUNT(*) AS count, MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime
| GROUP BY AgentName, User, ProcessName, ParentProcessName, PID
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```

### AMSI Bypass via VEH2
---
```sql
AgentName IS NOT EMPTY
AND (
  (
    EventType IN ("AddVectoredExceptionHandler", "DebugBreak")
  )
  OR (
    ModulePath LIKE "*\\amsi.dll"
  )
)
| SELECT
  AgentName,
  User,
  ParentProcessName,
  ProcessName,
  PID,
  COUNT(*) AS count,
  MIN(EventTime) AS firstTime,
  MAX(EventTime) AS lastTime,
  COUNT_IF(EventType = "AddVectoredExceptionHandler") AS veh_registration_count,
  COUNT_IF(EventType = "DebugBreak") AS debug_break_count,
  COUNT_IF(ModulePath LIKE "*\\amsi.dll") AS amsi_load_count
| GROUP BY AgentName, User, ParentProcessName, ProcessName, PID
| WHERE veh_registration_count > 1 AND debug_break_count > 0 AND amsi_load_count > 0
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```