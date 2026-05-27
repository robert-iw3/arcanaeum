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
FROM * // your index or data-stream with endpoint api logs
| WHERE (
  event.module IN ("sysmon", "endpoint")
  AND event.action IN ("VirtualProtect", "NtProtectVirtualMemory")
  AND file.path LIKE "*\\amsi.dll"
  AND process.memory.protection IN ("PAGE_EXECUTE_READWRITE", "0x40")
)
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.parent.name, process.name, process.pid, file.path, process.memory.protection
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```

### AMSI Bypass via NtSetContextThread
---
```sql
FROM *
| WHERE (
  (event.module = "wineventlog" AND event.code = "4" AND event.provider = "Microsoft-Windows-Kernel-Audit-API-Calls")
  OR (
    event.module IN ("sysmon", "endpoint")
    AND event.action IN ("NtSetContextThread", "SetThreadContext")
  )
)
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.name, process.parent.name, process.pid
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```

### AMSI Bypass via VEH2
---
```sql
FROM *
| WHERE (
  (
    event.module IN ("sysmon", "endpoint")
    AND event.action IN ("AddVectoredExceptionHandler", "DebugBreak")
  )
  OR (
    event.module IN ("sysmon", "endpoint")
    AND file.path LIKE "*\\amsi.dll"
  )
)
| STATS
  count = COUNT(*),
  firstTime = MIN(@timestamp),
  lastTime = MAX(@timestamp),
  veh_registration_count = COUNT_IF(event.action = "AddVectoredExceptionHandler"),
  debug_break_count = COUNT_IF(event.action = "DebugBreak"),
  amsi_load_count = COUNT_IF(file.path LIKE "*\\amsi.dll")
  BY host.name, user.name, process.parent.name, process.name, process.pid
| WHERE veh_registration_count > 1 AND debug_break_count > 0 AND amsi_load_count > 0
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```