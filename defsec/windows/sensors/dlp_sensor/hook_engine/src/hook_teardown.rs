/*=============================================================================================
 * SYSTEM:          Data Sensor - Observation & DLP
 * COMPONENT:       hook_teardown.rs (Ring-3 Hook DLL — Teardown & Re-entrancy Module)
 * DESCRIPTION:
 * 1. SENTINEL WATCHER   — A dedicated 64KB background thread monitors for the Teardown.sig
 * file at 250ms intervals. Upon detection, it invokes
 * FreeLibraryAndExitThread to facilitate a safe, self-directed
 * module ejection. Utilizing a file-based signal ensures reliable
 * communication across all session boundaries and privilege levels.
 *
 * 2. RE-ENTRANCY GUARD  — A thread-local depth counter prevents recursive hook invocation.
 * Because lower-level OS components (such as NTFS filter drivers or
 * the TCP/IP stack) may trigger WriteFile() during their own I/O
 * completions, this guard is strictly required to prevent infinite
 * recursion and subsequent stack exhaustion.
 *
 * 3. TEARDOWN GATE      — The is_teardown_requested() validation serves as the mandatory
 * initial check within every intercepted callback. When asserted,
 * the hook immediately delegates execution to the original API,
 * ensuring all in-flight I/O operations resolve safely before the
 * sentinel thread unmaps the library from memory.
 *
 * 4. HOOKS-DETACHED HANDSHAKE — After all in-flight threads have drained, the sentinel
 * opens the named event "Global\DataSensorHooksDetached" (pre-created
 * by the C# orchestrator) and signals it. This replaces the
 * non-deterministic Thread.Sleep(1500) in ForceEjectHooks() with a
 * true rendezvous, preventing the orchestrator from calling
 * teardown_engine() while Rust hooks are still executing.
 *
 * @RW
 *============================================================================================*/

use std::cell::Cell;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::LibraryLoader::FreeLibraryAndExitThread;

// ── FILE-SENTINEL CONFIGURATION ─────────────────────────────────────────────

const TEARDOWN_SIG_PATH: &str = r"C:\ProgramData\DataSensor\Teardown.sig";
const POLL_INTERVAL_MS: u64 = 250;
const HOOKS_DETACHED_EVENT: &str = "Global\\DataSensorHooksDetached\0";

// ── GLOBAL STATE ─────────────────────────────────────────────────────────────

static TEARDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static MODULE_HANDLE: OnceLock<usize> = OnceLock::new();
static IN_FLIGHT_THREADS: AtomicUsize = AtomicUsize::new(0);

// ── THREAD-LOCAL RE-ENTRANCY COUNTER ─────────────────────────────────────────

thread_local! {
    static HOOK_DEPTH: Cell<u32> = const { Cell::new(0) };
}

// ── PUBLIC API ────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub fn on_attach(h_module: usize) {
    let _ = MODULE_HANDLE.set(h_module);
    start_sentinel_watcher();
    log_diag("INFO", "Teardown sentinel watcher started (File-Sentinel mode).");
}

pub fn on_detach() {
    TEARDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

#[inline(always)]
pub fn is_teardown_requested() -> bool {
    TEARDOWN_REQUESTED.load(Ordering::Relaxed)
}

#[inline(always)]
pub fn enter_hook() -> bool {
    let is_reentrant = HOOK_DEPTH.with(|depth| {
        if depth.get() > 0 {
            true
        } else {
            depth.set(1);
            false
        }
    });

    if is_reentrant {
        return false;
    }

    IN_FLIGHT_THREADS.fetch_add(1, Ordering::SeqCst);

    if TEARDOWN_REQUESTED.load(Ordering::SeqCst) {
        IN_FLIGHT_THREADS.fetch_sub(1, Ordering::SeqCst);
        HOOK_DEPTH.with(|depth| depth.set(0));
        return false;
    }

    true
}

#[inline(always)]
pub fn exit_hook() {
    IN_FLIGHT_THREADS.fetch_sub(1, Ordering::SeqCst);
    HOOK_DEPTH.with(|depth| depth.set(0));
}

pub struct HookGuard;

impl HookGuard {
    #[inline(always)]
    pub fn acquire() -> Option<Self> {
        if enter_hook() { Some(HookGuard) } else { None }
    }
}

impl Drop for HookGuard {
    #[inline(always)]
    fn drop(&mut self) {
        exit_hook();
    }
}

// ── INTERNAL — SENTINEL WATCHER ───────────────────────────────────────────────

fn start_sentinel_watcher() {
    let result = thread::Builder::new()
        .name("DS-Sentinel".to_string())
        .stack_size(64 * 1024)
        .spawn(sentinel_loop);

    if let Err(e) = result {
        log_diag("ERROR", &format!("Sentinel thread spawn failed: {}. Manual teardown only.", e));
    }
}

fn sentinel_loop() {
    HOOK_DEPTH.with(|depth| depth.set(1));
    loop {
        thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
        if Path::new(TEARDOWN_SIG_PATH).exists() {
            TEARDOWN_REQUESTED.store(true, Ordering::SeqCst);
            log_diag("WARN", "Teardown signal detected. Closing entrance gate.");
            crate::remove_hooks();

            // Drain all in-flight hook callbacks before signalling the orchestrator.
            let mut wait_cycles = 0;
            loop {
                let active = IN_FLIGHT_THREADS.load(Ordering::SeqCst);
                if active == 0 {
                    log_diag("INFO", "In-flight threads reached 0. Safe to eject.");
                    break;
                }
                wait_cycles += 1;
                if wait_cycles % 10 == 0 {
                    log_diag("WARN", &format!("Ejection paused. {} threads still in-flight.", active));
                }
                thread::sleep(Duration::from_millis(50));
            }

            signal_hooks_detached();

            eject_self();
            return;
        }
    }
}

// ── HOOKS-DETACHED SIGNAL ────────────────────────────────────────────────────

fn signal_hooks_detached() {
    #[cfg(target_os = "windows")]
    unsafe {
        use windows_sys::Win32::System::Threading::OpenEventW;
        use windows_sys::Win32::System::Threading::SetEvent;
        use windows_sys::Win32::Foundation::CloseHandle;

        const EVENT_MODIFY_STATE: u32 = 0x0002;

        let name_utf16: Vec<u16> = HOOKS_DETACHED_EVENT.encode_utf16().collect();
        let h_event = OpenEventW(EVENT_MODIFY_STATE, 0, name_utf16.as_ptr());
        if h_event != 0 {
            SetEvent(h_event);
            CloseHandle(h_event);
            log_diag("INFO", "HooksDetached event signalled to C# orchestrator.");
        } else {
            // Orchestrator may have already timed-out and disposed the handle — non-fatal.
            log_diag("WARN", "HooksDetached event not found (orchestrator may have timed out). Proceeding with ejection.");
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        log_diag("INFO", "[STUB] signal_hooks_detached() — non-Windows build.");
    }
}

// ── SELF-EJECTION ─────────────────────────────────────────────────────────────

fn eject_self() {
    #[cfg(target_os = "windows")]
    {
        if let Some(&h_module_usize) = MODULE_HANDLE.get() {
            unsafe {
                FreeLibraryAndExitThread(h_module_usize as isize, 0);
            }
        } else {
            log_diag("ERROR", "MODULE_HANDLE not set. DLL will be inert but not ejected.");
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        log_diag("INFO", "[STUB] eject_self() — non-Windows build.");
    }
}

// ── DIAGNOSTIC HELPER ─────────────────────────────────────────────────────────

fn log_diag(level: &str, message: &str) {
    crate::send_diag_log(level, message);
}