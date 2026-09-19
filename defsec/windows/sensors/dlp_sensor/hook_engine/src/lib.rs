/*=============================================================================================
 * SYSTEM:          Data Sensor - Ring-3 Interceptor
 * COMPONENT:       lib.rs (In-Band API Hook)
 * DESCRIPTION:     Hooks WriteFile, computes SHA256 hashes for validation, inspects buffers,
 * and communicates with the C# Orchestrator via Named Pipes.
 * Integrates safe file-sentinel teardown and re-entrancy protections.
 * @RW
 *============================================================================================*/

use serde::Serialize;
use sha2::{Sha256, Digest};
use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use lazy_static::lazy_static;

#[path = "hook_teardown.rs"]
mod teardown;

type WriteFileFn = unsafe extern "system" fn(
    *mut c_void,   // HANDLE hFile
    *const c_void, // LPCVOID lpBuffer
    u32,           // DWORD nNumberOfBytesToWrite
    *mut u32,      // LPDWORD lpNumberOfBytesWritten
    *mut c_void,   // LPOVERLAPPED lpOverlapped
) -> i32;          // BOOL

static ORIGINAL_WRITEFILE: std::sync::OnceLock<WriteFileFn> = std::sync::OnceLock::new();

static ALERT_SENDER: OnceLock<std::sync::mpsc::SyncSender<String>> = OnceLock::new();

#[repr(C)]
struct IoStatusBlock {
    status: i32,
    information: usize,
}

type NtWriteFileFn = unsafe extern "system" fn(
    *mut std::ffi::c_void,
    *mut std::ffi::c_void,
    *mut std::ffi::c_void,
    *mut std::ffi::c_void,
    *mut IoStatusBlock,
    *const std::ffi::c_void,
    u32,
    *mut i64,
    *mut u32,
) -> i32;

static ORIGINAL_NTWRITEFILE: std::sync::OnceLock<NtWriteFileFn> = std::sync::OnceLock::new();

#[repr(C)]
struct FileNameInfo {
    file_name_length: u32,
    file_name: [u16; 512],
}

type NtQueryInfoFileFn = unsafe extern "system" fn(
    isize,                  // FileHandle
    *mut IoStatusBlock,     // IoStatusBlock
    *mut c_void,            // FileInformation
    u32,                    // Length
    u32,                    // FileInformationClass
) -> i32;                   // NTSTATUS (0 = success)

const FILE_NAME_INFORMATION_CLASS: u32 = 9;

static NT_QUERY_INFO_FILE: OnceLock<NtQueryInfoFileFn> = OnceLock::new();

static HINST_DLL: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

static HOST_PROCESS: OnceLock<String> = OnceLock::new();

#[derive(Serialize)]
struct DlpAlert {
    alert_type: String,
    action: String,
    process: String,
    destination: String,
    details: String,
    filepath: String,
    file_hash: String,
    confidence: i32,
    mitre_tactic: String,
}

static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();

fn ensure_initialized(hinst_dll: *mut c_void) {
    INIT.get_or_init(|| {
        #[cfg(target_os = "windows")]
        teardown::on_attach(hinst_dll as usize);

        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(name) = exe_path.file_name().and_then(|n| n.to_str()) {
                let _ = HOST_PROCESS.set(name.to_lowercase());
            }
        }

        let (tx, rx) = std::sync::mpsc::sync_channel::<String>(1024);
        let _ = ALERT_SENDER.set(tx);

        let rx_ptr = Box::into_raw(Box::new(rx));
        unsafe {
            CreateThread(std::ptr::null_mut(), 0, Some(ipc_worker), rx_ptr as *mut _, 0, std::ptr::null_mut());
        }
    });
}

unsafe extern "system" fn ipc_worker(param: *mut std::ffi::c_void) -> u32 {
    let rx = Box::from_raw(param as *mut std::sync::mpsc::Receiver<String>);
    while !teardown::is_teardown_requested() {
        if let Ok(payload) = rx.recv_timeout(std::time::Duration::from_millis(100)) {
            let mut delay_ms: u64 = 20;
            let mut retries = 0u32;

            while retries < 8 && !teardown::is_teardown_requested() {
                if let Ok(mut pipe) = OpenOptions::new().write(true).open(r"\\.\pipe\DataSensorAlerts") {
                    use std::io::Write;
                    let payload_nl = format!("{}\n", payload);
                    let _ = pipe.write_all(payload_nl.as_bytes());
                    break; // Delivered — exit retry loop
                }

                // Exponential backoff: 20 → 40 → 80 → 160 → 320 → 640 → 1000 ms (cap)
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                delay_ms = (delay_ms * 2).min(1000);
                retries += 1;
            }

            if retries == 8 {
                if let Ok(mut f) = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(r"C:\ProgramData\DataSensor\Logs\DataSensor_Diagnostic.log")
                {
                    use std::io::Write;
                    let _ = f.write_all(
                        b"[DS-Hook] [WARN] ipc_worker: payload dropped after 8 retries (pipe busy).\n"
                    );
                }
            }
        }
    }
    0
}

lazy_static! {
    static ref DLP_LITERALS: Vec<String> = {
        let mut keywords = Vec::new();
        if let Ok(config_data) = std::fs::read_to_string(r"C:\ProgramData\DataSensor\config.ini") {
            let mut in_section = false;
            for line in config_data.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('[') && trimmed.ends_with(']') {
                    in_section = trimmed == "[DLP_LITERALS]";
                    continue;
                }
                if in_section && !trimmed.is_empty() && !trimmed.starts_with(';') {
                    if let Some(idx) = trimmed.find('=') {
                        for kw in trimmed[idx + 1..].split(',') {
                            let val = kw.trim();
                            if !val.is_empty() { keywords.push(val.to_string()); }
                        }
                    }
                }
            }
        }
        if keywords.is_empty() { keywords.push("AKIA".to_string()); }
        keywords
    };

    static ref DLP_PATTERNS: regex::RegexSet = {
        let mut regex_list = Vec::new();
        if let Ok(config_data) = std::fs::read_to_string(r"C:\ProgramData\DataSensor\config.ini") {
            let mut in_regex_section = false;
            for line in config_data.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('[') && trimmed.ends_with(']') {
                    in_regex_section = trimmed == "[DLP_REGEX]";
                    continue;
                }
                if in_regex_section && !trimmed.is_empty() && !trimmed.starts_with(';') {
                let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        let val = parts[1].trim();
                        if !val.is_empty() {
                            match regex::Regex::new(val) {
                                Ok(re) if val.len() > 3 && val != ".*" && val != ".+" && !(re.is_match("") && re.is_match("a") && re.is_match("0")) => {
                                    regex_list.push(val.to_string());
                                }
                                Ok(_) => {
                                    // Silently discard universal-match patterns — they match everything.
                                }
                                Err(_) => {
                                    // Invalid regex — discard silently.
                                }
                            }
                        }
                    }
                }
            }
        }
        if regex_list.is_empty() { regex_list.push(r"AKIA[0-9A-Z]{16}".to_string()); }
        regex::RegexSet::new(&regex_list).unwrap_or_else(|_| regex::RegexSet::new(&[r"AKIA[0-9A-Z]{16}"]).unwrap())
    };

    static ref FILE_EXTENSIONS: (Vec<String>, Vec<String>) = {
        let mut archives = vec![".zip".to_string()];
        let mut texts = vec![".txt".to_string(), ".csv".to_string()];

        if let Ok(config_data) = std::fs::read_to_string(r"C:\ProgramData\DataSensor\config.ini") {
            let mut in_section = false;
            for line in config_data.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('[') && trimmed.ends_with(']') {
                    in_section = trimmed == "[FILE_INSPECTION]";
                    continue;
                }
                if !in_section { continue; }
                if trimmed.starts_with("ArchiveTypes=") {
                    archives = trimmed["ArchiveTypes=".len()..].split(',')
                        .map(|s| s.trim().to_lowercase()).collect();
                } else if trimmed.starts_with("TextTypes=") || trimmed.starts_with("DocumentTypes=") {
                    let mut types: Vec<String> = trimmed[(trimmed.find('=').unwrap() + 1)..]
                        .split(',').map(|s| s.trim().to_lowercase()).collect();
                    texts.append(&mut types);
                }
            }
        }
        (archives, texts)
    };

    static ref TRUSTED_PROCESSES: std::collections::HashSet<String> = {
        let mut procs = std::collections::HashSet::new();
        if let Ok(config_data) = std::fs::read_to_string(r"C:\ProgramData\DataSensor\config.ini") {
            let mut in_section = false;
            for line in config_data.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('[') && trimmed.ends_with(']') {
                    in_section = trimmed == "[EXCLUSIONS]";
                    continue;
                }
                if in_section && trimmed.starts_with("TrustedProcesses=") {
                    for p in trimmed["TrustedProcesses=".len()..].split(',') {
                        let val = p.trim().to_lowercase();
                        if !val.is_empty() { procs.insert(val); }
                    }
                }
            }
        }
        procs
    };
}

#[link(name = "kernel32")]
extern "system" {
    fn GetFileType(hFile: *mut c_void) -> u32;

    fn GetFinalPathNameByHandleW(
        hFile: *mut c_void,
        lpszFilePath: *mut u16,
        cchFilePath: u32,
        dwFlags: u32,
    ) -> u32;

    fn CreateThread(
        lpThreadAttributes: *mut std::ffi::c_void,
        dwStackSize: usize,
        lpStartAddress: Option<unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>,
        lpParameter: *mut std::ffi::c_void,
        dwCreationFlags: u32,
        lpThreadId: *mut u32,
    ) -> *mut std::ffi::c_void;
}
const FILE_TYPE_DISK: u32 = 0x0001;

unsafe extern "system" fn hooked_write_file(
    h_file: *mut c_void,
    lp_buffer: *const c_void,
    n_bytes: u32,
    lp_bytes_written: *mut u32,
    lp_overlapped: *mut c_void,
) -> i32 {
    ensure_initialized(HINST_DLL.load(std::sync::atomic::Ordering::Relaxed) as *mut c_void);

    let ftype = GetFileType(h_file);
    if ftype != FILE_TYPE_DISK && ftype != 0 {
        return resume_original(h_file, lp_buffer, n_bytes, lp_bytes_written, lp_overlapped);
    }
    if n_bytes == 0 || lp_buffer.is_null() {
        return resume_original(h_file, lp_buffer, n_bytes, lp_bytes_written, lp_overlapped);
    }

    let _guard = match teardown::HookGuard::acquire() {
        Some(g) => g,
        None => return resume_original(h_file, lp_buffer, n_bytes, lp_bytes_written, lp_overlapped),
    };

    if !inspect_and_alert(h_file, lp_buffer, n_bytes) {
        if !lp_bytes_written.is_null() { *lp_bytes_written = 0; }
        return 0;
    }

    resume_original(h_file, lp_buffer, n_bytes, lp_bytes_written, lp_overlapped)
}

#[inline(always)]
unsafe fn resume_original(
    h_file: *mut c_void,
    lp_buffer: *const c_void,
    n_bytes: u32,
    lp_bytes_written: *mut u32,
    lp_overlapped: *mut c_void,
) -> i32 {
    if let Some(original) = ORIGINAL_WRITEFILE.get() {
        return original(h_file, lp_buffer, n_bytes, lp_bytes_written, lp_overlapped);
    }
    1
}

const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_PROCESS_DETACH: u32 = 0;

pub fn remove_hooks() {
    unsafe {
        let _ = minhook_sys::MH_DisableHook(std::ptr::null_mut());  // Restore original bytes
        let _ = minhook_sys::MH_Uninitialize();                     // Free trampoline heap
    }
}

unsafe fn inspect_and_alert(h_file: *mut c_void, lp_buffer: *const c_void, n_bytes: u32) -> bool {
    if n_bytes == 0 || lp_buffer.is_null() { return true; }

    let host_proc = HOST_PROCESS.get().map(|s| s.as_str()).unwrap_or("Unknown_Process").to_string();

    let mut original_name = "intercepted_payload.dat".to_string();
    let mut file_path_opt: Option<String> = None;

    if let Some(nt_fn) = NT_QUERY_INFO_FILE.get() {
        let mut isb = IoStatusBlock { status: 0, information: 0 };
        let mut name_info = FileNameInfo { file_name_length: 0, file_name: [0u16; 512] };
        let status = nt_fn(h_file as isize, &mut isb,
            &mut name_info as *mut _ as *mut c_void,
            std::mem::size_of::<FileNameInfo>() as u32,
            FILE_NAME_INFORMATION_CLASS);

        if status == 0 || status == 0x80000005u32 as i32 {
            let len = (name_info.file_name_length / 2) as usize;
            let path_str = String::from_utf16_lossy(&name_info.file_name[..len.min(512)]);
            file_path_opt = Some(path_str);
        }
    }

    if file_path_opt.is_none() {
        let mut path_buf = [0u16; 512];
        let len = GetFinalPathNameByHandleW(h_file, path_buf.as_mut_ptr(), 512, 0);
        if len > 0 && len < 512 {
            let path_str = String::from_utf16_lossy(&path_buf[..len as usize]);
            let clean_path = path_str.replace("\\\\?\\", "");
            file_path_opt = Some(clean_path);
        }
    }

    let file_path = match file_path_opt {
        Some(p) => {
            let p_lower = p.to_lowercase();
            if let Some(idx) = p_lower.rfind('\\') {
                original_name = p_lower[idx + 1..].to_string();
            } else if let Some(idx) = p_lower.rfind('/') {
                original_name = p_lower[idx + 1..].to_string();
            }
            p_lower
        },
        None => String::from("unknown_stream"),
    };

    let is_own_path = file_path.contains("datasensor")
        || file_path.contains("namedpipe")
        || file_path.ends_with(".jsonl")
        || file_path.ends_with(".log")
        || file_path.contains("afd")
        || file_path.contains("tcp")
        || file_path.contains("udp")
        || file_path.contains("endpoint")
        || file_path.contains("mup");

    let is_system_noise = file_path.ends_with(".cache")
        || file_path.ends_with(".journal")
        || file_path.ends_with(".sqlite")
        || file_path.ends_with(".db")
        || file_path.ends_with(".db-wal")
        || file_path.ends_with(".db-shm")
        || file_path.ends_with(".etl")
        || file_path.ends_with(".db-journal")
        || file_path.contains("chrome\\user data");

    let host = HOST_PROCESS.get().map(|s| s.as_str()).unwrap_or("");

    let is_atomic_stage = file_path.ends_with(".tmp")
        || file_path.ends_with(".partial")
        || file_path.ends_with(".crdownload");

    let block_as_noise = if host_proc == "pwsh.exe" || host_proc == "powershell.exe" || host_proc == "cmd.exe" {
        is_system_noise
    } else {
        is_system_noise || is_atomic_stage
    };

    if is_own_path || block_as_noise { return true; }

    let ext = Path::new(&file_path).extension()
        .and_then(|e| e.to_str()).map(|s| format!(".{}", s.to_lowercase())).unwrap_or_default();

    if FILE_EXTENSIONS.0.contains(&ext) {
        let alert = DlpAlert {
            alert_type: "ASYNC_INSPECT_QUEUED".to_string(),
            action: "Archive_Delegation".to_string(),
            process: host_proc.clone(),
            destination: "Disk_Write".to_string(),
            details: "Archive created. Delegating to Orchestrator for deep inspection.".to_string(),
            filepath: file_path.clone(),
            file_hash: String::new(),
            confidence: 50,
            mitre_tactic: "T1560 - Archive Collected Data".to_string(),
        };
        if let Ok(json_payload) = serde_json::to_string(&alert) {
            if let Some(sender) = ALERT_SENDER.get() {
                let _ = sender.try_send(json_payload);
            }
        }
        return true;
    }

    let buffer_slice = std::slice::from_raw_parts(lp_buffer as *const u8, n_bytes as usize);

    if buffer_slice.len() >= 4
        && buffer_slice[0] == 0x50 && buffer_slice[1] == 0x4B
        && buffer_slice[2] == 0x03 && buffer_slice[3] == 0x04 {

        let evidence_dir = Path::new(r"C:\ProgramData\DataSensor\Evidence");
        let _ = fs::create_dir_all(evidence_dir);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut hasher = Sha256::new();
        hasher.update(buffer_slice);
        let computed_hash = hex::encode(hasher.finalize());
        let temp_zip_path = evidence_dir.join(format!("{}_{}_Intercepted.zip", timestamp, &computed_hash[0..8]));

        if let Ok(mut file) = File::create(&temp_zip_path) {
            let _ = file.write_all(buffer_slice);
        }

        let alert = DlpAlert {
            alert_type: "ASYNC_INSPECT_QUEUED".to_string(),
            action: "Archive_Delegation".to_string(),
            process: host_proc.clone(),
            destination: "Disk_Write".to_string(),
            details: "Archive created. Delegating to Orchestrator for deep inspection.".to_string(),
            filepath: temp_zip_path.display().to_string(),
            file_hash: computed_hash,
            confidence: 50,
            mitre_tactic: "T1560 - Archive Collected Data".to_string(),
        };
        if let Ok(json_payload) = serde_json::to_string(&alert) {
            if let Some(sender) = ALERT_SENDER.get() { let _ = sender.try_send(json_payload); }
        }
        return true;
    }

    if !FILE_EXTENSIONS.1.contains(&ext) {
        if TRUSTED_PROCESSES.contains(host) {
            return true;
        }
    }

    const MIN_INSPECT_BYTES: u32 = 16;
    if n_bytes < MIN_INSPECT_BYTES { return true; }

    let json_keys: &[&[u8]] = &[b"alert_type", b"DurationMs", b"Orchestrator", b"events"];
    let mut is_json_telemetry = false;
    for &key in json_keys {
        if buffer_slice.windows(key.len()).any(|w| w == key) { is_json_telemetry = true; break; }
        let mut utf16_key = Vec::with_capacity(key.len() * 2);
        for &b in key { utf16_key.push(b); utf16_key.push(0); }
        if buffer_slice.windows(utf16_key.len()).any(|w| w == utf16_key.as_slice()) {
            is_json_telemetry = true; break;
        }
    }
    let is_gzip = buffer_slice.len() > 2 && buffer_slice[0] == 0x1F && buffer_slice[1] == 0x8B;
    if is_gzip || buffer_slice.starts_with(b"H4sI") || is_json_telemetry { return true; }

    let content_utf8 = String::from_utf8_lossy(buffer_slice);
    let content_utf16: Option<String> = if buffer_slice.len() >= 4 && buffer_slice.len() % 2 == 0 {
        let has_bom = buffer_slice[0] == 0xFF && buffer_slice[1] == 0xFE;
        let null_odd = buffer_slice.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
        if has_bom || null_odd > buffer_slice.len() / 4 {
            let start = if has_bom { 2 } else { 0 };
            let words: Vec<u16> = buffer_slice[start..]
                .chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            Some(String::from_utf16_lossy(&words).to_string())
        } else { None }
    } else { None };

    let is_orch = content_utf8.contains("\"alert_type\"")
        || content_utf8.contains("\"events\":[")
        || content_utf8.contains("\"Component\":\"Orchestrator\"")
        || content_utf8.contains("\"DurationMs\":");
    let is_orch_utf16 = content_utf16.as_ref().map_or(false, |s|
        s.contains("\"alert_type\"") || s.contains("\"events\":[")
        || s.contains("\"Component\":\"Orchestrator\"") || s.contains("\"DurationMs\":"));
    if is_orch || is_orch_utf16 { return true; }

    let mut matched = false;
    let mut trigger_detail = String::new();

    for kw in DLP_LITERALS.iter() {
        let hit = content_utf8.contains(kw.as_str())
            || content_utf16.as_ref().map_or(false, |s| s.contains(kw.as_str()));
        if hit { matched = true; trigger_detail = format!("Literal Match: {}", kw); break; }
    }
    if !matched {
        let hit = DLP_PATTERNS.is_match(&content_utf8)
            || content_utf16.as_ref().map_or(false, |s| DLP_PATTERNS.is_match(s));
        if hit { matched = true; trigger_detail = "Regex Signature Match".to_string(); }
    }

    if matched {
        let mut hasher = Sha256::new();
        hasher.update(buffer_slice);
        let computed_hash = hex::encode(hasher.finalize());

        let evidence_dir = Path::new(r"C:\ProgramData\DataSensor\Evidence");
        let _ = fs::create_dir_all(evidence_dir);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let evidence_path = evidence_dir.join(
            format!("{}_{}_{}", timestamp, &computed_hash[0..8], original_name));

        if let Ok(mut file) = File::create(&evidence_path) {
            let _ = file.write_all(buffer_slice);
        }

        let alert = DlpAlert {
            alert_type: "ACTION_REQUIRED".to_string(),
            action: "File_Write_Blocked".to_string(),
            process: host_proc.clone(),
            destination: "Disk_Write".to_string(),
            details: format!("In-Band Write Blocked | {}", trigger_detail),
            filepath: evidence_path.display().to_string(),
            file_hash: computed_hash,
            confidence: 100,
            mitre_tactic: "T1485 - Data Destruction / Mitigation".to_string(),
        };
        if let Ok(json_payload) = serde_json::to_string(&alert) {
            if let Some(sender) = ALERT_SENDER.get() {
                let _ = sender.try_send(json_payload);
            }
        }
        return false;
    }

    true
}

unsafe extern "system" fn hooked_ntwritefile(
    h_file: *mut c_void, h_event: *mut c_void, apc_routine: *mut c_void, apc_context: *mut c_void,
    io_status_block: *mut IoStatusBlock, buffer: *const c_void, length: u32, byte_offset: *mut i64, key: *mut u32,
) -> i32 {
    ensure_initialized(HINST_DLL.load(std::sync::atomic::Ordering::Relaxed) as *mut c_void);

    let ftype = GetFileType(h_file);
    if (ftype != FILE_TYPE_DISK && ftype != 0) || length == 0 || buffer.is_null() {
        if let Some(orig) = ORIGINAL_NTWRITEFILE.get() { return orig(h_file, h_event, apc_routine, apc_context, io_status_block, buffer, length, byte_offset, key); }
        return 0xC0000001u32 as i32;
    }

    let _guard = match teardown::HookGuard::acquire() {
        Some(g) => g,
        None => {
            if let Some(orig) = ORIGINAL_NTWRITEFILE.get() { return orig(h_file, h_event, apc_routine, apc_context, io_status_block, buffer, length, byte_offset, key); }
            return 0xC0000001u32 as i32;
        }
    };

    if !inspect_and_alert(h_file, buffer, length) {
        if !io_status_block.is_null() { (*io_status_block).information = 0; }
        return 0xC0000022u32 as i32; // STATUS_ACCESS_DENIED
    }

    if let Some(orig) = ORIGINAL_NTWRITEFILE.get() {
        return orig(h_file, h_event, apc_routine, apc_context, io_status_block, buffer, length, byte_offset, key);
    }
    0xC0000001u32 as i32
}

pub fn send_diag_log(level: &str, message: &str) {
    if let Some(sender) = ALERT_SENDER.get() {
        let host_proc = HOST_PROCESS.get().map(|s| s.as_str()).unwrap_or("Unknown").to_string();
        let payload = format!(
            r#"{{"type":"DIAG_LOG_EVENT", "level":"{}", "process":"{}", "message":"{}"}}"#,
            level, host_proc, message
        );
        let _ = sender.try_send(payload);
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(hinst_dll: *mut c_void, fdw_reason: u32, _lpv_reserved: *mut c_void) -> i32 {
    match fdw_reason {DLL_PROCESS_ATTACH => {
            unsafe {
                windows_sys::Win32::System::LibraryLoader::DisableThreadLibraryCalls(hinst_dll as _);

                HINST_DLL.store(hinst_dll as usize, std::sync::atomic::Ordering::Relaxed);

                ensure_initialized(hinst_dll);

                if minhook_sys::MH_Initialize() != 0 { return 1; }

                let mut write_file_addr: Option<unsafe extern "system" fn() -> isize> = None;

                let h_kernelbase = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"kernelbase.dll\0".as_ptr());
                if h_kernelbase != 0 {
                    write_file_addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(h_kernelbase, b"WriteFile\0".as_ptr());
                }

                if write_file_addr.is_none() {
                    let h_kernel32 = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"kernel32.dll\0".as_ptr());
                    if h_kernel32 != 0 {
                        write_file_addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(h_kernel32, b"WriteFile\0".as_ptr());
                    }
                }

                let ntdll = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"ntdll.dll\0".as_ptr());
                if ntdll != 0 {
                    if let Some(fn_addr) = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                        ntdll, b"NtQueryInformationFile\0".as_ptr()
                    ) {
                        let _ = NT_QUERY_INFO_FILE.set(std::mem::transmute(fn_addr));
                    }

                    if let Some(nt_write_addr) = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                        ntdll, b"NtWriteFile\0".as_ptr()
                    ) {
                        let mut orig_nt: *mut c_void = std::ptr::null_mut();
                        if minhook_sys::MH_CreateHook(nt_write_addr as *mut _, hooked_ntwritefile as *mut _, &mut orig_nt) == 0 {
                            let _ = ORIGINAL_NTWRITEFILE.set(std::mem::transmute(orig_nt));
                            let _ = minhook_sys::MH_EnableHook(nt_write_addr as *mut _);
                        }
                    }
                }

                if let Some(addr) = write_file_addr {
                    let addr_ptr = addr as *mut c_void;
                    let mut original: *mut c_void = std::ptr::null_mut();
                    if minhook_sys::MH_CreateHook(addr_ptr, hooked_write_file as *mut c_void, &mut original) == 0 {
                        let _ = ORIGINAL_WRITEFILE.set(std::mem::transmute(original));
                        let _ = minhook_sys::MH_EnableHook(addr_ptr);
                    }
                }
            }
        }
        DLL_PROCESS_DETACH => {
            teardown::on_detach();
        }
        _ => {}
    }
    1
}