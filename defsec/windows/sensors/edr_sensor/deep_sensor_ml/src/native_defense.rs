// Native active-defense mechanism (thread suspend/resume, forensic dump, artifact
// correlation). Policy/gating stays in OsSensor.cs.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    MiniDumpWithFullMemory, MiniDumpWriteDump, ReadProcessMemory,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::{VirtualProtectEx, PAGE_NOACCESS};
use windows_sys::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenThread, QueryFullProcessImageNameW, ResumeThread, SuspendThread,
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, THREAD_SUSPEND_RESUME,
};
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use winreg::RegKey;
use sha2::{Digest, Sha256};

#[unsafe(no_mangle)]
pub extern "C" fn quarantine_native_thread(tid: u32) -> i32 {
    let result = std::panic::catch_unwind(|| unsafe {
        let h_thread = OpenThread(THREAD_SUSPEND_RESUME, 0, tid);
        if h_thread.is_null() {
            return 0;
        }
        let suspend_count = SuspendThread(h_thread);
        CloseHandle(h_thread);
        if suspend_count == u32::MAX { 0 } else { 1 }
    });
    result.unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn resume_native_thread(tid: u32) -> i32 {
    let result = std::panic::catch_unwind(|| unsafe {
        let h_thread = OpenThread(THREAD_SUSPEND_RESUME, 0, tid);
        if h_thread.is_null() {
            return 0;
        }
        let resume_count = ResumeThread(h_thread);
        CloseHandle(h_thread);
        if resume_count == u32::MAX { 0 } else { 1 }
    });
    result.unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn preserve_forensics(pid: u32, dump_path_c: *const c_char) -> i32 {
    if dump_path_c.is_null() {
        return 0;
    }
    let path_str = unsafe {
        match CStr::from_ptr(dump_path_c).to_str() {
            Ok(s) => s.to_owned(),
            Err(_) => return 0,
        }
    };

    let result = std::panic::catch_unwind(move || {
        let file = match std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path_str)
        {
            Ok(f) => f,
            Err(_) => return 0,
        };
        let h_file = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;

        unsafe {
            let h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
            if h_process.is_null() {
                return 0;
            }
            let ok = MiniDumpWriteDump(
                h_process,
                pid,
                h_file,
                MiniDumpWithFullMemory,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            );
            CloseHandle(h_process);
            if ok != 0 { 1 } else { 0 }
        }
    });
    result.unwrap_or(0)
}

/// out_buffer must be caller-allocated with at least `size` bytes.
#[unsafe(no_mangle)]
pub extern "C" fn read_process_memory_region(
    pid: u32,
    address: u64,
    out_buffer: *mut u8,
    size: u64,
) -> i32 {
    if out_buffer.is_null() || size == 0 {
        return 0;
    }
    let result = std::panic::catch_unwind(|| unsafe {
        let h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if h_process.is_null() {
            return 0;
        }
        let mut bytes_read: usize = 0;
        let ok = ReadProcessMemory(
            h_process,
            address as *const core::ffi::c_void,
            out_buffer as *mut core::ffi::c_void,
            size as usize,
            &mut bytes_read,
        );
        CloseHandle(h_process);
        if ok != 0 && bytes_read as u64 == size { 1 } else { 0 }
    });
    result.unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn virtual_protect_noaccess(pid: u32, address: u64, size: u64) -> i32 {
    let result = std::panic::catch_unwind(|| unsafe {
        let h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, 0, pid);
        if h_process.is_null() {
            return 0;
        }
        let mut old_protect: u32 = 0;
        let ok = VirtualProtectEx(
            h_process,
            address as *const core::ffi::c_void,
            size as usize,
            PAGE_NOACCESS,
            &mut old_protect,
        );
        CloseHandle(h_process);
        if ok != 0 { 1 } else { 0 }
    });
    result.unwrap_or(0)
}

// ============================================================================
// ON-DISK ARTIFACT CORRELATION (image hash, loaded modules, persistence)
// ============================================================================

fn get_image_path(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut size: u32 = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size);
        CloseHandle(h);
        if ok == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..size as usize]))
    }
}

fn get_parent_pid(pid: u32) -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
        let mut result = None;
        if Process32First(snap, &mut entry) != 0 {
            loop {
                if entry.th32ProcessID == pid {
                    result = Some(entry.th32ParentProcessID);
                    break;
                }
                if Process32Next(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
        result
    }
}

/// Lightweight lookup for host-isolation PID-lineage correlation. Returns 0 if not found.
#[unsafe(no_mangle)]
pub extern "C" fn get_process_parent_pid(pid: u32) -> u32 {
    std::panic::catch_unwind(|| get_parent_pid(pid).unwrap_or(0)).unwrap_or(0)
}

// Built-in command-line signatures for known offensive tooling (Sigma-rule seed data).
// Stored here, not as literal strings in the launcher, so the interpreted script never
// contains known attack-tool command syntax verbatim.
#[unsafe(no_mangle)]
pub extern "C" fn get_builtin_threat_signatures() -> *mut c_char {
    let sigs: Vec<&str> = vec![
        "sekurlsa::logonpasswords",
        "lsadump::",
        "privilege::debug",
        "Invoke-BloodHound",
        "procdump -ma lsass",
        "vssadmin delete shadows",
    ];
    let json = serde_json::to_string(&sigs).unwrap_or_else(|_| "[]".to_string());
    match CString::new(json) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn get_loaded_modules(pid: u32) -> Vec<String> {
    let mut result = Vec::new();
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if h.is_null() {
            return result;
        }
        let mut modules = [0isize; 1024];
        let mut needed: u32 = 0;
        let ok = EnumProcessModulesEx(
            h,
            modules.as_mut_ptr() as *mut _,
            (modules.len() * std::mem::size_of::<isize>()) as u32,
            &mut needed,
            LIST_MODULES_ALL,
        );
        if ok != 0 {
            let count = (needed as usize / std::mem::size_of::<isize>()).min(modules.len());
            for m in modules.iter().take(count) {
                let mut name_buf = [0u16; 1024];
                let len = GetModuleFileNameExW(h, *m as _, name_buf.as_mut_ptr(), name_buf.len() as u32);
                if len > 0 {
                    let name = String::from_utf16_lossy(&name_buf[..len as usize]);
                    if !name.to_lowercase().contains(r"\windows\") {
                        result.push(name);
                    }
                }
            }
        }
        CloseHandle(h);
    }
    result
}

fn check_run_keys(leaf: &str) -> Vec<String> {
    let mut found = Vec::new();
    let leaf_lower = leaf.to_lowercase();
    for (root_name, root) in [("HKLM", HKEY_LOCAL_MACHINE), ("HKCU", HKEY_CURRENT_USER)] {
        let hk = RegKey::predef(root);
        for sub in [
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        ] {
            if let Ok(key) = hk.open_subkey(sub) {
                for name in key.enum_values().flatten().map(|(n, _)| n) {
                    if let Ok(value) = key.get_value::<String, _>(&name) {
                        if value.to_lowercase().contains(&leaf_lower) {
                            found.push(format!("Run:{}\\{}\\{}", root_name, sub, name));
                        }
                    }
                }
            }
        }
    }
    found
}

fn check_services(leaf: &str) -> Vec<String> {
    let mut found = Vec::new();
    let leaf_lower = leaf.to_lowercase();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(services) = hklm.open_subkey("SYSTEM\\CurrentControlSet\\Services") {
        for name in services.enum_keys().flatten() {
            if let Ok(svc_key) = services.open_subkey(&name) {
                if let Ok(image_path) = svc_key.get_value::<String, _>("ImagePath") {
                    if image_path.to_lowercase().contains(&leaf_lower) {
                        found.push(format!("Service:{}", name));
                    }
                }
            }
        }
    }
    found
}

fn check_scheduled_tasks(leaf: &str) -> Vec<String> {
    let mut found = Vec::new();
    let leaf_lower = leaf.to_lowercase();
    fn walk(dir: &std::path::Path, leaf_lower: &str, found: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, leaf_lower, found);
            } else if let Ok(content) = std::fs::read_to_string(&path) {
                if content.to_lowercase().contains(leaf_lower) {
                    found.push(format!("Task:{}", path.display()));
                }
            }
        }
    }
    walk(std::path::Path::new(r"C:\Windows\System32\Tasks"), &leaf_lower, &mut found);
    found
}

fn check_startup_folders(leaf: &str) -> Vec<String> {
    let mut found = Vec::new();
    let leaf_lower = leaf.to_lowercase();
    let program_data = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    let app_data = std::env::var("AppData").unwrap_or_default();
    let mut bases = vec![format!(r"{}\Microsoft\Windows\Start Menu\Programs\Startup", program_data)];
    if !app_data.is_empty() {
        bases.push(format!(r"{}\Microsoft\Windows\Start Menu\Programs\Startup", app_data));
    }
    for base in bases {
        let Ok(entries) = std::fs::read_dir(&base) else { continue };
        for entry in entries.flatten() {
            let fname = entry.file_name().to_string_lossy().to_lowercase();
            if fname.contains(&leaf_lower) {
                found.push(format!("Startup:{}", entry.path().display()));
            }
        }
    }
    found
}

/// Returns a JSON blob (ImagePath, ImageSHA256, ParentPID, ParentImage, LoadedModules,
/// Persistence) for the incident report. Caller must free the result via free_string.
#[unsafe(no_mangle)]
pub extern "C" fn correlate_on_disk_artifacts(pid: u32) -> *mut c_char {
    let result = std::panic::catch_unwind(|| {
        let image_path = get_image_path(pid).unwrap_or_default();

        let image_sha256 = if !image_path.is_empty() {
            std::fs::read(&image_path)
                .ok()
                .map(|bytes| {
                    let mut hasher = Sha256::new();
                    hasher.update(&bytes);
                    format!("{:x}", hasher.finalize())
                })
                .unwrap_or_default()
        } else {
            String::new()
        };

        let parent_pid = get_parent_pid(pid).unwrap_or(0);
        let parent_image = if parent_pid > 0 {
            get_image_path(parent_pid).unwrap_or_default()
        } else {
            String::new()
        };

        let loaded_modules = get_loaded_modules(pid);

        let leaf = std::path::Path::new(&image_path)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();

        let mut persistence = Vec::new();
        if !leaf.is_empty() {
            persistence.extend(check_run_keys(&leaf));
            persistence.extend(check_services(&leaf));
            persistence.extend(check_scheduled_tasks(&leaf));
            persistence.extend(check_startup_folders(&leaf));
        }

        serde_json::json!({
            "ImagePath": image_path,
            "ImageSHA256": image_sha256,
            "ParentPID": parent_pid,
            "ParentImage": parent_image,
            "LoadedModules": loaded_modules,
            "Persistence": persistence,
        })
        .to_string()
    });

    let json_str = result.unwrap_or_else(|_| "{}".to_string());
    match CString::new(json_str) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}
