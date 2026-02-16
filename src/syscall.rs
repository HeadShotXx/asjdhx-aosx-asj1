
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::SystemServices::*;

pub fn get_syscall_number(func_name: &str) -> Option<u32> {
    unsafe {
        let ntdll_base = get_ntdll_base()?;
        let func_addr = get_proc_address_manual(ntdll_base, func_name)?;

        let func_bytes = std::slice::from_raw_parts(func_addr as *const u8, 8);

        if func_bytes[0] == 0x4c
            && func_bytes[1] == 0x8b
            && func_bytes[2] == 0xd1
            && func_bytes[3] == 0xb8
            && func_bytes[6] == 0x00
            && func_bytes[7] == 0x00
        {
            let high = u32::from(func_bytes[5]);
            let low = u32::from(func_bytes[4]);
            let syscall_number = (high << 8) | low;
            return Some(syscall_number);
        }

        None
    }
}

unsafe fn get_ntdll_base() -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    let peb_ptr: *const usize;
    #[cfg(target_arch = "x86_64")]
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb_ptr);

    let ldr_ptr = *(peb_ptr.add(3)) as *const usize; // PEB->Ldr (0x18 offset)
    let mut current_link = *(ldr_ptr.add(2)) as *const usize; // Ldr->InLoadOrderModuleList.Flink (0x10 offset)
    let head = current_link;

    loop {
        let base_name_ptr = *(current_link.add(11)) as *const u16; // LDR_DATA_TABLE_ENTRY->BaseDllName.Buffer (0x58 offset)
        let base_name_len = *(current_link.add(10)) as u32 & 0xFFFF; // LDR_DATA_TABLE_ENTRY->BaseDllName.Length (0x50 offset)

        if !base_name_ptr.is_null() {
            let name_slice = std::slice::from_raw_parts(base_name_ptr, (base_name_len / 2) as usize);
            let name = String::from_utf16_lossy(name_slice);
            if name.to_lowercase() == "ntdll.dll" {
                return Some(*(current_link.add(6))); // LDR_DATA_TABLE_ENTRY->DllBase (0x30 offset)
            }
        }

        current_link = *current_link as *const usize;
        if current_link == head || current_link.is_null() {
            break;
        }
    }

    None
}

unsafe fn get_proc_address_manual(base: usize, func_name: &str) -> Option<usize> {
    let dos_header = base as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    let nt_headers = (base + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress as usize;
    if export_dir_rva == 0 {
        return None;
    }

    let export_dir = (base + export_dir_rva) as *const IMAGE_EXPORT_DIRECTORY;
    let names_rva = (*export_dir).AddressOfNames as usize;
    let funcs_rva = (*export_dir).AddressOfFunctions as usize;
    let ords_rva = (*export_dir).AddressOfNameOrdinals as usize;

    for i in 0..(*export_dir).NumberOfNames {
        let name_rva = *((base + names_rva + (i as usize * 4)) as *const u32) as usize;
        let name_ptr = (base + name_rva) as *const i8;
        let name_str = std::ffi::CStr::from_ptr(name_ptr).to_str().ok()?;

        if name_str == func_name {
            let ord = *((base + ords_rva + (i as usize * 2)) as *const u16) as usize;
            let func_rva = *((base + funcs_rva + (ord * 4)) as *const u32) as usize;
            return Some(base + func_rva);
        }
    }

    None
}
