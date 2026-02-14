
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use std::mem;

fn rva_to_offset(rva: usize, sections: *const IMAGE_SECTION_HEADER, num_sections: u16) -> Option<usize> {
    for i in 0..num_sections {
        let section = unsafe { *sections.add(i as usize) };
        if rva >= section.VirtualAddress as usize && rva < (section.VirtualAddress + section.SizeOfRawData) as usize {
            return Some(section.PointerToRawData as usize + (rva - section.VirtualAddress as usize));
        }
    }
    None
}

pub fn get_syscall_number(func_name: &str) -> Option<u32> {
    let ntdll_bytes = std::fs::read("C:\\Windows\\System32\\ntdll.dll").ok()?;
    let dos_header = ntdll_bytes.as_ptr() as *const IMAGE_DOS_HEADER;

    let nt_headers = unsafe {
        (ntdll_bytes.as_ptr() as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64
    };

    let export_dir_rva = unsafe {
        (*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress as usize
    };

    let num_sections = unsafe { (*nt_headers).FileHeader.NumberOfSections };
    let section_header = (nt_headers as usize + mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;

    let export_dir_offset = rva_to_offset(export_dir_rva, section_header, num_sections)?;
    let export_dir = unsafe {
        &*(ntdll_bytes.as_ptr().add(export_dir_offset) as *const IMAGE_EXPORT_DIRECTORY)
    };

    let names_offset = rva_to_offset(export_dir.AddressOfNames as usize, section_header, num_sections)?;
    let ordinals_offset = rva_to_offset(export_dir.AddressOfNameOrdinals as usize, section_header, num_sections)?;
    let functions_offset = rva_to_offset(export_dir.AddressOfFunctions as usize, section_header, num_sections)?;

    let names = unsafe {
        std::slice::from_raw_parts(ntdll_bytes.as_ptr().add(names_offset) as *const u32, export_dir.NumberOfNames as usize)
    };
    let ordinals = unsafe {
        std::slice::from_raw_parts(ntdll_bytes.as_ptr().add(ordinals_offset) as *const u16, export_dir.NumberOfNames as usize)
    };
    let functions = unsafe {
        std::slice::from_raw_parts(ntdll_bytes.as_ptr().add(functions_offset) as *const u32, export_dir.NumberOfFunctions as usize)
    };

    for i in 0..export_dir.NumberOfNames as usize {
        let name_offset = rva_to_offset(names[i] as usize, section_header, num_sections)?;
        let name = unsafe {
            std::ffi::CStr::from_ptr(ntdll_bytes.as_ptr().add(name_offset) as *const i8)
        }.to_str().ok()?;

        if name == func_name {
            let ordinal = ordinals[i];
            let func_rva = functions[ordinal as usize] as usize;
            let func_offset = rva_to_offset(func_rva, section_header, num_sections)?;

            let func_bytes = &ntdll_bytes[func_offset..func_offset + 8];
            // Look for mov eax, <id>
            // Typically:
            // 4c 8b d1    mov r10, rcx
            // b8 id id 00 00 mov eax, id
            if func_bytes[3] == 0xb8 {
                let low = func_bytes[4] as u32;
                let high = func_bytes[5] as u32;
                return Some((high << 8) | low);
            }
        }
    }

    None
}
