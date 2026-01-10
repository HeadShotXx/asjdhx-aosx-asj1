//! Registry Protection module
//!
//! Provides functions to lock/protect registry keys by modifying DACLs.
//! This is useful for protecting sensitive registry paths from unauthorized access.

use crate::{Result, SignatureMonsterError};
use windows::Win32::Foundation::{HANDLE, PSID};
use windows::Win32::Security::*;
use windows::Win32::Security::Authorization::*;
use windows::Win32::System::Registry::*;
use windows::core::PCWSTR;
use std::ptr::null_mut;

/// Registry protection utilities
pub struct RegistryProtection {
    _private: (),
}

impl RegistryProtection {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Convert a string to wide null-terminated string
    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Parse registry path into root key and subkey
    fn parse_path(path: &str) -> Result<(HKEY, String)> {
        let parts: Vec<&str> = path.splitn(2, '\\').collect();
        if parts.len() < 2 {
            return Err(SignatureMonsterError::RegistryError(
                "Invalid registry path format".to_string(),
            ));
        }

        let root = match parts[0].to_uppercase().as_str() {
            "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
            "HKCR" | "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
            "HKU" | "HKEY_USERS" => HKEY_USERS,
            _ => {
                return Err(SignatureMonsterError::RegistryError(format!(
                    "Unknown registry root: {}",
                    parts[0]
                )))
            }
        };

        Ok((root, parts[1].to_string()))
    }

    /// Lock a registry key by denying access to "Everyone"
    /// This prevents modifications to the registry key.
    pub fn lock_key(&self, path: &str) -> Result<()> {
        let (root, subkey) = Self::parse_path(path)?;
        let wide_subkey = Self::to_wide(&subkey);

        // Open with READ_CONTROL and WRITE_DAC permissions
        let mut hkey = HKEY::default();
        unsafe {
            RegOpenKeyExW(
                root,
                PCWSTR(wide_subkey.as_ptr()),
                0,
                KEY_READ | KEY_WRITE | REG_SAM_FLAGS(0x00040000) | REG_SAM_FLAGS(0x00020000), // READ_CONTROL | WRITE_DAC
                &mut hkey,
            )?;
        }

        // Create "Everyone" SID
        let mut everyone_sid: PSID = PSID::default();
        let mut sid_size: u32 = 0;
        
        // First call to get size
        unsafe {
            let _ = CreateWellKnownSid(
                WinWorldSid,
                None,
                PSID(null_mut()),
                &mut sid_size,
            );
        }

        let mut sid_buffer = vec![0u8; sid_size as usize];
        everyone_sid = PSID(sid_buffer.as_mut_ptr() as *mut _);

        unsafe {
            CreateWellKnownSid(
                WinWorldSid,
                None,
                everyone_sid,
                &mut sid_size,
            )?;
        }

        // Build EXPLICIT_ACCESS for denying all access
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: KEY_ALL_ACCESS.0,
            grfAccessMode: DENY_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: windows::core::PWSTR(everyone_sid.0 as *mut u16),
            },
        };

        // Set entries in ACL
        let mut new_dacl: *mut ACL = null_mut();
        unsafe {
            SetEntriesInAclW(
                Some(&[ea]),
                None,
                &mut new_dacl,
            )?;
        }

        // Apply the new DACL
        unsafe {
            SetSecurityInfo(
                HANDLE(hkey.0 as *mut _),
                SE_REGISTRY_KEY,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(new_dacl),
                None,
            )?;

            let _ = RegCloseKey(hkey);
        }

        Ok(())
    }

    /// Unlock a registry key by removing deny ACEs (restore default access)
    pub fn unlock_key(&self, path: &str) -> Result<()> {
        let (root, subkey) = Self::parse_path(path)?;
        let wide_subkey = Self::to_wide(&subkey);

        let mut hkey = HKEY::default();
        unsafe {
            RegOpenKeyExW(
                root,
                PCWSTR(wide_subkey.as_ptr()),
                0,
                KEY_READ | KEY_WRITE | REG_SAM_FLAGS(0x00040000) | REG_SAM_FLAGS(0x00020000),
                &mut hkey,
            )?;
        }

        // Create empty DACL (removes all explicit permissions, inherits from parent)
        let mut new_dacl: *mut ACL = null_mut();
        unsafe {
            SetEntriesInAclW(
                None,
                None,
                &mut new_dacl,
            )?;

            SetSecurityInfo(
                HANDLE(hkey.0 as *mut _),
                SE_REGISTRY_KEY,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(new_dacl),
                None,
            )?;

            let _ = RegCloseKey(hkey);
        }

        Ok(())
    }

    /// Check if a registry key is protected (has deny ACEs)
    pub fn is_key_protected(&self, path: &str) -> bool {
        // Try to open with write access - if it fails, key is protected
        let (root, subkey) = match Self::parse_path(path) {
            Ok((r, s)) => (r, s),
            Err(_) => return false,
        };
        let wide_subkey = Self::to_wide(&subkey);

        let mut hkey = HKEY::default();
        let result = unsafe {
            RegOpenKeyExW(
                root,
                PCWSTR(wide_subkey.as_ptr()),
                0,
                KEY_WRITE,
                &mut hkey,
            )
        };

        if result.is_ok() {
            unsafe { let _ = RegCloseKey(hkey); }
            false
        } else {
            true
        }
    }

    /// Lock multiple registry keys
    pub fn lock_keys(&self, paths: &[&str]) -> Vec<Result<()>> {
        paths.iter().map(|path| self.lock_key(path)).collect()
    }

    /// Protect a list of registry paths (convenience wrapper)
    pub fn protect_paths(&self, paths: &[&str]) {
        for path in paths {
            let _ = self.lock_key(path);
        }
    }
}

impl Default for RegistryProtection {
    fn default() -> Self {
        Self::new()
    }
}

/// Common registry paths that malware often targets for persistence
pub const COMMON_PERSISTENCE_PATHS: &[&str] = &[
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
];

/// Registry paths commonly used by specific malware families
pub const MALWARE_REGISTRY_INDICATORS: &[&str] = &[
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
    r"HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot",
];
