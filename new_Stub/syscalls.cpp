#include "syscalls.h"

#define STRINGIFY(x) #x
#define TO_STRING(x) STRINGIFY(x)

extern "C" {

NTSTATUS __attribute__((naked)) SyscallQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    asm volatile (
        ".intel_syntax noprefix\n\t"
        "mov r10, rcx\n\t"
        "mov eax, " TO_STRING(SYSCALL_QUERY_SYSTEM_INFORMATION) "\n\t"
        "syscall\n\t"
        "ret\n\t"
        ".att_syntax prefix"
    );
}

NTSTATUS __attribute__((naked)) SyscallOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    asm volatile (
        ".intel_syntax noprefix\n\t"
        "mov r10, rcx\n\t"
        "mov eax, " TO_STRING(SYSCALL_OPEN_PROCESS) "\n\t"
        "syscall\n\t"
        "ret\n\t"
        ".att_syntax prefix"
    );
}

NTSTATUS __attribute__((naked)) SyscallAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    asm volatile (
        ".intel_syntax noprefix\n\t"
        "mov r10, rcx\n\t"
        "mov eax, " TO_STRING(SYSCALL_ALLOCATE_MEMORY) "\n\t"
        "syscall\n\t"
        "ret\n\t"
        ".att_syntax prefix"
    );
}

NTSTATUS __attribute__((naked)) SyscallWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    asm volatile (
        ".intel_syntax noprefix\n\t"
        "mov r10, rcx\n\t"
        "mov eax, " TO_STRING(SYSCALL_WRITE_MEMORY) "\n\t"
        "syscall\n\t"
        "ret\n\t"
        ".att_syntax prefix"
    );
}

NTSTATUS __attribute__((naked)) SyscallCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList) {
    asm volatile (
        ".intel_syntax noprefix\n\t"
        "mov r10, rcx\n\t"
        "mov eax, " TO_STRING(SYSCALL_CREATE_THREAD) "\n\t"
        "syscall\n\t"
        "ret\n\t"
        ".att_syntax prefix"
    );
}

NTSTATUS __attribute__((naked)) SyscallProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
    asm volatile (
        ".intel_syntax noprefix\n\t"
        "mov r10, rcx\n\t"
        "mov eax, " TO_STRING(SYSCALL_PROTECT_MEMORY) "\n\t"
        "syscall\n\t"
        "ret\n\t"
        ".att_syntax prefix"
    );
}

NTSTATUS __attribute__((naked)) SyscallClose(HANDLE Handle) {
    asm volatile (
        ".intel_syntax noprefix\n\t"
        "mov r10, rcx\n\t"
        "mov eax, " TO_STRING(SYSCALL_CLOSE_HANDLE) "\n\t"
        "syscall\n\t"
        "ret\n\t"
        ".att_syntax prefix"
    );
}

} // extern "C"