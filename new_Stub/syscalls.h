#pragma once

#include <windows.h>
#include <winternl.h>

#define SYSCALL_STUB_SIZE 23

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Define syscall numbers for required functions
#define SYSCALL_OPEN_PROCESS   0x0026
#define SYSCALL_ALLOCATE_MEMORY 0x0018
#define SYSCALL_WRITE_MEMORY   0x003a
#define SYSCALL_CREATE_THREAD  0x004e
#define SYSCALL_PROTECT_MEMORY 0x0050
#define SYSCALL_CLOSE_HANDLE   0x000f
#define SYSCALL_QUERY_SYSTEM_INFORMATION 0x0036

// Function prototypes for syscall wrappers
extern "C" NTSTATUS SyscallQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
extern "C" NTSTATUS SyscallOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
extern "C" NTSTATUS SyscallAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
extern "C" NTSTATUS SyscallWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
extern "C" NTSTATUS SyscallCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
extern "C" NTSTATUS SyscallProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
extern "C" NTSTATUS SyscallClose(HANDLE Handle);