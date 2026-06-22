# Security Research: Advanced Process Injection and Evasion Techniques

This document provides an educational overview of advanced techniques often studied in detection engineering and security research. Understanding these methods is essential for developing robust defensive strategies and improving security software.

## 1. Direct Syscalls

### Overview
Standard Windows applications interact with the kernel through the Windows API (e.g., `VirtualAlloc`). These APIs are wrappers around internal functions in `ntdll.dll` (e.g., `NtAllocateVirtualMemory`), which execute the `syscall` instruction.

### Technique
Security products often "hook" functions in `ntdll.dll` to monitor activity. Direct syscalls involve executing the `syscall` instruction directly from the application's code, bypassing user-mode hooks in `ntdll.dll`.

### Defensive Perspective
*   **Detection:** Modern EDRs monitor for syscalls originating from memory regions not associated with `ntdll.dll`.
*   **Instrumentation:** Kernel-mode callbacks (e.g., via `PsSetCreateProcessNotifyRoutine`) and Event Tracing for Windows (ETW) allow the kernel to report on system calls regardless of their origin in user space.

## 2. DLL Unhooking

### Overview
EDRs often monitor processes by patching library functions in memory. DLL unhooking is a technique used to restore the original, unmodified code of a library.

### Technique
A common approach is to:
1.  Map a "clean" copy of `ntdll.dll` from the disk into the process's memory.
2.  Identify the `.text` section of the clean copy.
3.  Replace the hooked `.text` section of the currently loaded `ntdll.dll` with the clean one.

### Defensive Perspective
*   **Monitoring:** Defenders track calls to `NtProtectVirtualMemory` that change code section permissions (e.g., from RX to RWX or RW).
*   **Integrity Checks:** Security software may periodically re-verify its hooks or use hardware breakpoints that cannot be easily removed by overwriting memory.

## 3. Targeted Process Injection

### Overview
Injecting code into legitimate system processes is a method used to blend in with normal system activity. Processes like `explorer.exe` or `RuntimeBroker.exe` are common targets due to their prevalence and expected background activity.

### Technique
`RuntimeBroker.exe` is responsible for managing permissions for Windows Store apps. From a research perspective, it is interesting because it often has limited permissions itself but interacts with many other components.

### Defensive Perspective
*   **Behavioral Analysis:** Security solutions monitor for "cross-process" operations. If an unrelated process opens a handle to a system process with high-access rights (`PROCESS_ALL_ACCESS`) and attempts to create a remote thread, it is flagged as highly suspicious.
*   **Parent-Child Relationships:** Unusual parent-child process relationships are a key indicator of injection or spoofing.

## 4. Process Protection and Access Restriction

### Overview
Windows provides mechanisms to protect processes from unauthorized access, such as Protected Process Light (PPL).

### Technique
While PPL is a system-level feature, researchers study how process attributes and security descriptors can be used to limit the ability of other user-mode processes to open handles to a specific process.

### Defensive Perspective
*   **Kernel Visibility:** AV/EDR solutions operate at the kernel level (Ring 0). Even if a process attempts to restrict access from other user-mode processes, the kernel-level driver maintains full visibility into the process's memory, threads, and handles.
*   **Anti-Tampering:** Modern security products include robust anti-tampering mechanisms to prevent their own processes and drivers from being disabled or bypassed.

## 5. Modern Detection: ETW and Beyond

Modern security engineering focuses on **Event Tracing for Windows (ETW)**, specifically providers like `Microsoft-Windows-Threat-Intelligence`. These providers allow the kernel to log sensitive operations (like `MiMapWriteableMemory` or `PspCreateThreadInternal`) directly, providing a high-fidelity stream of activity that is difficult to evade using user-mode-only techniques.

---

### Resources for Further Study

*   [Windows Internals (Microsoft Press)](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals)
*   [MITRE ATT&CK® - Process Injection (T1055)](https://attack.mitre.org/techniques/T1055/)
*   [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/)
