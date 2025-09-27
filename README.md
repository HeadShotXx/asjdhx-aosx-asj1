# Advanced Professional Anti-Debugging (Header-Only)

This repository contains a single-header C++ library for several basic and advanced anti-debugging and anti-tampering techniques for both Windows and Linux.

The project is a header-only library, which makes it incredibly easy to integrate. Just drop the `anti_debug.h` file in your project and include it.

## Structure

*   `anti_debug.h`: A single, self-contained, header-only library. It contains all the logic, including the advanced checks and the randomized calling mechanism.
*   `main.cpp`: An example program demonstrating how to use the library's functions.

## Compilation

### Windows with MSVC (Visual Studio)
The necessary libraries are linked automatically via a `#pragma` directive.
```bash
cl /EHsc main.cpp
```

### Windows with MinGW (g++)
The new anti-injection features require linking against the `advapi32` library.
```bash
g++ main.cpp -o main.exe -ladvapi32
```

### Linux (with g++)
```bash
g++ main.cpp -o main
```

## Anti-Debugging Features
The library can detect debuggers using a variety of techniques, which are called in a random order to make them harder to bypass.

### Windows
*   `IsDebuggerPresent()`: Standard WinAPI check.
*   PEB `BeingDebugged` Flag: Checks the flag in the Process Environment Block.
*   Timing Check (`RDTSC`): Detects slowdowns caused by debugger single-stepping.
*   **Hardware Breakpoints**: Checks CPU debug registers (`Dr0`-`Dr3`).
*   **`NtGlobalFlag`**: Checks a more obscure flag in the PEB.
*   **`CloseHandle` Exception Trick**: An exception-based check that behaves differently under a debugger. (MSVC only)

### Linux
*   `ptrace(PTRACE_TRACEME)`: The classic `ptrace` self-attachment trick.
*   `/proc/self/status` `TracerPid`: Checks if a process is tracing the current one.
*   **`/proc/self/maps` Scan**: Scans memory maps for names of common debuggers.
*   **`LD_PRELOAD` Check**: Checks for the `LD_PRELOAD` environment variable.

## Anti-Tampering Features (Windows Only)

### API Unhooking (`UnhookCriticalAPIs`)
This function provides powerful protection against API hooking, a technique used by many analysis tools to intercept function calls.
*   **How it works**: It reads the clean `.text` section (the executable code) from the original `ntdll.dll` and `kernel32.dll` files on disk and uses it to overwrite the versions currently loaded in memory. This instantly and forcefully removes any inline hooks that have been placed on functions within those libraries.

### DLL Injection Prevention (`PreventRemoteThreadCreation`)
This function hardens the application against the most common form of DLL injection.
*   **How it works**: It modifies the security permissions (DACL) of the application's own process at runtime. It adds a rule that explicitly denies other processes the `PROCESS_CREATE_THREAD` permission, which is required by the `CreateRemoteThread` function. This effectively slams the door on tools that rely on this method for injection.

**Disclaimer**: These anti-tampering features are very powerful and may conflict with legitimate software that uses hooks, such as antivirus programs, performance monitors, or screen recording software. Test thoroughly in your target environment.