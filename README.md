# Advanced Professional Anti-Debugging Techniques in C++

This repository contains a C++ implementation of several basic and advanced anti-debugging techniques for both Windows and Linux.

The project is structured to hide implementation details, making it harder to reverse-engineer. The checks are called in a random order to prevent simple, sequential patching by an attacker.

## Structure

*   `anti_debug.h`: The clean, public-facing header. Include this in your project. It exposes a single function: `CheckForDebugger()`.
*   `anti_debug.cpp`: Contains the implementation of all anti-debugging checks and the logic for calling them randomly.
*   `anti_debug_internal.h`: A private header containing the function declarations for the individual checks. Do not include this directly.
*   `main.cpp`: An example program demonstrating how to use the `CheckForDebugger()` function and how to react subtly to a detected debugger.

## Compilation

Because the implementation is now in a separate `.cpp` file, you must include it in the compilation command.

### Windows with MSVC (Visual Studio)
Open a "Developer Command Prompt for VS" and run:
```bash
cl /EHsc main.cpp anti_debug.cpp
```

### Windows with MinGW (g++)
Open a command prompt or terminal with `g++` in its path and run:
```bash
g++ main.cpp anti_debug.cpp -o main.exe
```

### Linux (with g++)
```bash
g++ main.cpp anti_debug.cpp -o main
```

## Implemented Techniques

### Windows (Basic)
*   `IsDebuggerPresent()`: Standard WinAPI check.
*   PEB `BeingDebugged` Flag: Checks the flag in the Process Environment Block.
*   Timing Check (`RDTSC`): Detects slowdowns caused by debugger single-stepping.

### Windows (Advanced)
*   **Hardware Breakpoints**: Checks CPU debug registers (`Dr0`-`Dr3`) for hardware breakpoints.
*   **`NtGlobalFlag`**: Checks a more obscure flag in the PEB that is set by debuggers.
*   **`CloseHandle` Exception Trick**: Uses a structured exception (`__try`/`__except`) on an invalid handle, which behaves differently when a debugger is attached. (MSVC only)

### Linux (Basic)
*   `ptrace(PTRACE_TRACEME)`: The classic `ptrace` self-attachment trick.
*   `/proc/self/status` `TracerPid`: Checks if a process is tracing the current one.

### Linux (Advanced)
*   **`/proc/self/maps` Scan**: Scans the process's own memory maps for the names of common debuggers or analysis tools (e.g., `gdb`, `ida`).
*   **`LD_PRELOAD` Check**: Checks for the presence of the `LD_PRELOAD` environment variable, which is often used to inject hooking libraries.

## How to Use Professionally

The advice from the previous version still stands: **be subtle**. The new `main.cpp` provides a better example of this. Instead of exiting immediately, it causes a critical function to "fail" later on. An attacker will likely waste time debugging the critical function itself, rather than suspecting an anti-debugging check that ran much earlier.

**The goal is not to be invincible, but to be inconvenient.** By using a layered, subtle, and unpredictable approach, you significantly raise the cost and effort required to reverse-engineer your application.