# Advanced Professional Anti-Debugging (Header-Only)

This repository contains a single-header C++ library for several basic and advanced anti-debugging techniques for both Windows and Linux.

The project is now a header-only library, which makes it incredibly easy to integrate into any project. Just drop the `anti_debug.h` file in your project and include it.

## Structure

*   `anti_debug.h`: A single, self-contained, header-only library. It contains all the logic, including the advanced checks and the randomized calling mechanism.
*   `main.cpp`: An example program demonstrating how to use the `CheckForDebugger()` function and how to react subtly to a detected debugger.

## Compilation

Since this is now a header-only library, you no longer need to compile multiple source files. The compilation command is much simpler.

### Windows with MSVC (Visual Studio)
Open a "Developer Command Prompt for VS" and run:
```bash
cl /EHsc main.cpp
```

### Windows with MinGW (g++)
Open a command prompt or terminal with `g++` in its path and run:
```bash
g++ main.cpp -o main.exe
```

### Linux (with g++)
```bash
g++ main.cpp -o main
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

The advice from the previous version still stands: **be subtle**. The `main.cpp` provides an excellent example of this. Instead of exiting immediately, it causes a critical function to "fail" later on. An attacker will likely waste time debugging the critical function itself, rather than suspecting an anti-debugging check that ran much earlier.

**The goal is not to be invincible, but to be inconvenient.** By using a layered, subtle, and unpredictable approach, you significantly raise the cost and effort required to reverse-engineer your application.