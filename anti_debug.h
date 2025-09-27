#ifndef ANTI_DEBUG_H
#define ANTI_DEBUG_H

#if defined(_WIN32)
#include <windows.h>
#include <intrin.h>

// Technique 1: IsDebuggerPresent()
// Works on both MSVC and g++
bool checkIsDebuggerPresent() {
    return IsDebuggerPresent();
}

// Technique 2: Check PEB BeingDebugged flag
#if defined(_MSC_VER) // For MSVC
bool checkPEB() {
    BOOL found = FALSE;
    __asm {
        mov eax, fs:[0x30]    // PEB
        mov al, [eax + 0x2] // BeingDebugged
        mov found, al
    }
    return found;
}
#elif defined(__GNUC__) // For g++ (MinGW)
bool checkPEB() {
    BOOL found = FALSE;
    // This inline assembly is for 32-bit. For 64-bit, gs segment would be used.
    asm volatile (
        "movl %%fs:0x30, %%eax\n\t"
        "movb 0x2(%%eax), %%al\n\t"
        "movb %%al, %0"
        : "=r" (found)
        :
        : "eax"
    );
    return found;
}
#else
// Fallback for other compilers on Windows
bool checkPEB() { return false; }
#endif

// Technique 3: RDTSC timing check
// Works on both MSVC and g++
bool checkTiming() {
    ULONGLONG t1 = __rdtsc();
    // A debugger will cause a significant delay between two __rdtsc calls
    // This is just a placeholder; a real implementation would need calibration
    for (int i = 0; i < 100; ++i) {
        volatile int x = i;
    }
    ULONGLONG t2 = __rdtsc();
    return (t2 - t1) > 100000; // Threshold needs calibration
}

// Technique 4: INT 3 exception check
// This uses Structured Exception Handling, which is specific to MSVC.
// It is disabled for g++ builds.
#if defined(_MSC_VER)
bool checkInt3() {
    __try {
        __asm int 3;
        // If the debugger handles the exception, this line will be skipped
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // If our handler catches it, no debugger is present
        return false;
    }
}
#endif

// Main detection function
bool isDebuggerPresent() {
    if (checkIsDebuggerPresent()) return true;
    if (checkPEB()) return true;
    if (checkTiming()) return true;

#if defined(_MSC_VER)
    // if (checkInt3()) return true; // This one is more aggressive, MSVC only
#endif

    return false;
}

#elif defined(__linux__)
#include <sys/ptrace.h>
#include <fstream>
#include <string>
#include <streambuf>

// Technique 1: ptrace(PTRACE_TRACEME)
bool checkPtrace() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        return true;
    }
    // Detach from ourselves if successful
    ptrace(PTRACE_DETACH, 0, 1, 0);
    return false;
}

// Technique 2: Check /proc/self/status for TracerPid
bool checkTracerPid() {
    std::ifstream status_file("/proc/self/status");
    std::string content((std::istreambuf_iterator<char>(status_file)),
                         std::istreambuf_iterator<char>());
    if (content.find("TracerPid:\t0") == std::string::npos) {
        return true;
    }
    return false;
}

bool isDebuggerPresent() {
    if (checkPtrace()) return true;
    if (checkTracerPid()) return true;
    return false;
}

#else
// Unsupported OS
bool isDebuggerPresent() {
    return false;
}
#endif

#endif // ANTI_DEBUG_H