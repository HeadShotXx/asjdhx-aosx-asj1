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
    // Note: The __asm block is only supported for x86 (32-bit) builds in MSVC.
    // For x64, this check will not be compiled.
    #if !defined(_WIN64)
    bool checkPEB() {
        BOOL found = FALSE;
        __asm {
            mov eax, fs:[0x30]    // PEB
            mov al, [eax + 0x2] // BeingDebugged
            mov found, al
        }
        return found;
    }
    #else
    // On MSVC x64, this check is more complex. We'll skip it.
    bool checkPEB() { return false; }
    #endif
#elif defined(__GNUC__) // For g++ (MinGW)
    bool checkPEB() {
        BOOL found = FALSE;
        #if defined(_WIN64)
            // 64-bit g++
            asm volatile (
                "movq %%gs:0x60, %%rax\n\t"     // Get PEB from GS segment
                "movzbl 0x2(%%rax), %%eax\n\t"  // Get BeingDebugged byte and zero-extend to 32-bits in EAX
                "movl %%eax, %0"               // Store result in 'found'
                : "=r" (found)
                :
                : "rax"
            );
        #else
            // 32-bit g++
            asm volatile (
                "movl %%fs:0x30, %%eax\n\t"     // Get PEB from FS segment
                "movzbl 0x2(%%eax), %%eax\n\t"  // Get BeingDebugged byte and zero-extend to 32-bits in EAX
                "movl %%eax, %0"               // Store result in 'found'
                : "=r" (found)
                :
                : "eax"
            );
        #endif
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
    for (int i = 0; i < 1000; ++i) { // Increased loop for better timing
        volatile int x = i;
    }
    ULONGLONG t2 = __rdtsc();
    // This threshold is arbitrary and needs calibration for a real system.
    return (t2 - t1) > 500000;
}

// Technique 4: INT 3 exception check
// This uses Structured Exception Handling, which is specific to MSVC.
#if defined(_MSC_VER) && !defined(_WIN64)
bool checkInt3() {
    __try {
        __asm int 3;
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
#endif

// Main detection function
bool isDebuggerPresent() {
    if (checkIsDebuggerPresent()) return true;
    if (checkPEB()) return true;
    if (checkTiming()) return true;

#if defined(_MSC_VER) && !defined(_WIN64)
    // if (checkInt3()) return true; // This one is more aggressive, MSVC x86 only
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
    ptrace(PTRACE_DETACH, 0, 1, 0);
    return false;
}

// Technique 2: Check /proc/self/status for TracerPid
bool checkTracerPid() {
    std::ifstream status_file("/proc/self/status");
    if (!status_file) return false;
    std::string line;
    while (std::getline(status_file, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            // If TracerPid is not 0, a debugger is attached.
            if (line.find("TracerPid:\t0") == std::string::npos) {
                return true;
            }
            break;
        }
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