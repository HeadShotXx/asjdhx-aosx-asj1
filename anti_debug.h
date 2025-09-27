#ifndef ANTI_DEBUG_H
#define ANTI_DEBUG_H

#include <vector>
#include <numeric>
#include <algorithm>
#include <random>

#if defined(_WIN32)
#include <windows.h>
#include <intrin.h>
#elif defined(__linux__)
#include <sys/ptrace.h>
#include <fstream>
#include <string>
#include <streambuf>
#include <cstdlib>
#endif

// All implementation details are hidden within this anonymous namespace.
// Functions are marked 'static inline' to prevent multiple-definition
// linker errors if this header is included in multiple source files.
namespace {
namespace AntiDebug {

#if defined(_WIN32)
    // --- Basic Windows Check Implementations ---
    static inline bool checkIsDebuggerPresent() {
        return IsDebuggerPresent();
    }

    #if defined(_MSC_VER)
        #if !defined(_WIN64)
        static inline bool checkPEB() {
            BOOL found = FALSE;
            __asm {
                mov eax, fs:[0x30]
                mov al, [eax + 0x2]
                mov found, al
            }
            return found;
        }
        #else
        static inline bool checkPEB() { return false; } // MSVC x64 doesn't support this inline asm
        #endif
    #elif defined(__GNUC__)
    static inline bool checkPEB() {
        BOOL found = FALSE;
        #if defined(_WIN64)
            asm volatile ( "movq %%gs:0x60, %%rax\n\t" "movzbl 0x2(%%rax), %%eax\n\t" "movl %%eax, %0" : "=r" (found) : : "rax" );
        #else
            asm volatile ( "movl %%fs:0x30, %%eax\n\t" "movzbl 0x2(%%eax), %%eax\n\t" "movl %%eax, %0" : "=r" (found) : : "eax" );
        #endif
        return found;
    }
    #else
    static inline bool checkPEB() { return false; }
    #endif

    static inline bool checkTiming() {
        ULONGLONG t1 = __rdtsc();
        for (int i = 0; i < 1000; ++i) { volatile int x = i; }
        ULONGLONG t2 = __rdtsc();
        return (t2 - t1) > 500000; // Arbitrary threshold
    }

    #if defined(_MSC_VER) && !defined(_WIN64)
    static inline bool checkInt3() {
        __try { __asm int 3; return true; }
        __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
    }
    #endif

    // --- Advanced Windows Check Implementations ---
    static inline bool checkHardwareBreakpoints() {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            return ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0;
        }
        return false;
    }

    static inline bool checkNtGlobalFlag() {
        DWORD ntGlobalFlag = 0;
        #if defined(_WIN64)
            ntGlobalFlag = *(DWORD*)(__readgsqword(0x60) + 0xBC);
        #else
            ntGlobalFlag = *(DWORD*)(__readfsdword(0x30) + 0x68);
        #endif
        return (ntGlobalFlag & 0x70) != 0;
    }

    static inline bool checkCloseHandle() {
        #if defined(_MSC_VER)
        __try { CloseHandle((HANDLE)0xDEADBEEF); }
        __except(EXCEPTION_EXECUTE_HANDLER) { return true; }
        #endif
        return false;
    }

#elif defined(__linux__)
    // --- Linux Check Implementations ---
    static inline bool checkPtrace() {
        if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
            return true;
        }
        ptrace(PTRACE_DETACH, 0, 1, 0);
        return false;
    }

    static inline bool checkTracerPid() {
        std::ifstream status_file("/proc/self/status");
        if (!status_file) return false;
        std::string line;
        while (std::getline(status_file, line)) {
            if (line.rfind("TracerPid:", 0) == 0) {
                if (line.find("TracerPid:\t0") == std::string::npos) {
                    return true;
                }
                break;
            }
        }
        return false;
    }

    // --- Advanced Linux Check Implementations ---
    static inline bool checkProcMaps() {
        std::ifstream maps_file("/proc/self/maps");
        if (!maps_file) return false;

        const std::vector<std::string> suspicious_libs = {
            "gdb", "strace", "ida", "ollydbg", "radare", "x64dbg"
        };

        std::string line;
        while (std::getline(maps_file, line)) {
            for (const auto& lib : suspicious_libs) {
                if (line.find(lib) != std::string::npos) {
                    return true;
                }
            }
        }
        return false;
    }

    static inline bool checkLdPreload() {
        if (getenv("LD_PRELOAD")) {
            return true;
        }
        return false;
    }
#endif

} // namespace AntiDebug
} // anonymous namespace

// This is the single public-facing function.
// It is also marked 'static inline' to allow it to be defined in the header.
static inline bool CheckForDebugger() {
    // Create a vector of function pointers to our checks
    std::vector<bool(*)()> checks;

#if defined(_WIN32)
    checks.push_back(AntiDebug::checkIsDebuggerPresent);
    checks.push_back(AntiDebug::checkPEB);
    checks.push_back(AntiDebug::checkTiming);
    checks.push_back(AntiDebug::checkNtGlobalFlag);
    checks.push_back(AntiDebug::checkHardwareBreakpoints);
    checks.push_back(AntiDebug::checkCloseHandle);
    #if defined(_MSC_VER) && !defined(_WIN64)
    // checks.push_back(AntiDebug::checkInt3);
    #endif
#elif defined(__linux__)
    checks.push_back(AntiDebug::checkPtrace);
    checks.push_back(AntiDebug::checkTracerPid);
    checks.push_back(AntiDebug::checkProcMaps);
    checks.push_back(AntiDebug::checkLdPreload);
#endif

    // Shuffle the checks to run in a random order to make analysis harder
    auto rd = std::random_device {};
    auto rng = std::default_random_engine { rd() };
    std::shuffle(std::begin(checks), std::end(checks), rng);

    // Execute the checks
    for (const auto& check : checks) {
        if (check()) {
            return true; // Debugger detected
        }
    }

    return false;
}

#endif // ANTI_DEBUG_H