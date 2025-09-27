#include "anti_debug.h"
#include "anti_debug_internal.h"
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

// Forward declare all check functions from the internal header
namespace AntiDebug {
    // Basic Checks
    bool checkIsDebuggerPresent();
    bool checkPEB();
    bool checkTiming();
    #if defined(_MSC_VER) && !defined(_WIN64)
    bool checkInt3();
    #endif

    // Advanced Windows Checks
    #if defined(_WIN32)
    bool checkHardwareBreakpoints();
    bool checkNtGlobalFlag();
    bool checkCloseHandle();
    #endif

    // Linux Checks
    #if defined(__linux__)
    bool checkPtrace();
    bool checkTracerPid();
    bool checkProcMaps();
    bool checkLdPreload();
    #endif
}

// The main function exposed in the public API
bool CheckForDebugger() {
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
    // checks.push_back(AntiDebug::checkInt3); // Still too aggressive for default
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

// ---- Implementations of the actual checks ----

namespace AntiDebug {

#if defined(_WIN32)
    // --- Basic Windows Check Implementations ---
    bool checkIsDebuggerPresent() {
        return IsDebuggerPresent();
    }

    #if defined(_MSC_VER)
        #if !defined(_WIN64)
        bool checkPEB() {
            BOOL found = FALSE;
            __asm {
                mov eax, fs:[0x30]
                mov al, [eax + 0x2]
                mov found, al
            }
            return found;
        }
        #else
        bool checkPEB() { return false; } // MSVC x64 doesn't support this inline asm
        #endif
    #elif defined(__GNUC__)
    bool checkPEB() {
        BOOL found = FALSE;
        #if defined(_WIN64)
            asm volatile ( "movq %%gs:0x60, %%rax\n\t" "movzbl 0x2(%%rax), %%eax\n\t" "movl %%eax, %0" : "=r" (found) : : "rax" );
        #else
            asm volatile ( "movl %%fs:0x30, %%eax\n\t" "movzbl 0x2(%%eax), %%eax\n\t" "movl %%eax, %0" : "=r" (found) : : "eax" );
        #endif
        return found;
    }
    #else
    bool checkPEB() { return false; }
    #endif

    bool checkTiming() {
        ULONGLONG t1 = __rdtsc();
        for (int i = 0; i < 1000; ++i) { volatile int x = i; }
        ULONGLONG t2 = __rdtsc();
        return (t2 - t1) > 500000; // Arbitrary threshold
    }

    #if defined(_MSC_VER) && !defined(_WIN64)
    bool checkInt3() {
        __try { __asm int 3; return true; }
        __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
    }
    #endif

    // --- Advanced Windows Check Implementations ---
    bool checkHardwareBreakpoints() {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            return ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0;
        }
        return false;
    }

    bool checkNtGlobalFlag() {
        DWORD ntGlobalFlag = 0;
        #if defined(_WIN64)
            ntGlobalFlag = *(DWORD*)(__readgsqword(0x60) + 0xBC);
        #else
            ntGlobalFlag = *(DWORD*)(__readfsdword(0x30) + 0x68);
        #endif
        return (ntGlobalFlag & 0x70) != 0;
    }

    bool checkCloseHandle() {
        #if defined(_MSC_VER)
        __try { CloseHandle((HANDLE)0xDEADBEEF); }
        __except(EXCEPTION_EXECUTE_HANDLER) { return true; }
        #endif
        return false;
    }

#elif defined(__linux__)
    // --- Linux Check Implementations ---
    bool checkPtrace() {
        if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
            return true;
        }
        ptrace(PTRACE_DETACH, 0, 1, 0);
        return false;
    }

    bool checkTracerPid() {
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
    bool checkProcMaps() {
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

    bool checkLdPreload() {
        // getenv is not thread-safe, but in this context it's acceptable.
        if (getenv("LD_PRELOAD")) {
            return true;
        }
        return false;
    }
#endif

} // namespace AntiDebug