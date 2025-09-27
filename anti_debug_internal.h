#ifndef ANTI_DEBUG_INTERNAL_H
#define ANTI_DEBUG_INTERNAL_H

// This is a private header. Do not include it directly in your application.
// It contains the declarations for the individual anti-debugging checks.

namespace AntiDebug {

// --- Basic Checks ---
bool checkIsDebuggerPresent();
bool checkPEB();
bool checkTiming();

#if defined(_MSC_VER) && !defined(_WIN64)
bool checkInt3();
#endif

#if defined(__linux__)
bool checkPtrace();
bool checkTracerPid();
#endif

// --- Advanced Checks (to be implemented) ---
#if defined(_WIN32)
bool checkHardwareBreakpoints();
bool checkNtGlobalFlag();
bool checkCloseHandle();
#elif defined(__linux__)
bool checkProcMaps();
bool checkLdPreload();
#endif

} // namespace AntiDebug

#endif // ANTI_DEBUG_INTERNAL_H