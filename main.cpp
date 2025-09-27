#include <iostream>
#include "anti_debug.h"

// A placeholder for a critical function in your application.
// For example, this could be a function that validates a license key,
// decrypts data, or establishes a connection to a secure server.
bool PerformCriticalTask() {
    // In a real application, this function would perform some vital work.
    // We'll just return true to indicate success.
    return true;
}

int main(int argc, char* argv[]) {
#if defined(_WIN32)
    // --- Harden the application against tampering ---
    // These should be called as early as possible in the application's lifecycle.

    // Prevent other processes from injecting DLLs using CreateRemoteThread.
    // This is a one-time setup.
    PreventRemoteThreadCreation();
    std::cout << "Anti-injection enabled." << std::endl;

    // Restore critical system DLLs to their original state from disk,
    // removing any API hooks that may have been placed. This can be called
    // at multiple, unpredictable points in the code.
    UnhookCriticalAPIs();
    std::cout << "System DLLs unhooked." << std::endl;
#endif

    // --- Subtle Anti-Debugging Consequence ---
    // Instead of exiting immediately, we'll make the program behave
    // in an unexpected but non-obvious way if a debugger is found.

    if (CheckForDebugger()) {
        // A debugger was detected.
        // We won't print a message. Instead, we'll cause a critical task to fail.
        // An attacker stepping through the code will see PerformCriticalTask() return false,
        // and will likely assume the bug is in that function, not in an anti-debug check
        // that was called much earlier.
        std::cout << "Critical task failed. Please check your configuration." << std::endl;
        return 1;
    }

    // No debugger detected, proceed as normal.
    std::cout << "Performing critical task..." << std::endl;
    if (PerformCriticalTask()) {
        std::cout << "Critical task completed successfully." << std::endl;
        std::cout << "Application running normally." << std::endl;
    } else {
        // This path should not be taken unless there is a real failure.
        std::cout << "Critical task failed unexpectedly." << std::endl;
        return 1;
    }

    return 0;
}