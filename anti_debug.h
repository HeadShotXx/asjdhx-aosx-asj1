#ifndef ANTI_DEBUG_H
#define ANTI_DEBUG_H

// Call this function at various, unpredictable points in your application.
// It will perform a series of checks to determine if a debugger is present.
// Returns true if a debugger is detected, false otherwise.
bool CheckForDebugger();

#endif // ANTI_DEBUG_H