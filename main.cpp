#include <iostream>
#include "anti_debug.h"

int main() {
    if (isDebuggerPresent()) {
        std::cout << "Debugger detected. Exiting." << std::endl;
        return 1;
    }

    std::cout << "No debugger detected. Running application." << std::endl;
    // Your application logic here
    return 0;
}