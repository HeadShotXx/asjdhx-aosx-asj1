#include "anti_sandbox.h"
#include <iostream>

int main() {
    bool is_sandboxed = false;

    if (AntiSandbox::check_cpuid()) {
        std::cout << "Sandbox detected: CPUID hypervisor bit is set." << std::endl;
        is_sandboxed = true;
    }

    if (AntiSandbox::check_timing()) {
        std::cout << "Sandbox detected: Timing anomaly detected." << std::endl;
        is_sandboxed = true;
    }

    if (AntiSandbox::check_ram()) {
        std::cout << "Sandbox detected: Low RAM detected." << std::endl;
        is_sandboxed = true;
    }

    if (AntiSandbox::check_mac_address()) {
        std::cout << "Sandbox detected: VM MAC address detected." << std::endl;
        is_sandboxed = true;
    }

#ifdef _WIN32
    if (AntiSandbox::check_hardware_names()) {
        std::cout << "Sandbox detected: VM hardware names found." << std::endl;
        is_sandboxed = true;
    }

    if (AntiSandbox::check_registry_keys()) {
        std::cout << "Sandbox detected: VM registry keys found." << std::endl;
        is_sandboxed = true;
    }

    if (AntiSandbox::check_vm_files()) {
        std::cout << "Sandbox detected: VM files found." << std::endl;
        is_sandboxed = true;
    }
#else
    if (AntiSandbox::check_linux_artifacts()) {
        std::cout << "Sandbox detected: Linux VM artifacts found." << std::endl;
        is_sandboxed = true;
    }
#endif

    if (AntiSandbox::check_running_processes()) {
        std::cout << "Sandbox detected: Analysis tools running." << std::endl;
        is_sandboxed = true;
    }

    if (!is_sandboxed) {
        std::cout << "Environment appears to be clean." << std::endl;
    }

    return 0;
}