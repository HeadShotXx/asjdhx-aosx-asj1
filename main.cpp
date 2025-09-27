#include <iostream>
#include "anti_vm.h"

int main() {
    std::cout << "--- Anti-VM Detection ---" << std::endl;

    bool cpuid_vm = AntiVM::checkCPUID();
    std::cout << "CPUID check: " << (cpuid_vm ? "VM Detected" : "OK") << std::endl;

    bool mac_vm = AntiVM::checkMACAddress();
    std::cout << "MAC Address check: " << (mac_vm ? "VM Detected" : "OK") << std::endl;

    bool proc_vm = AntiVM::checkProcesses();
    std::cout << "Processes check: " << (proc_vm ? "VM Detected" : "OK") << std::endl;

#if defined(_WIN32)
    bool reg_vm = AntiVM::checkRegistry();
    std::cout << "Registry check: " << (reg_vm ? "VM Detected" : "OK") << std::endl;
#endif

    bool fs_vm = AntiVM::checkFileSystem();
    std::cout << "File System check: " << (fs_vm ? "VM Detected" : "OK") << std::endl;

    std::cout << "-------------------------" << std::endl;

    bool is_vm = AntiVM::isVM();
    if (is_vm) {
        std::cout << "Overall result: A Virtual Machine has been detected." << std::endl;
    } else {
        std::cout << "Overall result: No Virtual Machine detected." << std::endl;
    }

    return 0;
}