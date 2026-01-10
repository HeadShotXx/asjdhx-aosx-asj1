//! Signature Monster CLI
//!
//! Command-line interface for the Signature Monster SDK

use signaturemonster::SignatureChecker;

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           SIGNATURE MONSTER SDK - System Info                ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let checker = SignatureChecker::new();

    // HWID Information
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ HARDWARE ID (HWID) INFORMATION                              │");
    println!("└─────────────────────────────────────────────────────────────┘");
    
    if let Ok(info) = checker.hwid.get_all() {
        println!("  Processor ID:      {}", info.processor_id.as_deref().unwrap_or("N/A"));
        println!("  Motherboard:       {}", info.motherboard_serial.as_deref().unwrap_or("N/A"));
        println!("  BIOS Serial:       {}", info.bios_serial.as_deref().unwrap_or("N/A"));
        println!("  System UUID:       {}", info.system_uuid.as_deref().unwrap_or("N/A"));
        println!("  Machine GUID:      {}", info.machine_guid.as_deref().unwrap_or("N/A"));
        println!("  Computer Name:     {}", info.computer_name.as_deref().unwrap_or("N/A"));
    }
    
    if let Ok(hash) = checker.hwid.generate_hwid_hash() {
        println!("  HWID Hash:         {}", hash);
    }
    println!();

    // Windows Information
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ WINDOWS INFORMATION                                         │");
    println!("└─────────────────────────────────────────────────────────────┘");
    
    if let Ok(info) = checker.hwid.get_windows_info() {
        println!("  Windows Name:      {}", info.name.as_deref().unwrap_or("N/A"));
        println!("  Version:           {}", info.version.as_deref().unwrap_or("N/A"));
        println!("  Build:             {}", info.build.as_deref().unwrap_or("N/A"));
        println!("  Display Version:   {}", info.display_version.as_deref().unwrap_or("N/A"));
        println!("  Edition:           {}", info.edition.as_deref().unwrap_or("N/A"));
        println!("  Product ID:        {}", info.product_id.as_deref().unwrap_or("N/A"));
    }
    println!();

    // User Information
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ USER INFORMATION                                            │");
    println!("└─────────────────────────────────────────────────────────────┘");
    
    if let Ok(user) = checker.user.current_username() {
        println!("  Username:          {}", user);
    }
    if let Ok(domain) = checker.user.current_domain() {
        println!("  Domain:            {}", domain);
    }
    if let Ok(home) = checker.user.home_directory() {
        println!("  Home Directory:    {}", home);
    }
    println!("  Is Admin:          {}", checker.user.is_admin());
    println!();

    // Disk Information
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ DISK DRIVE INFORMATION                                      │");
    println!("└─────────────────────────────────────────────────────────────┘");
    
    if let Ok(disks) = checker.disk.list_drives() {
        for (i, disk) in disks.iter().enumerate() {
            println!("  Disk {}:", i);
            println!("    Model:           {}", disk.model.as_deref().unwrap_or("N/A"));
            println!("    Serial:          {}", disk.serial_number.as_deref().unwrap_or("N/A"));
            println!("    Interface:       {}", disk.interface_type.as_deref().unwrap_or("N/A"));
        }
    }
    
    if let Ok(is_vm) = checker.disk.is_virtual() {
        println!("  Virtual Machine:   {}", is_vm);
    }
    println!();

    // Running Processes (sample)
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ RUNNING PROCESSES (first 10)                                │");
    println!("└─────────────────────────────────────────────────────────────┘");
    
    if let Ok(processes) = checker.process.list_processes() {
        for proc in processes.iter().take(10) {
            println!("  [{}] {}", proc.pid, proc.name);
        }
        println!("  ... and {} more", processes.len().saturating_sub(10));
    }
    println!();

    // Open Windows
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ OPEN WINDOWS                                                │");
    println!("└─────────────────────────────────────────────────────────────┘");
    
    if let Ok(windows) = checker.process.list_window_titles() {
        for win in windows.iter().take(10) {
            println!("  [{}] {} - {}", 
                win.pid.unwrap_or(0),
                win.process_name.as_deref().unwrap_or("Unknown"),
                win.main_window_title.as_deref().unwrap_or(""));
        }
        if windows.len() > 10 {
            println!("  ... and {} more", windows.len() - 10);
        }
    }
    println!();

    // Services (sample)
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ RUNNING SERVICES (first 10)                                 │");
    println!("└─────────────────────────────────────────────────────────────┘");
    
    if let Ok(services) = checker.services.list_services() {
        let running: Vec<_> = services.iter()
            .filter(|s| s.state == signaturemonster::services::ServiceState::Running)
            .take(10)
            .collect();
        for svc in &running {
            println!("  {} ({})", svc.name, svc.display_name);
        }
        let total_running = services.iter()
            .filter(|s| s.state == signaturemonster::services::ServiceState::Running)
            .count();
        if total_running > 10 {
            println!("  ... and {} more running", total_running - 10);
        }
    }
    println!();

    // Scheduled Tasks (sample)
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ SCHEDULED TASKS (first 10)                                  │");
    println!("└─────────────────────────────────────────────────────────────┘");
    
    if let Ok(tasks) = checker.tasks.list_tasks() {
        for task in tasks.iter().take(10) {
            println!("  {} [{}]", task.task_name, task.state.as_deref().unwrap_or("Unknown"));
        }
        if tasks.len() > 10 {
            println!("  ... and {} more", tasks.len() - 10);
        }
    }
    println!();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                    Scan Complete                             ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
}
