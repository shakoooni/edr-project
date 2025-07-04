//! Integration tests for process crate (Linux only)

#[cfg(target_os = "linux")]
mod linux_tests {
    use process::linux::LinuxScanner;
    use process::region::read_region;
    use process::MemoryScanner;

    #[test]
    fn test_list_processes() {
        let procs = LinuxScanner::list_processes().expect("list_processes failed");
        assert!(!procs.is_empty(), "No processes found");
    }


    #[test]
    fn test_scan_memory() {
        let procs = LinuxScanner::list_processes().expect("list_processes failed");
        // Try to find a process with at least one accessible memory region
        let mut found = false;
        for proc in procs.iter().filter(|p| p.pid > 1) {
            match LinuxScanner::scan_memory(proc.pid) {
                Ok(regions) if !regions.is_empty() => {
                    found = true;
                    break;
                },
                _ => continue,
            }
        }
        assert!(found, "No accessible process with memory regions found");
    }

    #[test]
    fn test_read_region() {
        let procs = LinuxScanner::list_processes().expect("list_processes failed");
        // Find a process that is not PID 1 and likely accessible
        let pid = procs.iter().find(|p| p.pid > 1).map(|p| p.pid).expect("No suitable process found");
        match LinuxScanner::scan_memory(pid) {
            Ok(regions) => {
                if let Some(region) = regions.get(0) {
                    let data = read_region(pid, region.start, region.end);
                    if let Err(e) = data {
                        let msg = format!("{}", e);
                        assert!(msg.contains("Permission denied") || msg.contains("IO error"), "Unexpected error: {}", msg);
                    }
                }
            },
            Err(e) => assert!(format!("{}", e).contains("Permission denied"), "Unexpected error: {}", e),
        }
    }
}
