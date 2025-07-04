




/// Returns true if a debugger is detected (Linux only).
#[cfg(target_os = "linux")]
fn is_debugger_present() -> bool {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("TracerPid:") {
                let val = line.split(':').nth(1).unwrap_or("").trim();
                return val != "0";
            }
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
fn is_debugger_present() -> bool { false }


#[cfg(target_os = "linux")]
fn set_process_name(name: &str) {
    use std::ffi::CString;
    use libc::prctl;
    const PR_SET_NAME: libc::c_int = 15;
    if let Ok(cname) = CString::new(name) {
        // Safe: name is checked, prctl is called with valid args
        unsafe {
            prctl(PR_SET_NAME, cname.as_ptr() as usize, 0, 0, 0);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn set_process_name(_name: &str) {}

/// Main entry point for the EDR agent. Hardened, minimal, and secure.
fn main() {
    // Anti-debugging
    if is_debugger_present() {
        eprintln!("[FATAL] Debugger detected. Exiting.");
        std::process::exit(1);
    }
    // Stealth: process renaming
    set_process_name("[kworker/u:3]");

    // Load config
    let config_path = "configs/config.toml";
    let config = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("[FATAL] Failed to read config");
            std::process::exit(1);
        }
    };
    let scan_interval = config
        .lines()
        .find(|l| l.trim_start().starts_with("scan_interval_seconds"))
        .and_then(|l| l.split('=').nth(1))
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or_else(|| {
            eprintln!("[WARN] scan_interval_seconds not found or invalid, defaulting to 60");
            60
        });
    let log_path = config
        .lines()
        .find(|l| l.trim_start().starts_with("log_path"))
        .and_then(|l| l.split('=').nth(1))
        .map(|v| v.trim().trim_matches('"').to_string())
        .unwrap_or_else(|| {
            eprintln!("[WARN] log_path not found, defaulting to ../logs/edr.log");
            "../logs/edr.log".to_string()
        });

    // Self-integrity check
    const EXPECTED_HASH: Option<&str> = None;
    let exe_path = "/proc/self/exe";
    match utils::file_sha256(exe_path) {
        Ok(hash) => {
            let hash_hex = hex::encode(hash);
            if let Some(expected) = EXPECTED_HASH {
                if !hash_hex.eq_ignore_ascii_case(expected) {
                    eprintln!("[FATAL] Agent binary hash mismatch! Expected: {} Got: {}", expected, hash_hex);
                    std::process::exit(1);
                }
            }
            println!("[INFO] Agent self-integrity hash: {}", hash_hex);
        }
        Err(e) => {
            eprintln!("[WARN] Could not compute self hash: {}", e);
        }
    }

    // Logging and runtime
    if let Err(e) = utils::BinaryLogger::init(&log_path) {
        eprintln!("[FATAL] Failed to init logger: {}", e);
        std::process::exit(1);
    }
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("[FATAL] Failed to build tokio runtime: {}", e);
            std::process::exit(1);
        }
    };
    rt.block_on(agent::run_scan_loop(scan_interval));
}
