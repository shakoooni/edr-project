pub mod region;
use sha2::{Sha256, Digest};

/// Analysis result for a memory region
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegionAnalysis {
    /// SHA256 hash of region
    pub sha256: [u8; 32],
    /// Shannon entropy (0.0-8.0 typical)
    pub entropy: f32,
    /// True if region is anonymous
    pub is_anonymous: bool,
    /// True if region has PE header (MZ)
    pub has_pe_header: bool,
    /// True if region contains syscall stub pattern
    pub contains_syscalls: bool,
    /// True if region is not backed by file
    pub has_no_backing_file: bool,
    /// True if region differs from previous scan
    pub diffed_from_last_scan: bool,
    /// Entropy score scaled (0-20)
    pub compressed_entropy_score: f32,
}

/// Analyze a memory region's contents for EDR heuristics.
pub fn analyze_region(data: &[u8], previous_hash: Option<[u8; 32]>) -> RegionAnalysis {
    let sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    };
    let entropy = {
        let mut counts = [0usize; 256];
        for &b in data { counts[b as usize] += 1; }
        let len = data.len() as f32;
        if len == 0.0 { 0.0 } else {
            let mut e = 0.0f32;
            for &c in &counts {
                if c == 0 { continue; }
                let p = c as f32 / len;
                e -= p * p.log2();
            }
            e
        }
    };
    let has_pe_header = data.len() > 2 && data[0] == 0x4D && data[1] == 0x5A; // 'MZ'
    let contains_syscalls = data.windows(6).any(|w| w == [0x4C,0x8B,0xD1,0xB8,0x00,0x00]); // e.g., mov r10, rcx; syscall (x64)
    let diffed_from_last_scan = previous_hash.map_or(false, |prev| prev != sha256);
    let compressed_entropy_score = (entropy / 8.0 * 20.0).min(20.0);
    RegionAnalysis {
        sha256,
        entropy,
        is_anonymous: false, // set by caller
        has_pe_header,
        contains_syscalls,
        has_no_backing_file: false, // set by caller
        diffed_from_last_scan,
        compressed_entropy_score,
    }
}




use serde::{Serialize, Deserialize};
use thiserror::Error;

/// Represents a process in the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub name: String,
}

/// Represents a memory region in a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Start address
    pub start: u64,
    /// End address
    pub end: u64,
    /// Permissions (e.g., rwx)
    pub perms: String,
    /// Is anonymous (not backed by file)
    pub is_anonymous: bool,
    /// Path to backing file, if any
    pub file_path: Option<String>,
}

/// Errors for process scanning.
#[derive(Error, Debug)]
pub enum ProcessScanError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Permission denied for pid {0}")]
    PermissionDenied(u32),
}

/// Cross-platform trait for memory scanning.
pub trait MemoryScanner {
    /// List all processes.
    fn list_processes() -> Result<Vec<ProcessInfo>, ProcessScanError>;
    /// Scan memory regions for a process.
    fn scan_memory(pid: u32) -> Result<Vec<MemoryRegion>, ProcessScanError>;
}

/// Linux implementation of MemoryScanner.
#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;
    use std::fs;
    use std::io::{BufRead, BufReader};

    /// Read a memory region from /proc/[pid]/mem (Linux only).


    /// Linux memory scanner implementation.
    pub struct LinuxScanner;

    impl MemoryScanner for LinuxScanner {
        fn list_processes() -> Result<Vec<ProcessInfo>, ProcessScanError> {
            let mut procs = Vec::new();
            for entry in fs::read_dir("/proc")? {
                let entry = entry?;
                let file_name = entry.file_name();
                if let Ok(pid) = file_name.to_string_lossy().parse::<u32>() {
                    let cmdline_path = format!("/proc/{}/comm", pid);
                    let name = match fs::read_to_string(&cmdline_path) {
                        Ok(n) => n.trim().to_string(),
                        Err(_) => "unknown".to_string(),
                    };
                    procs.push(ProcessInfo { pid, name });
                }
            }
            Ok(procs)
        }

        fn scan_memory(pid: u32) -> Result<Vec<MemoryRegion>, ProcessScanError> {
            let maps_path = format!("/proc/{}/maps", pid);
            let file = fs::File::open(&maps_path)
                .map_err(|e| if e.kind() == std::io::ErrorKind::PermissionDenied {
                    ProcessScanError::PermissionDenied(pid)
                } else {
                    ProcessScanError::Io(e)
                })?;
            let reader = BufReader::new(file);
            let mut regions = Vec::new();
            for line in reader.lines() {
                let line = line?;
                let mut parts = line.split_whitespace();
                let addr = parts.next().ok_or_else(|| ProcessScanError::Parse(line.clone()))?;
                let perms = parts.next().unwrap_or("").to_string();
                let _offset = parts.next();
                let _dev = parts.next();
                let _inode = parts.next();
                let file_path = parts.next().map(|s| s.to_string());
                let mut addr_parts = addr.split('-');
                let start = match addr_parts.next() {
                    Some(s) => u64::from_str_radix(s, 16).unwrap_or(0),
                    None => 0,
                };
                let end = match addr_parts.next() {
                    Some(s) => u64::from_str_radix(s, 16).unwrap_or(0),
                    None => 0,
                };
                let is_anonymous = file_path.is_none();
                regions.push(MemoryRegion {
                    start,
                    end,
                    perms,
                    is_anonymous,
                    file_path,
                });
            }
            Ok(regions)
        }
    }

    impl LinuxScanner {
        /// Publicly expose process listing for use in agent
        pub fn list_processes() -> Result<Vec<ProcessInfo>, ProcessScanError> {
            <Self as MemoryScanner>::list_processes()
        }
        pub fn scan_memory(pid: u32) -> Result<Vec<MemoryRegion>, ProcessScanError> {
            <Self as MemoryScanner>::scan_memory(pid)
        }
    }

    /// Scan and analyze all memory regions for a process, returning analysis results.
    pub fn scan_and_analyze(pid: u32) -> Result<Vec<(MemoryRegion, RegionAnalysis)>, ProcessScanError> {
        let regions = LinuxScanner::scan_memory(pid)?;
        let mut results = Vec::new();
        for region in &regions {
            // Only scan RX/RWX regions, skip others for stealth/perf
            if !region.perms.contains('x') { continue; }
            let data = match region::read_region(pid, region.start, region.end) {
                Ok(d) => d,
                Err(_) => continue, // skip unreadable
            };
            let mut analysis = analyze_region(&data, None);
            analysis.is_anonymous = region.is_anonymous;
            analysis.has_no_backing_file = region.file_path.is_none();
            results.push((region.clone(), analysis));
        }
        Ok(results)
    }
}

