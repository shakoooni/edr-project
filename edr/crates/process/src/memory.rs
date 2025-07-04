//! Memory region enumeration and reading (Linux-first)
// Strictly no unsafe unless fully justified and audited
// All syscalls and file reads are checked and fail-closed

use std::fs::{File, read_dir};
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Process {
    pub pid: u32,
    pub exe: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub offset: u64,
    pub dev: String,
    pub inode: u64,
    pub pathname: Option<String>,
}

/// List all processes (Linux: /proc only)
pub fn list_processes() -> std::io::Result<Vec<Process>> {
    let mut procs = Vec::new();
    for entry in read_dir("/proc")? {
        let entry = entry?;
        let fname = entry.file_name();
        if let Ok(pid) = fname.to_string_lossy().parse::<u32>() {
            let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
                .ok()
                .map(|p| p.to_string_lossy().to_string());
            procs.push(Process { pid, exe });
        }
    }
    Ok(procs)
}

/// Parse /proc/[pid]/maps for memory regions
pub fn list_regions(pid: u32) -> std::io::Result<Vec<Region>> {
    let path = format!("/proc/{}/maps", pid);
    let file = File::open(&path)?;
    let reader = BufReader::new(file);
    let mut regions = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let mut parts = line.splitn(6, ' ');
        let addr = parts.next().unwrap_or("");
        let perms = parts.next().unwrap_or("").to_string();
        let offset = parts.next().unwrap_or("0");
        let dev = parts.next().unwrap_or("").to_string();
        let inode = parts.next().unwrap_or("0");
        let pathname = parts.next().map(|s| s.trim().to_string());
        let mut addr_parts = addr.splitn(2, '-');
        let start = u64::from_str_radix(addr_parts.next().unwrap_or("0"), 16).unwrap_or(0);
        let end = u64::from_str_radix(addr_parts.next().unwrap_or("0"), 16).unwrap_or(0);
        let offset = u64::from_str_radix(offset, 16).unwrap_or(0);
        let inode = inode.parse::<u64>().unwrap_or(0);
        regions.push(Region {
            start,
            end,
            perms,
            offset,
            dev,
            inode,
            pathname,
        });
    }
    Ok(regions)
}

/// Read a memory region from /proc/[pid]/mem
pub fn read_region(pid: u32, region: &Region) -> std::io::Result<Vec<u8>> {
    let path = format!("/proc/{}/mem", pid);
    let mut file = File::open(&path)?;
    file.seek(std::io::SeekFrom::Start(region.start))?;
    let size = (region.end - region.start) as usize;
    let mut buf = vec![0u8; size.min(1024 * 1024 * 16)]; // 16MB max read
    let n = file.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}
