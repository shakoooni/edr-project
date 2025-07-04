use std::fs::OpenOptions;
use std::io::{Read, Seek};
use smallvec::SmallVec;
use crate::ProcessScanError;

/// Read a memory region from /proc/[pid]/mem (Linux only).
pub fn read_region(pid: u32, start: u64, end: u64) -> Result<Vec<u8>, ProcessScanError> {
    let mem_path = format!("/proc/{}/mem", pid);
    let mut file = OpenOptions::new().read(true).open(&mem_path)
        .map_err(|e| if e.kind() == std::io::ErrorKind::PermissionDenied {
            ProcessScanError::PermissionDenied(pid)
        } else {
            ProcessScanError::Io(e)
        })?;
    file.seek(std::io::SeekFrom::Start(start)).map_err(ProcessScanError::Io)?;
    let size = (end - start) as usize;
    // Use stack allocation for small regions, heap for large
    if size <= 4096 {
        let mut buf: SmallVec<[u8; 4096]> = SmallVec::from_elem(0u8, size);
        let n = file.read(&mut buf).map_err(ProcessScanError::Io)?;
        buf.truncate(n);
        Ok(buf.to_vec())
    } else {
        let mut buf = vec![0u8; size.min(1024 * 1024)]; // Limit to 1MB per region for safety
        let n = file.read(&mut buf).map_err(ProcessScanError::Io)?;
        buf.truncate(n);
        Ok(buf)
    }
}
