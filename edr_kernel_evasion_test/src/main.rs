//! EDR Kernel Evasion Detection Test
// Attempts to detect hidden processes and memory regions using multiple methods.
// This is a userland-only, safe test. No kernel code is loaded or executed.

use std::fs;
use std::collections::HashSet;
use libc::{syscall, SYS_getdents64};
use std::ffi::CStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::io::Read;

fn list_proc_pids_via_proc() -> HashSet<u32> {
    let mut pids = HashSet::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(fname) = entry.file_name().into_string() {
                if let Ok(pid) = fname.parse::<u32>() {
                    pids.insert(pid);
                }
            }
        }
    }
    pids
}

fn list_proc_pids_via_syscall() -> HashSet<u32> {
    use std::fs::File;
    use std::mem::{size_of, MaybeUninit};
    use libc::dirent64;
    let mut pids = HashSet::new();
    let file = File::open("/proc").expect("open /proc");
    let fd = file.as_raw_fd();
    let mut buf = vec![0u8; 4096];
    loop {
        let nread = unsafe {
            syscall(
                SYS_getdents64,
                fd,
                buf.as_mut_ptr(),
                buf.len()
            )
        } as isize;
        if nread <= 0 { break; }
        let mut bpos = 0;
        while bpos < nread as usize {
            let d = unsafe { &*(buf[bpos..].as_ptr() as *const dirent64) };
            let name = unsafe { CStr::from_ptr(d.d_name.as_ptr()) };
            if let Ok(s) = name.to_str() {
                if let Ok(pid) = s.parse::<u32>() {
                    pids.insert(pid);
                }
            }
            bpos += d.d_reclen as usize;
        }
    }
    pids
}

fn main() {
    println!("[EDR KERNEL TEST] Enumerating processes via /proc and syscall...");
    let pids_proc = list_proc_pids_via_proc();
    let pids_syscall = list_proc_pids_via_syscall();
    let missing: Vec<_> = pids_syscall.difference(&pids_proc).collect();
    let extra: Vec<_> = pids_proc.difference(&pids_syscall).collect();
    println!("[EDR KERNEL TEST] PIDs in syscall but not /proc: {:?}", missing);
    println!("[EDR KERNEL TEST] PIDs in /proc but not syscall: {:?}", extra);
    if !missing.is_empty() {
        println!("[EDR KERNEL TEST] WARNING: Possible hidden processes detected!");
    } else {
        println!("[EDR KERNEL TEST] No hidden processes detected.");
    }
    // Optionally, add memory region cross-checks here
}
