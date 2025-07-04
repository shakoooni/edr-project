//! Extreme EDR Test Harness: Simulates massive-scale, nation-state level evasion and stress.
// WARNING: This will heavily stress your system. Use with caution.

use std::thread;
use std::time::{Duration, Instant};
use std::process::{Command, Stdio};
use rand::{Rng, seq::SliceRandom};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::ffi::CString;

#[cfg(target_os = "linux")]
fn set_process_name(name: &str) {
    use libc::prctl;
    const PR_SET_NAME: libc::c_int = 15;
    let cname = CString::new(name).unwrap_or_default();
    unsafe {
        prctl(PR_SET_NAME, cname.as_ptr() as usize, 0, 0, 0);
    }
}

#[cfg(not(target_os = "linux"))]
fn set_process_name(_name: &str) {}

fn random_name() -> String {
    let names = [
        "[kworker/u:6]", "[rcu_sched]", "[migration/0]", "[bioset]", "[kswapd0]",
        "[systemd]", "[dbus-daemon]", "[sshd]", "[bash]", "[Xorg]",
        "[udevd]", "[irq/16-ehci_hcd]", "[watchdog/0]", "[jbd2/sda1-8]", "[ext4-rsv-conver]"
    ];
    names.choose(&mut rand::thread_rng()).unwrap().to_string()
}

fn main() {
    let running = Arc::new(AtomicBool::new(true));
    let mut handles = vec![];
    let start = Instant::now();
    let thread_count = 128;
    let process_count = 32;
    let mem_regions_per_thread = 32;
    let file_count = 128;

    // 1. Massive concurrency: threads with random names and memory patterns
    for _ in 0..thread_count {
        let running = running.clone();
        handles.push(thread::spawn(move || {
            set_process_name(&random_name());
            let mut regions: Vec<&'static mut [u8]> = vec![];
            for _ in 0..mem_regions_per_thread {
                let mut region = vec![0u8; 256 * 1024];
                rand::thread_rng().fill(&mut region[..]);
                for b in &mut region { *b ^= 0xAA; }
                let leaked: &'static mut [u8] = Box::leak(region.into_boxed_slice());
                regions.push(leaked);
            }
            while running.load(Ordering::Relaxed) {
                // Mutate memory
                for region in &mut regions {
                    rand::thread_rng().fill(&mut region[..]);
                }
                thread::sleep(Duration::from_millis(rand::thread_rng().gen_range(10..100)));
            }
        }));
    }

    // 2. Rapid process creation/termination
    handles.push(thread::spawn({
        let running = running.clone();
        move || {
            while running.load(Ordering::Relaxed) {
                for _ in 0..process_count {
                    let child = Command::new("/bin/true")
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn();
                    if let Ok(mut c) = child {
                        let _ = c.wait();
                    }
                }
            }
        }
    }));

    // 3. Dynamic code loading/unloading in a loop (Linux only)
    #[cfg(target_os = "linux")]
    handles.push(thread::spawn({
        let running = running.clone();
        move || {
            use libc::{dlopen, dlclose, RTLD_NOW};
            let exe = std::env::current_exe().unwrap();
            let cexe = CString::new(exe.to_str().unwrap()).unwrap();
            while running.load(Ordering::Relaxed) {
                unsafe {
                    let handle = dlopen(cexe.as_ptr(), RTLD_NOW);
                    if !handle.is_null() {
                        thread::sleep(Duration::from_millis(10));
                        dlclose(handle);
                    }
                }
            }
        }
    }));

    // 4. Shared memory and file descriptor stress (Linux only)
    #[cfg(target_os = "linux")]
    handles.push(thread::spawn({
        let running = running.clone();
        move || {
            use libc::{shm_open, shm_unlink, ftruncate, O_CREAT, O_RDWR, S_IRUSR, S_IWUSR};
            let mut ids = vec![];
            for i in 0..file_count {
                let name = format!("/edrtestshm_{}", i);
                let cname = CString::new(name.clone()).unwrap();
                unsafe {
                    let fd = shm_open(cname.as_ptr(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
                    if fd >= 0 {
                        ftruncate(fd, 4096);
                        ids.push((fd, name));
                    }
                }
            }
            while running.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(100));
            }
            for (fd, name) in ids {
                unsafe {
                    libc::close(fd);
                    shm_unlink(CString::new(name).unwrap().as_ptr());
                }
            }
        }
    }));

    // 5. Living off the land: launch system tools with odd args
    handles.push(thread::spawn({
        let running = running.clone();
        move || {
            let cmds = ["ls", "cat", "echo", "date", "whoami", "id", "uname"];
            while running.load(Ordering::Relaxed) {
                let cmd = cmds.choose(&mut rand::thread_rng()).unwrap();
                let _ = Command::new(cmd)
                    .arg("--version")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn();
                thread::sleep(Duration::from_millis(rand::thread_rng().gen_range(50..200)));
            }
        }
    }));

    // 6. Obfuscate environment variables
    std::env::set_var("LD_PRELOAD", "/dev/zero");
    std::env::set_var("PATH", "/tmp:/usr/bin:/bin");

    // 7. Main thread: time-based triggers, run for 60 seconds
    println!("[EDR TEST] Extreme test running. This will stress your system for 60 seconds.");
    while start.elapsed().as_secs() < 60 {
        thread::sleep(Duration::from_secs(1));
    }
    running.store(false, Ordering::Relaxed);
    for h in handles { let _ = h.join(); }
    println!("[EDR TEST] Extreme test complete. Sleeping for EDR detection...");
    thread::sleep(Duration::from_secs(30));
}
