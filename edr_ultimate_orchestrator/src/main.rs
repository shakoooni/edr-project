//! EDR Ultimate Orchestrator: Launches all NSA-level test harnesses and attack scripts in parallel.
// WARNING: This will heavily stress your VM. Use only in a safe, isolated environment.

use std::process::{Command, Stdio, Child};
use std::thread;
use std::time::Duration;
use rand::Rng;

fn launch(cmd: &str, args: &[&str]) -> Option<Child> {
    Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()
}

fn main() {
    println!("[ORCH] Launching all EDR adversary tests in parallel...");
    let mut children = vec![];

    // 1. Launch Rust test harnesses
    let harnesses: [(&str, &[&str]); 3] = [
        ("cargo", &["run", "-p", "fake_malware"]),
        ("cargo", &["run", "-p", "edr_test_harness"]),
        ("cargo", &["run", "-p", "edr_kernel_evasion_test"]),
    ];
    for (cmd, args) in harnesses.iter() {
        if let Some(child) = launch(cmd, args) {
            children.push(child);
        }
    }

    // 2. Launch persistence/tampering script
    if let Some(child) = launch("bash", &["scripts/edr_tamper.sh"]) {
        children.push(child);
    }

    // 3. Launch LOTL/fileless attack script
    if let Some(child) = launch("bash", &["scripts/edr_lotl.sh"]) {
        children.push(child);
    }

    // 4. Launch NAS edge case script
    if let Some(child) = launch("bash", &["scripts/edr_nas_stress.sh"]) {
        children.push(child);
    }

    // 5. Launch resource exhaustion script
    if let Some(child) = launch("bash", &["scripts/edr_resource_stress.sh"]) {
        children.push(child);
    }

    // 6. Fuzzing (optional, if set up)
    // if let Some(child) = launch("cargo", &["fuzz", "run", "edr_fuzz_target"]) {
    //     children.push(child);
    // }

    // 7. Wait and randomize
    let duration = rand::thread_rng().gen_range(60..180);
    println!("[ORCH] All tests running. Waiting {} seconds for completion...", duration);
    thread::sleep(Duration::from_secs(duration));

    // 8. Cleanup
    for mut child in children {
        let _ = child.kill();
    }
    println!("[ORCH] Orchestration complete. Check EDR logs and results.");
}
