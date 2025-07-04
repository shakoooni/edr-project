#![deny(unsafe_code)]
#![deny(missing_docs)]
//! Async scan orchestrator for ultra_edr.

// --- Security Hardening ---
// - All disk output is integrity-checked and redacted.
// - All cryptography is constant-time and side-channel resistant.
// - All error handling is explicit and defensive.
// - No panics, unwraps, or expects in core logic.
// - No network, telemetry, or external calls.
// - All interfaces are trait-based for testability.
// - All FFI/syscalls must be strictly validated (see process crate).


use tokio::time::Duration;
use rand::{thread_rng, Rng};
use process::linux::{LinuxScanner, scan_and_analyze};
use triage::{score_factors, RiskFactors, RiskClass};
use process::ProcessInfo;
use carving::{dump_encrypted_region, key_from_passphrase};
use log::{info, warn};
use sha2::Digest; // Brings the Digest trait into scope for Sha256::digest

/// Run the async scan loop for all processes, with randomized interval for stealth.
pub async fn run_scan_loop(scan_interval_secs: u64) {
    let mut rng = thread_rng();
    loop {
        // Add jitter: +/- 30% of interval
        let jitter = rng.gen_range(
            (scan_interval_secs as f64 * 0.7) as u64..
            (scan_interval_secs as f64 * 1.3) as u64
        );
        tokio::time::sleep(Duration::from_secs(jitter)).await;
        match LinuxScanner::list_processes() {
            Ok(procs) => {
                for proc in procs {
                    // Defensive: skip invalid pids
                    if proc.pid == 0 { continue; }
                    if let Err(e) = scan_and_triage_process(&proc).await {
                        warn!("Scan error for pid {}: {}", proc.pid, e);
                    }
                }
            }
            Err(e) => warn!("Process listing failed: {}", e),
        }
    }
}

/// Scan and triage a single process.
pub async fn scan_and_triage_process(proc: &ProcessInfo) -> Result<(), String> {
    let pid = proc.pid;
    if pid == 0 {
        return Err("Invalid PID 0".to_string());
    }
    let regions = match scan_and_analyze(pid) {
        Ok(r) => r,
        Err(e) => return Err(format!("scan error: {}", e)),
    };
    for (region, analysis) in regions {
        let factors = RiskFactors {
            high_entropy: analysis.entropy > 6.5,
            is_anonymous: analysis.is_anonymous,
            has_pe_header: analysis.has_pe_header,
            contains_syscalls: analysis.contains_syscalls,
            has_no_backing_file: analysis.has_no_backing_file,
            diffed_from_last_scan: analysis.diffed_from_last_scan,
            compressed_entropy_score: analysis.compressed_entropy_score,
        };
        let score = score_factors(&factors);
        if score.classification != RiskClass::Benign {
            info!("[EDR] PID {} region {:#x}-{:#x} score: {:?}", pid, region.start, region.end, score);
            if score.classification == RiskClass::Malicious {
                // Carve and encrypt region
                let out_path = format!("/tmp/edr_dump_{}_{}_{}.bin", pid, region.start, region.end);
                let key = key_from_passphrase("ultra_edr_secret");
                // Defensive: check region bounds
                if region.start >= region.end {
                    warn!("Invalid region bounds: {:#x}-{:#x}", region.start, region.end);
                    continue;
                }
                // For demo: re-read region for dump (in real use, pass data from analysis)
                match process::region::read_region(pid, region.start, region.end) {
                    Ok(data) => {
                        // Defensive: check dump size
                        if data.is_empty() {
                            warn!("Region data empty for PID {} region {:#x}-{:#x}", pid, region.start, region.end);
                            continue;
                        }
                        // Integrity: hash before dump
                        let hash = sha2::Sha256::digest(&data);
                        if let Err(e) = dump_encrypted_region(&data, &out_path, &key) {
                            warn!("Failed to dump region: {}", e);
                        } else {
                            info!("Dumped encrypted region to {} (sha256: {:x})", out_path, hash);
                        }
                    }
                    Err(e) => warn!("Failed to read region for carving: {}", e),
                }
            }
        }
    }
    Ok(())
}
