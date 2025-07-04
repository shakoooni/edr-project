#![deny(unsafe_code)]
#![deny(missing_docs)]
//! Async scan orchestrator for ultra_edr.


use tokio::time::{interval, Duration};
use rand::{thread_rng, Rng};
use process::linux::{LinuxScanner, scan_and_analyze};
use triage::{score_factors, RiskFactors, RiskScore, RiskClass};
use process::{MemoryScanner, ProcessInfo, RegionAnalysis};
use carving::{dump_encrypted_region, key_from_passphrase};
use log::{info, warn};

/// Run the async scan loop for all processes.
/// Run the async scan loop for all processes, with randomized interval for stealth.
pub async fn run_scan_loop(scan_interval_secs: u64) {
    let mut rng = thread_rng();
    loop {
        // Add jitter: +/- 30%% of interval
        let jitter = rng.gen_range(
            (scan_interval_secs as f64 * 0.7) as u64..
            (scan_interval_secs as f64 * 1.3) as u64
        );
        tokio::time::sleep(Duration::from_secs(jitter)).await;
        match LinuxScanner::list_processes() {
            Ok(procs) => {
                for proc in procs {
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
                // For demo: re-read region for dump (in real use, pass data from analysis)
                match process::region::read_region(pid, region.start, region.end) {
                    Ok(data) => {
                        if let Err(e) = dump_encrypted_region(&data, &out_path, &key) {
                            warn!("Failed to dump region: {}", e);
                        } else {
                            info!("Dumped encrypted region to {}", out_path);
                        }
                    }
                    Err(e) => warn!("Failed to read region for carving: {}", e),
                }
            }
        }
    }
    Ok(())
}
