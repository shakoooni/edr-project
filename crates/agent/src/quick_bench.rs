use std::time::Instant;
use sha2::{Sha256, Digest};
use tempfile::NamedTempFile;
use std::io::Write;

fn main() {
    // Config integrity check
    let data = vec![0xAB; 4096];
    let mut tmp = match NamedTempFile::new() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[ERROR] Failed to create temp file: {e}");
            return;
        }
    };
    if let Err(e) = tmp.as_file_mut().write_all(&data) {
        eprintln!("[ERROR] Failed to write to temp file: {e}");
        return;
    }
    let hash = Sha256::digest(&data);
    let path = match tmp.path().to_str() {
        Some(p) => p.to_string(),
        None => {
            eprintln!("[ERROR] Temp file path is not valid UTF-8");
            return;
        }
    };
    let start = Instant::now();
    for _ in 0..10_000 {
        if let Ok(d) = std::fs::read(&path) {
            let _ = Sha256::digest(&d) == hash;
        }
    }
    let elapsed = start.elapsed();
    println!("Config integrity: 10,000 checks in {:?} (avg: {:?} per op)", elapsed, elapsed/10_000);

    // Binary integrity check
    let data = vec![0xCD; 4096];
    let mut tmp = match NamedTempFile::new() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[ERROR] Failed to create temp file: {e}");
            return;
        }
    };
    if let Err(e) = tmp.as_file_mut().write_all(&data) {
        eprintln!("[ERROR] Failed to write to temp file: {e}");
        return;
    }
    let hash = Sha256::digest(&data);
    let path = match tmp.path().to_str() {
        Some(p) => p.to_string(),
        None => {
            eprintln!("[ERROR] Temp file path is not valid UTF-8");
            return;
        }
    };
    let start = Instant::now();
    for _ in 0..10_000 {
        if let Ok(d) = std::fs::read(&path) {
            let _ = Sha256::digest(&d) == hash;
        }
    }
    let elapsed = start.elapsed();
    println!("Binary integrity: 10,000 checks in {:?} (avg: {:?} per op)", elapsed, elapsed/10_000);

    // Log entry parse
    let log_line = "2025-07-03T12:00:00Z|ALERT: test event";
    let start = Instant::now();
    for _ in 0..1_000_000 {
        let _ = log_line.splitn(2, '|').collect::<Vec<_>>();
    }
    let elapsed = start.elapsed();
    println!("Log parse: 1,000,000 parses in {:?} (avg: {:?} per op)", elapsed, elapsed/1_000_000);
}
