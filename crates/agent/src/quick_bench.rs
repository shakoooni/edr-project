use std::time::Instant;
use sha2::{Sha256, Digest};
use tempfile::NamedTempFile;
use std::io::Write;

fn main() {
    // Config integrity check
    let data = vec![0xAB; 4096];
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.as_file_mut().write_all(&data).unwrap();
    let hash = Sha256::digest(&data);
    let path = tmp.path().to_str().unwrap().to_string();
    let start = Instant::now();
    for _ in 0..10_000 {
        let _ = std::fs::read(&path).map(|d| Sha256::digest(&d) == hash);
    }
    let elapsed = start.elapsed();
    println!("Config integrity: 10,000 checks in {:?} (avg: {:?} per op)", elapsed, elapsed/10_000);

    // Binary integrity check
    let data = vec![0xCD; 4096];
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.as_file_mut().write_all(&data).unwrap();
    let hash = Sha256::digest(&data);
    let path = tmp.path().to_str().unwrap().to_string();
    let start = Instant::now();
    for _ in 0..10_000 {
        let _ = std::fs::read(&path).map(|d| Sha256::digest(&d) == hash);
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
