use criterion::{criterion_group, criterion_main, Criterion};
use sha2::{Sha256, Digest};
use std::io::Write;
use tempfile::NamedTempFile;

// Benchmark config integrity check
fn bench_config_integrity(c: &mut Criterion) {
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
    c.bench_function("config_integrity_check", |b| {
        b.iter(|| {
            if let Ok(d) = std::fs::read(&path) {
                let _ = Sha256::digest(&d) == hash;
            }
        });
    });
}

// Benchmark binary integrity check
fn bench_binary_integrity(c: &mut Criterion) {
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
    c.bench_function("binary_integrity_check", |b| {
        b.iter(|| {
            if let Ok(d) = std::fs::read(&path) {
                let _ = Sha256::digest(&d) == hash;
            }
        });
    });
}

// Benchmark log entry parsing
fn bench_log_entry_parse(c: &mut Criterion) {
    let log_line = "2025-07-03T12:00:00Z|ALERT: test event";
    c.bench_function("log_entry_parse", |b| {
        b.iter(|| {
            let _ = log_line.splitn(2, '|').collect::<Vec<_>>();
        });
    });
}

criterion_group!(benches, bench_config_integrity, bench_binary_integrity, bench_log_entry_parse);
criterion_main!(benches);
