use criterion::{criterion_group, criterion_main, Criterion};
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{Write, Read};
use tempfile::NamedTempFile;

// Benchmark config integrity check
fn bench_config_integrity(c: &mut Criterion) {
    let data = vec![0xAB; 4096];
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.as_file_mut().write_all(&data).unwrap();
    let hash = Sha256::digest(&data);
    let path = tmp.path().to_str().unwrap().to_string();
    c.bench_function("config_integrity_check", |b| {
        b.iter(|| {
            let _ = std::fs::read(&path).map(|d| Sha256::digest(&d) == hash);
        });
    });
}

// Benchmark binary integrity check
fn bench_binary_integrity(c: &mut Criterion) {
    let data = vec![0xCD; 4096];
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.as_file_mut().write_all(&data).unwrap();
    let hash = Sha256::digest(&data);
    let path = tmp.path().to_str().unwrap().to_string();
    c.bench_function("binary_integrity_check", |b| {
        b.iter(|| {
            let _ = std::fs::read(&path).map(|d| Sha256::digest(&d) == hash);
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
