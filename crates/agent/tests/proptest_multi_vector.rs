use proptest::prelude::*;
use sha2::{Sha256, Digest};
use std::fs;
use std::io::Write;
use std::sync::{Arc, Barrier};
use std::thread;
use tempfile::NamedTempFile;

// Simulate config integrity check
fn check_config_integrity(path: &str, expected_hash: [u8; 32]) -> bool {
    match fs::read(path) {
        Ok(data) => {
            let actual = Sha256::digest(&data);
            actual.as_slice() == expected_hash
        },
        Err(_) => false,
    }
}

// Simulate binary integrity check
fn check_binary_integrity(path: &str, expected_hash: [u8; 32]) -> bool {
    match fs::read(path) {
        Ok(data) => {
            let actual = Sha256::digest(&data);
            actual.as_slice() == expected_hash
        },
        Err(_) => false,
    }
}

// Simulate log entry parser (hardened)
fn parse_log_entry(line: &str) -> Option<(&str, &str)> {
    if line.contains('\0') || line.contains('\n') || line.contains('\r') { return None; }
    if line.len() > 1024 { return None; }
    if line.chars().any(|c| c.is_control() && c != '\t') { return None; }
    let mut parts = line.splitn(2, '|');
    let ts = parts.next()?;
    let event = parts.next()?;
    if ts.len() < 4 || event.is_empty() { return None; }
    Some((ts, event))
}

proptest! {
    #[test]
    fn multi_vector_concurrent_attack(
        config_data in proptest::collection::vec(any::<u8>(), 2..4096),
        binary_data in proptest::collection::vec(any::<u8>(), 2..4096),
        log_data in proptest::collection::vec(any::<u8>(), 2..1024),
        junk in proptest::collection::vec(any::<u8>(), 1..32)
    ) {
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = vec![];

        // Config tamper thread
        {
            let barrier = barrier.clone();
            let config_data = config_data.clone();
            handles.push(thread::spawn(move || {
                let tmp = NamedTempFile::new().unwrap();
                tmp.as_file().write_all(&config_data).unwrap();
                let hash = Sha256::digest(&config_data);
                let path = tmp.path().to_str().unwrap();
                barrier.wait();
                // Tamper: flip, truncate, extend
                let mut tampered = config_data.clone();
                tampered[0] ^= 0xFF;
                tmp.as_file().set_len(0).unwrap();
                tmp.as_file().write_all(&tampered).unwrap();
                assert!(!check_config_integrity(path, hash.into()));
                tmp.as_file().set_len(0).unwrap();
                tmp.as_file().write_all(&config_data).unwrap();
                let mut extended = config_data.clone();
                extended.extend_from_slice(&junk);
                tmp.as_file().set_len(0).unwrap();
                tmp.as_file().write_all(&extended).unwrap();
                assert!(!check_config_integrity(path, hash.into()));
            }));
        }

        // Binary tamper thread
        {
            let barrier = barrier.clone();
            let binary_data = binary_data.clone();
            handles.push(thread::spawn(move || {
                let tmp = NamedTempFile::new().unwrap();
                tmp.as_file().write_all(&binary_data).unwrap();
                let hash = Sha256::digest(&binary_data);
                let path = tmp.path().to_str().unwrap();
                barrier.wait();
                // Tamper: flip, zero, delete
                let mut tampered = binary_data.clone();
                tampered[0] ^= 0xAA;
                tmp.as_file().set_len(0).unwrap();
                tmp.as_file().write_all(&tampered).unwrap();
                assert!(!check_binary_integrity(path, hash.into()));
                let zeros = vec![0u8; binary_data.len()];
                tmp.as_file().set_len(0).unwrap();
                tmp.as_file().write_all(&zeros).unwrap();
                assert!(!check_binary_integrity(path, hash.into()));
                let _ = fs::remove_file(path);
                assert!(!check_binary_integrity(path, hash.into()));
            }));
        }

        // Log injection thread
        {
            let barrier = barrier.clone();
            let log_data = log_data.clone();
            handles.push(thread::spawn(move || {
                let log_line = match std::str::from_utf8(&log_data) {
                    Ok(v) => v,
                    Err(_) => return, // skip invalid utf8
                };
                barrier.wait();
                // Try to inject nulls, control, Unicode, delimiters
                let mut injected = log_line.to_string();
                injected.push('\0');
                assert!(parse_log_entry(&injected).is_none());
                let mut injected = log_line.to_string();
                injected.push('|');
                assert!(parse_log_entry(&injected).is_none());
                let mut injected = log_line.to_string();
                injected.push('\u{202e}');
                assert!(parse_log_entry(&injected).is_none());
            }));
        }

        // Fault injection thread (simulate IO/perm errors)
        {
            let barrier = barrier.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                // Simulate random fs errors (permission, not found)
                let path = "/unlikely/to/exist/edr_test";
                assert!(!check_config_integrity(path, [0u8;32]));
                assert!(!check_binary_integrity(path, [0u8;32]));
            }));
        }

        for h in handles { h.join().unwrap(); }
    }
}
