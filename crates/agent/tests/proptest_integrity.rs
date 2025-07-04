use proptest::prelude::*;
use sha2::{Sha256, Digest};
use std::fs;

// Simulate a self-integrity check for a config file
fn check_config_integrity(path: &str, expected_hash: [u8; 32]) -> bool {
    match fs::read(path) {
        Ok(data) => {
            let actual = Sha256::digest(&data);
            actual.as_slice() == expected_hash
        },
        Err(_) => false,
    }
}

proptest! {
    #[test]
    fn config_integrity_detects_all_tamper(data in proptest::collection::vec(any::<u8>(), 1..4096)) {
        use std::io::Write;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.as_file().write_all(&data).unwrap();
        let hash = Sha256::digest(&data);
        let path = tmp.path().to_str().unwrap();
        // Should pass for original
        assert!(check_config_integrity(path, hash.clone().into()));

        // 1. Single byte flip
        let mut tampered = data.clone();
        tampered[0] ^= 0xFF;
        tmp.as_file().set_len(0).unwrap();
        tmp.as_file().write_all(&tampered).unwrap();
        assert!(!check_config_integrity(path, hash.into()));

        // 2. Truncation
        if data.len() > 1 {
            tmp.as_file().set_len((data.len() - 1) as u64).unwrap();
            assert!(!check_config_integrity(path, hash.into()));
        }

        // 3. Appended junk
        let mut extended = data.clone();
        extended.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        tmp.as_file().set_len(0).unwrap();
        tmp.as_file().write_all(&extended).unwrap();
        assert!(!check_config_integrity(path, hash.into()));

        // 4. Overwrite with zeros
        let zeros = vec![0u8; data.len()];
        tmp.as_file().set_len(0).unwrap();
        tmp.as_file().write_all(&zeros).unwrap();
        assert!(!check_config_integrity(path, hash.into()));

        // 5. File deleted
        let _ = std::fs::remove_file(path);
        assert!(!check_config_integrity(path, hash.into()));
    }
}
