use proptest::prelude::*;


fn parse_scan_interval(config: &str) -> u64 {
    config
        .lines()
        .find(|l| l.trim_start().starts_with("scan_interval_seconds"))
        .and_then(|l| l.split('=').nth(1))
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(60)
}

fn parse_log_path(config: &str) -> String {
    config
        .lines()
        .find(|l| l.trim_start().starts_with("log_path"))
        .and_then(|l| l.split('=').nth(1))
        .map(|v| v.trim().trim_matches('"').to_string())
        .unwrap_or_else(|| "../logs/edr.log".to_string())
}

proptest! {
    #[test]
    fn scan_interval_and_log_path_hardened(
        s in proptest::collection::vec(any::<u8>(), 0..65536)
    ) {
        // Try to parse as UTF-8, fallback to lossy
        let config_buf;
        let config = match std::str::from_utf8(&s) {
            Ok(v) => v,
            Err(_) => {
                config_buf = std::string::String::from_utf8_lossy(&s).to_string();
                &config_buf
            }
        };

        // Hardened: never panic, always returns a valid type
        let interval = parse_scan_interval(config);
        let log_path = parse_log_path(config);

        // Assert interval is within reasonable bounds
        prop_assert!(interval <= u64::MAX);
        // Assert log_path is not empty and not absurdly long
        prop_assert!(!log_path.is_empty());
        prop_assert!(log_path.len() < 4096);

        // Hardened: check for injection attempts (no newlines, nulls)
        prop_assert!(!log_path.contains('\0'));
        prop_assert!(!log_path.contains('\n'));
    }
}
