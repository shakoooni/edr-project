use proptest::prelude::*;

// Example log entry parser (replace with your actual parser if different)
fn parse_log_entry(line: &str) -> Option<(&str, &str)> {
    // Hardened: reject nulls, control chars, excessive length, Unicode tricks, suspicious whitespace
    if line.contains('\0') || line.contains('\n') || line.contains('\r') { return None; }
    if line.len() > 1024 { return None; }
    if line.chars().any(|c| c.is_control() && c != '\t') { return None; }
    if line.chars().any(|c| c == '\u{202e}' || c == '\u{200e}' || c == '\u{200f}') { return None; } // RTL/LTR override
    if line.chars().any(|c| c.is_whitespace() && c != ' ' && c != '\t') { return None; }
    let mut parts = line.splitn(2, '|');
    let ts = parts.next()?;
    let event = parts.next()?;
    if ts.len() < 4 || event.is_empty() { return None; }
    if ts.chars().any(|c| c < ' ' || c == '\0' || c.is_control() || c.is_whitespace() && c != ' ' && c != '\t') { return None; }
    if event.chars().any(|c| c < ' ' || c == '\0' || c == '|' || c.is_control() || c.is_whitespace() && c != ' ' && c != '\t') { return None; }
    Some((ts, event))
}

proptest! {
    #[test]
    fn log_entry_integrity_hardened_ultimate(s in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let buf;
        let line = match std::str::from_utf8(&s) {
            Ok(v) => v,
            Err(_) => { buf = String::from_utf8_lossy(&s).to_string(); &buf }
        };
        // Hardened: never panic, always returns valid type or None
        let parsed = parse_log_entry(line);
        // If parsed, check for advanced injection/tamper attempts
        if let Some((ts, event)) = parsed {
            prop_assert!(!ts.contains('\0'));
            prop_assert!(!event.contains('\0'));
            prop_assert!(!event.contains("|")); // No extra delimiters
            prop_assert!(ts.chars().all(|c| c.is_ascii_digit() || c == '-' || c == ':' || c == 'T' || c == 'Z'));
            prop_assert!(ts.len() < 128);
            prop_assert!(event.len() < 900);
            prop_assert!(!ts.chars().any(|c| c.is_control() && c != '\t'));
            prop_assert!(!event.chars().any(|c| c.is_control() && c != '\t'));
            prop_assert!(!ts.chars().any(|c| c == char::from_u32(0x202e).unwrap() || c == char::from_u32(0x200e).unwrap() || c == char::from_u32(0x200f).unwrap()));
            prop_assert!(!event.chars().any(|c| c == char::from_u32(0x202e).unwrap() || c == char::from_u32(0x200e).unwrap() || c == char::from_u32(0x200f).unwrap()));
        }
    }
}
