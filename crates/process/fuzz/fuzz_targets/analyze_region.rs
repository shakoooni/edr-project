#![no_main]
use libfuzzer_sys::fuzz_target;
use process::analyze_region;

fuzz_target!(|data: &[u8]| {
    // Fuzz with no previous hash
    let _ = analyze_region(data, None);
    // Fuzz with a fixed previous hash
    let _ = analyze_region(data, Some([0u8; 32]));
});
