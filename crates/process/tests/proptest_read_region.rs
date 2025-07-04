use proptest::prelude::*;
use process::region::read_region;

proptest! {
    #[test]
    fn read_region_no_panic(
        pid in 0u32..100_000,
        start in 0u64..0x1_0000_0000,
        len in 0u64..0x10000
    ) {
        let end = start.saturating_add(len);
        // Hardened: never panic, always returns Ok or a well-formed error
        let _ = read_region(pid, start, end);
    }
}
