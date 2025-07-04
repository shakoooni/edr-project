use proptest::prelude::*;
use process::analyze_region;

proptest! {
    #[test]
    fn analyze_region_no_panic(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = analyze_region(&data, None);
        let _ = analyze_region(&data, Some([0u8; 32]));
    }
}
