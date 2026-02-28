#![no_main]

use libfuzzer_sys::fuzz_target;

use uselesskey_core_kid::{kid_from_bytes, kid_from_bytes_with_prefix, DEFAULT_KID_PREFIX_BYTES};

fuzz_target!(|data: &[u8]| {
    // Fuzz the default kid derivation with arbitrary "SPKI" bytes.
    let kid = kid_from_bytes(data);
    assert!(!kid.is_empty());

    // Same input always produces the same kid.
    let kid2 = kid_from_bytes(data);
    assert_eq!(kid, kid2);

    // Fuzz with custom prefix lengths (1..=32).
    if let Some(&first) = data.first() {
        let prefix = ((first as usize) % 32) + 1; // 1..=32
        let custom = kid_from_bytes_with_prefix(data, prefix);
        assert!(!custom.is_empty());

        if prefix == DEFAULT_KID_PREFIX_BYTES {
            assert_eq!(kid, custom);
        }
    }
});
