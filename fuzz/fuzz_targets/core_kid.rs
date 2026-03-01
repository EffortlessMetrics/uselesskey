#![no_main]

use base64::Engine as _;
use libfuzzer_sys::fuzz_target;

use uselesskey_core_kid::{DEFAULT_KID_PREFIX_BYTES, kid_from_bytes, kid_from_bytes_with_prefix};

fuzz_target!(|data: &[u8]| {
    // Default kid generation must succeed for any input.
    let kid = kid_from_bytes(data);
    assert!(!kid.is_empty());

    // Determinism: same input produces same kid.
    let kid2 = kid_from_bytes(data);
    assert_eq!(kid, kid2);

    // Decoded kid should have the expected length.
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(kid.as_bytes())
        .expect("kid must be valid base64url");
    assert_eq!(decoded.len(), DEFAULT_KID_PREFIX_BYTES);

    // Custom prefix lengths in the valid range (1..=32).
    if let Some(&first) = data.first() {
        let prefix = ((first as usize) % 32) + 1; // 1..=32
        let custom = kid_from_bytes_with_prefix(data, prefix);
        let custom_decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(custom.as_bytes())
            .expect("custom kid must be valid base64url");
        assert_eq!(custom_decoded.len(), prefix);
    }
});
