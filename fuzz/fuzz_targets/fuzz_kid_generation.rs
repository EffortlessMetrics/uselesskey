#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey_core_kid::{DEFAULT_KID_PREFIX_BYTES, kid_from_bytes, kid_from_bytes_with_prefix};

#[derive(Arbitrary, Debug)]
struct KidInput {
    key_bytes: Vec<u8>,
    prefix_bytes: u8,
}

fuzz_target!(|input: KidInput| {
    // Cap input size to avoid excessive allocations.
    if input.key_bytes.len() > 8192 {
        return;
    }

    // kid_from_bytes must not panic and must be deterministic.
    let kid1 = kid_from_bytes(&input.key_bytes);
    let kid2 = kid_from_bytes(&input.key_bytes);
    assert_eq!(kid1, kid2, "kid_from_bytes must be deterministic");
    assert!(!kid1.is_empty());

    // kid must be URL-safe (base64url characters only).
    assert!(
        kid1.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "kid must be URL-safe: {kid1}"
    );

    // Default prefix produces a kid that decodes to DEFAULT_KID_PREFIX_BYTES.
    let decoded = base64_url_decode(&kid1);
    assert_eq!(
        decoded.len(),
        DEFAULT_KID_PREFIX_BYTES,
        "default kid must decode to {DEFAULT_KID_PREFIX_BYTES} bytes"
    );

    // kid_from_bytes_with_prefix with valid prefix_bytes (1..=32).
    let prefix = clamp_prefix(input.prefix_bytes);
    let kid_custom = kid_from_bytes_with_prefix(&input.key_bytes, prefix);
    let kid_custom2 = kid_from_bytes_with_prefix(&input.key_bytes, prefix);
    assert_eq!(kid_custom, kid_custom2, "custom kid must be deterministic");

    let decoded_custom = base64_url_decode(&kid_custom);
    assert_eq!(
        decoded_custom.len(),
        prefix,
        "custom kid must decode to {prefix} bytes"
    );

    // Different prefix lengths produce different kid lengths (unless both decode to same).
    let prefix_alt = clamp_prefix(input.prefix_bytes.wrapping_add(1));
    if prefix != prefix_alt {
        let kid_alt = kid_from_bytes_with_prefix(&input.key_bytes, prefix_alt);
        // Different prefix lengths should generally produce different output lengths.
        if prefix != prefix_alt {
            let decoded_alt = base64_url_decode(&kid_alt);
            assert_eq!(decoded_alt.len(), prefix_alt);
        }
        let _ = kid_alt;
    }
});

fn clamp_prefix(raw: u8) -> usize {
    let v = (raw as usize % 32) + 1; // 1..=32
    v
}

fn base64_url_decode(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    URL_SAFE_NO_PAD.decode(s.as_bytes()).expect("kid must be valid base64url")
}
