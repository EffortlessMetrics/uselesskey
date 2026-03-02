//! Deterministic key-ID generation from raw key bytes.
//!
//! Produces URL-safe, base64url-encoded BLAKE3 hashes truncated to 96 bits
//! by default. Use [`kid_from_bytes`] for the standard length or
//! [`kid_from_bytes_with_prefix`] for a custom hash prefix.

#![forbid(unsafe_code)]
//! Deterministic key-id (kid) helpers for uselesskey fixture crates.
//!
//! Generates URL-safe base64 key identifiers by hashing public key material
//! with BLAKE3. The default prefix length (12 bytes / 96 bits) provides
//! sufficient collision resistance for test fixture scenarios.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Default number of hash bytes used for key IDs.
///
/// 12 bytes = 96 bits, enough to avoid accidental collisions in test fixtures.
pub const DEFAULT_KID_PREFIX_BYTES: usize = 12;

/// Generate a deterministic key ID from key bytes.
///
/// Uses BLAKE3 and base64url (no padding), truncating to
/// [`DEFAULT_KID_PREFIX_BYTES`].
///
/// # Examples
///
/// ```
/// use uselesskey_core_kid::kid_from_bytes;
///
/// let kid = kid_from_bytes(b"my-public-key-bytes");
/// assert!(!kid.is_empty());
/// // Same input always produces the same kid
/// assert_eq!(kid, kid_from_bytes(b"my-public-key-bytes"));
/// ```
pub fn kid_from_bytes(bytes: &[u8]) -> String {
    kid_from_bytes_with_prefix(bytes, DEFAULT_KID_PREFIX_BYTES)
}

/// Generate a deterministic key ID from key bytes with a custom hash prefix length.
///
/// `prefix_bytes` must be in `1..=32`.
///
/// # Examples
///
/// ```
/// use uselesskey_core_kid::kid_from_bytes_with_prefix;
///
/// // Shorter prefix = shorter kid string
/// let short = kid_from_bytes_with_prefix(b"my-key", 4);
/// let long  = kid_from_bytes_with_prefix(b"my-key", 16);
/// assert!(short.len() < long.len());
/// ```
pub fn kid_from_bytes_with_prefix(bytes: &[u8], prefix_bytes: usize) -> String {
    assert!(
        (1..=blake3::OUT_LEN).contains(&prefix_bytes),
        "prefix_bytes must be in 1..={} (got {prefix_bytes})",
        blake3::OUT_LEN
    );

    let digest = blake3::hash(bytes);
    URL_SAFE_NO_PAD.encode(&digest.as_bytes()[..prefix_bytes])
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::{DEFAULT_KID_PREFIX_BYTES, kid_from_bytes, kid_from_bytes_with_prefix};

    #[test]
    fn kid_is_deterministic() {
        let a = kid_from_bytes(b"fixture-public-key");
        let b = kid_from_bytes(b"fixture-public-key");
        assert_eq!(a, b);
    }

    #[test]
    fn kid_changes_when_input_changes() {
        let a = kid_from_bytes(b"fixture-public-key-a");
        let b = kid_from_bytes(b"fixture-public-key-b");
        assert_ne!(a, b);
    }

    #[test]
    fn default_kid_decodes_to_96_bits() {
        let kid = kid_from_bytes(b"fixture-public-key");
        let decoded = URL_SAFE_NO_PAD
            .decode(kid.as_bytes())
            .expect("kid should be valid base64url");
        assert_eq!(decoded.len(), DEFAULT_KID_PREFIX_BYTES);
    }

    #[test]
    fn configurable_prefix_length_is_respected() {
        let kid = kid_from_bytes_with_prefix(b"fixture-public-key", 8);
        let decoded = URL_SAFE_NO_PAD
            .decode(kid.as_bytes())
            .expect("kid should be valid base64url");
        assert_eq!(decoded.len(), 8);
    }

    #[test]
    #[should_panic(expected = "prefix_bytes must be in 1..=32")]
    fn prefix_length_must_be_non_zero() {
        let _ = kid_from_bytes_with_prefix(b"fixture-public-key", 0);
    }
}
