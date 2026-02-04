/// Specification for Ed25519 key generation.
///
/// Ed25519 has no configurable parameters like RSA bit size,
/// so this struct is simple and always returns the same spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub struct Ed25519Spec {
    // Ed25519 has fixed parameters, but we keep this struct for API consistency
    // and future-proofing (e.g., context strings if we add Ed25519ctx support).
    _private: (),
}

impl Ed25519Spec {
    /// Create a new Ed25519 spec.
    ///
    /// Ed25519 has no configurable parameters, so this always
    /// returns the same spec.
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Stable encoding for cache keys / deterministic derivation.
    ///
    /// If you change this, bump the derivation version in `uselesskey-core`.
    pub fn stable_bytes(&self) -> [u8; 4] {
        // Fixed identifier for Ed25519 keys.
        // Format: [magic byte, version, reserved, reserved]
        [b'E', b'd', 0x01, 0x00]
    }
}
