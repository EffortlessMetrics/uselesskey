use std::fmt;

use crate::derive;

/// Seed material used for deterministic fixture generation.
///
/// The actual bytes are intentionally not printed in `Debug` to prevent
/// accidental leakage in test output.
///
/// # Examples
///
/// ```
/// use uselesskey_core::Seed;
///
/// // Create from raw bytes
/// let bytes = [0u8; 32];
/// let seed = Seed::new(bytes);
///
/// // Create from a string (hashed to 32 bytes)
/// let seed = Seed::from_env_value("my-ci-seed").unwrap();
///
/// // Debug output is redacted
/// assert_eq!(format!("{:?}", seed), "Seed(**redacted**)");
/// ```
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct Seed(pub(crate) [u8; 32]);

impl Seed {
    /// Create a seed from raw bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use uselesskey_core::Seed;
    ///
    /// let bytes = [42u8; 32];
    /// let seed = Seed::new(bytes);
    /// assert_eq!(seed.bytes(), &bytes);
    /// ```
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Access raw seed bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use uselesskey_core::Seed;
    ///
    /// let seed = Seed::from_env_value("test").unwrap();
    /// let bytes: &[u8; 32] = seed.bytes();
    /// assert_eq!(bytes.len(), 32);
    /// ```
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive a seed from a user-provided string.
    ///
    /// - If the value looks like 32-byte hex (64 chars), it is parsed as hex.
    /// - Otherwise we hash the string with BLAKE3 to obtain 32 bytes.
    ///
    /// This is intentionally forgiving because test runners and CI often pass
    /// "human" seeds like `ci` or `local`.
    ///
    /// # Examples
    ///
    /// ```
    /// use uselesskey_core::Seed;
    ///
    /// // Simple string seed (hashed internally)
    /// let seed = Seed::from_env_value("ci").unwrap();
    ///
    /// // 64-character hex seed
    /// let hex = "0000000000000000000000000000000000000000000000000000000000000001";
    /// let seed = Seed::from_env_value(hex).unwrap();
    ///
    /// // With 0x prefix
    /// let seed = Seed::from_env_value("0x0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    ///
    /// // Whitespace is trimmed
    /// let seed = Seed::from_env_value("  my-seed  ").unwrap();
    /// ```
    ///
    /// # Determinism
    ///
    /// The same input always produces the same seed:
    ///
    /// ```
    /// use uselesskey_core::Seed;
    ///
    /// let seed1 = Seed::from_env_value("test").unwrap();
    /// let seed2 = Seed::from_env_value("test").unwrap();
    /// assert_eq!(seed1.bytes(), seed2.bytes());
    /// ```
    pub fn from_env_value(value: &str) -> Result<Self, String> {
        let v = value.trim();

        // Optional 0x prefix.
        let hex = v.strip_prefix("0x").unwrap_or(v);

        if hex.len() == 64 {
            return parse_hex_32(hex).map(Self);
        }

        // Fallback: hash the string into 32 bytes.
        Ok(Self(*derive::hash32(v.as_bytes()).as_bytes()))
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(**redacted**)")
    }
}

fn parse_hex_32(hex: &str) -> Result<[u8; 32], String> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }

    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];

    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi = val(chunk[0]).ok_or_else(|| format!("invalid hex char: {}", chunk[0] as char))?;
        let lo = val(chunk[1]).ok_or_else(|| format!("invalid hex char: {}", chunk[1] as char))?;
        out[i] = (hi << 4) | lo;
    }

    Ok(out)
}

/// Domain strings are used to separate unrelated fixture types.
///
/// Example domains:
/// - `uselesskey:rsa:keypair`
/// - `uselesskey:x509:ca`
///
/// Domains should be stable across versions.
pub type ArtifactDomain = &'static str;

/// Version tag for the derivation scheme.
///
/// Bump this if you *intentionally* change how fixture derivation works.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DerivationVersion(pub u16);

impl DerivationVersion {
    pub const V1: Self = Self(1);
}

/// Identifies a cached artifact and (in deterministic mode) the seed used to generate it.
///
/// The goal is stability:
/// the same `(domain, label, spec, variant)` produces the same artifact in deterministic mode,
/// regardless of call order.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ArtifactId {
    pub domain: ArtifactDomain,
    pub label: String,
    pub spec_fingerprint: [u8; 32],
    pub variant: String,
    pub derivation_version: DerivationVersion,
}

impl ArtifactId {
    pub fn new(
        domain: ArtifactDomain,
        label: impl Into<String>,
        spec_bytes: &[u8],
        variant: impl Into<String>,
        derivation_version: DerivationVersion,
    ) -> Self {
        Self {
            domain,
            label: label.into(),
            spec_fingerprint: *derive::hash32(spec_bytes).as_bytes(),
            variant: variant.into(),
            derivation_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_debug_is_redacted() {
        let seed = Seed::new([7u8; 32]);
        assert_eq!(format!("{:?}", seed), "Seed(**redacted**)");
    }

    #[test]
    fn parse_hex_32_rejects_wrong_length() {
        let err = parse_hex_32("abcd").unwrap_err();
        assert!(err.contains("expected 64 hex chars"));
    }

    #[test]
    fn parse_hex_32_rejects_invalid_char() {
        let mut s = "0".repeat(64);
        s.replace_range(10..11, "g");

        let err = parse_hex_32(&s).unwrap_err();
        assert!(err.contains("invalid hex char"));
    }

    #[test]
    fn artifact_id_fingerprints_spec_bytes() {
        let spec = [1u8, 2, 3, 4, 5];
        let id = ArtifactId::new(
            "domain:test",
            "label",
            &spec,
            "variant",
            DerivationVersion::V1,
        );

        let expected = *crate::derive::hash32(&spec).as_bytes();
        assert_eq!(id.spec_fingerprint, expected);
    }

    #[test]
    fn artifact_id_preserves_fields() {
        let id = ArtifactId::new(
            "domain:test",
            "my-label",
            b"spec",
            "my-variant",
            DerivationVersion::V1,
        );

        assert_eq!(id.domain, "domain:test");
        assert_eq!(id.label, "my-label");
        assert_eq!(id.variant, "my-variant");
        assert_eq!(id.derivation_version, DerivationVersion::V1);
    }

    #[test]
    fn seed_from_env_value_parses_hex_with_prefix_and_whitespace() {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let seed = Seed::from_env_value(&format!("  {hex}  ")).unwrap();
        assert_eq!(seed.bytes()[31], 1);
        assert!(seed.bytes()[..31].iter().all(|b| *b == 0));
    }

    #[test]
    fn seed_from_env_value_parses_uppercase_hex() {
        let hex = "F".repeat(64);
        let seed = Seed::from_env_value(&hex).unwrap();
        assert!(seed.bytes().iter().all(|b| *b == 0xFF));
    }
}
