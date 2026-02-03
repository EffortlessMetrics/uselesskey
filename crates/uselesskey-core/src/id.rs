use std::fmt;

use crate::derive;

/// Seed material used for deterministic fixture generation.
///
/// The actual bytes are intentionally not printed in `Debug`.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct Seed(pub(crate) [u8; 32]);

impl Seed {
    /// Create a seed from raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Access raw seed bytes.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive a seed from a user-provided string.
    ///
    /// - If the value looks like 32-byte hex, it is parsed as hex.
    /// - Otherwise we hash the string with BLAKE3 to obtain 32 bytes.
    ///
    /// This is intentionally forgiving because test runners and CI often pass
    /// “human” seeds like `ci` or `local`.
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
