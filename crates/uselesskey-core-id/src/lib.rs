#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;

use blake3::Hash;

/// Seed bytes derived from a fixture master seed.
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
    pub fn from_env_value(value: &str) -> Result<Self, String> {
        let v = value.trim();
        let hex = v.strip_prefix("0x").unwrap_or(v);

        if hex.len() == 64 {
            return parse_hex_32(hex).map(Self);
        }

        Ok(Self(*hash32(v.as_bytes()).as_bytes()))
    }
}

impl core::fmt::Debug for Seed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
        return Err(alloc::format!("expected 64 hex chars, got {}", hex.len()));
    }

    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];

    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi = val(chunk[0])
            .ok_or_else(|| alloc::format!("invalid hex char: {}", chunk[0] as char))?;
        let lo = val(chunk[1])
            .ok_or_else(|| alloc::format!("invalid hex char: {}", chunk[1] as char))?;
        out[i] = (hi << 4) | lo;
    }

    Ok(out)
}

/// Domain strings are used to separate unrelated fixture types.
pub type ArtifactDomain = &'static str;

/// Version tag for the derivation scheme.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct DerivationVersion(pub u16);

impl DerivationVersion {
    pub const V1: Self = Self(1);
}

/// Identifier used for deterministic artifact cache entries.
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
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
            spec_fingerprint: *hash32(spec_bytes).as_bytes(),
            variant: variant.into(),
            derivation_version,
        }
    }
}

pub fn hash32(bytes: &[u8]) -> Hash {
    blake3::hash(bytes)
}

/// Derive a per-artifact seed from the master seed and the artifact identifier.
pub fn derive_seed(master: &Seed, id: &ArtifactId) -> Seed {
    match id.derivation_version.0 {
        1 => derive_seed_v1(master, id),
        other => {
            #[cfg(feature = "std")]
            eprintln!("uselesskey-core-id: unknown derivation version {other}, using v1");
            #[cfg(not(feature = "std"))]
            let _ = other;
            derive_seed_v1(master, id)
        }
    }
}

fn derive_seed_v1(master: &Seed, id: &ArtifactId) -> Seed {
    use blake3::Hasher;

    let mut hasher = Hasher::new_keyed(master.bytes());

    hasher.update(&id.derivation_version.0.to_be_bytes());
    write_len_prefixed(&mut hasher, id.domain.as_bytes());
    write_len_prefixed(&mut hasher, id.label.as_bytes());
    write_len_prefixed(&mut hasher, id.variant.as_bytes());
    hasher.update(&id.spec_fingerprint);

    let out = hasher.finalize();
    Seed(*out.as_bytes())
}

fn write_len_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    hasher.update(&len.to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::{ArtifactId, DerivationVersion, Seed, derive_seed, hash32, parse_hex_32};

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

        let expected = *hash32(&spec).as_bytes();
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
    fn derive_seed_unknown_version_is_deterministic() {
        let master = Seed::new([9u8; 32]);
        let id = ArtifactId::new(
            "domain:test",
            "label",
            b"spec",
            "variant",
            DerivationVersion(999),
        );

        let first = derive_seed(&master, &id);
        let second = derive_seed(&master, &id);
        assert_eq!(first.bytes(), second.bytes());
    }

    #[test]
    fn derive_seed_version_affects_output() {
        let master = Seed::new([3u8; 32]);
        let id_v1 = ArtifactId::new(
            "domain:test",
            "label",
            b"spec",
            "variant",
            DerivationVersion::V1,
        );
        let id_v2 = ArtifactId::new(
            "domain:test",
            "label",
            b"spec",
            "variant",
            DerivationVersion(2),
        );

        let v1 = derive_seed(&master, &id_v1);
        let v2 = derive_seed(&master, &id_v2);
        assert_ne!(v1.bytes(), v2.bytes());
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

    #[test]
    fn parse_hex_32_lowercase_values() {
        // "0a" repeated 32 times → each byte should be 0x0a = 10
        let hex = "0a".repeat(32);
        let parsed = parse_hex_32(&hex).unwrap();
        assert!(parsed.iter().all(|b| *b == 0x0a));
    }

    #[test]
    fn derive_seed_label_affects_output() {
        let master = Seed::new([5u8; 32]);
        let id_a = ArtifactId::new("d", "label-a", b"spec", "v", DerivationVersion::V1);
        let id_b = ArtifactId::new("d", "label-b", b"spec", "v", DerivationVersion::V1);
        assert_ne!(
            derive_seed(&master, &id_a).bytes(),
            derive_seed(&master, &id_b).bytes()
        );
    }
}
