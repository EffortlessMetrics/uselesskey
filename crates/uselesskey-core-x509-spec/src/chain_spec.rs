//! X.509 certificate chain specification.

use crate::{KeyUsage, NotBeforeOffset};

/// Specification for generating a three-level X.509 certificate chain
/// (root CA -> intermediate CA -> leaf).
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ChainSpec {
    /// Common Name (CN) for the leaf certificate.
    pub leaf_cn: String,
    /// DNS Subject Alternative Names for the leaf certificate.
    pub leaf_sans: Vec<String>,
    /// Common Name (CN) for the root CA.
    pub root_cn: String,
    /// Common Name (CN) for the intermediate CA.
    pub intermediate_cn: String,
    /// RSA key size in bits.
    pub rsa_bits: usize,
    /// Root CA validity period in days.
    pub root_validity_days: u32,
    /// Intermediate CA validity period in days.
    pub intermediate_validity_days: u32,
    /// Leaf certificate validity period in days.
    pub leaf_validity_days: u32,
    /// Override for leaf `not_before` relative to the deterministic base time.
    ///
    /// When `None`, `not_before = base_time - 1 day` (the default).
    pub leaf_not_before: Option<NotBeforeOffset>,
    /// Override for intermediate `not_before` relative to the deterministic base time.
    ///
    /// When `None`, `not_before = base_time - 1 day` (the default).
    pub intermediate_not_before: Option<NotBeforeOffset>,
    /// Optional override for whether the intermediate claims CA status.
    ///
    /// When `None`, the intermediate remains a CA.
    pub intermediate_is_ca: Option<bool>,
    /// Optional override for the intermediate key usage bits.
    ///
    /// When `None`, the intermediate uses standard CA key usage.
    pub intermediate_key_usage: Option<KeyUsage>,
}

impl ChainSpec {
    /// Create a chain spec with sensible defaults for the given leaf CN.
    ///
    /// The leaf CN is automatically added to the SAN list.
    pub fn new(leaf_cn: impl Into<String>) -> Self {
        let leaf_cn = leaf_cn.into();
        let root_cn = format!("{} Root CA", leaf_cn);
        let intermediate_cn = format!("{} Intermediate CA", leaf_cn);
        let leaf_sans = vec![leaf_cn.clone()];
        Self {
            leaf_cn,
            leaf_sans,
            root_cn,
            intermediate_cn,
            rsa_bits: 2048,
            root_validity_days: 3650,
            intermediate_validity_days: 1825,
            leaf_validity_days: 3650,
            leaf_not_before: None,
            intermediate_not_before: None,
            intermediate_is_ca: None,
            intermediate_key_usage: None,
        }
    }

    /// Set the DNS Subject Alternative Names for the leaf certificate.
    ///
    /// The leaf CN is **not** automatically added; include it explicitly if needed.
    pub fn with_sans(mut self, sans: Vec<String>) -> Self {
        self.leaf_sans = sans;
        self
    }

    /// Set the root CA Common Name.
    pub fn with_root_cn(mut self, cn: impl Into<String>) -> Self {
        self.root_cn = cn.into();
        self
    }

    /// Set the intermediate CA Common Name.
    pub fn with_intermediate_cn(mut self, cn: impl Into<String>) -> Self {
        self.intermediate_cn = cn.into();
        self
    }

    /// Set the RSA key size in bits.
    pub fn with_rsa_bits(mut self, bits: usize) -> Self {
        self.rsa_bits = bits;
        self
    }

    /// Set the root CA validity period in days.
    pub fn with_root_validity_days(mut self, days: u32) -> Self {
        self.root_validity_days = days;
        self
    }

    /// Set the intermediate CA validity period in days.
    pub fn with_intermediate_validity_days(mut self, days: u32) -> Self {
        self.intermediate_validity_days = days;
        self
    }

    /// Set the leaf certificate validity period in days.
    pub fn with_leaf_validity_days(mut self, days: u32) -> Self {
        self.leaf_validity_days = days;
        self
    }

    /// Set the leaf `not_before` override.
    pub fn with_leaf_not_before(mut self, offset: NotBeforeOffset) -> Self {
        self.leaf_not_before = Some(offset);
        self
    }

    /// Set the intermediate `not_before` override.
    pub fn with_intermediate_not_before(mut self, offset: NotBeforeOffset) -> Self {
        self.intermediate_not_before = Some(offset);
        self
    }

    /// Override whether the intermediate claims CA status.
    pub fn with_intermediate_is_ca(mut self, is_ca: bool) -> Self {
        self.intermediate_is_ca = Some(is_ca);
        self
    }

    /// Override the intermediate key usage bits.
    pub fn with_intermediate_key_usage(mut self, key_usage: KeyUsage) -> Self {
        self.intermediate_key_usage = Some(key_usage);
        self
    }

    /// Stable byte representation for deterministic derivation.
    ///
    /// SANs are sorted and deduplicated before encoding for stability.
    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Version prefix (v3: rich not_before offsets + intermediate overrides)
        out.push(3);

        // leaf_cn
        let leaf_cn_bytes = self.leaf_cn.as_bytes();
        out.extend_from_slice(&(leaf_cn_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(leaf_cn_bytes);

        // leaf_sans (sorted and deduplicated for stability)
        let mut sorted_sans = self.leaf_sans.clone();
        sorted_sans.sort();
        sorted_sans.dedup();
        out.extend_from_slice(&(sorted_sans.len() as u32).to_be_bytes());
        for san in &sorted_sans {
            let san_bytes = san.as_bytes();
            out.extend_from_slice(&(san_bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(san_bytes);
        }

        // root_cn
        let root_cn_bytes = self.root_cn.as_bytes();
        out.extend_from_slice(&(root_cn_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(root_cn_bytes);

        // intermediate_cn
        let int_cn_bytes = self.intermediate_cn.as_bytes();
        out.extend_from_slice(&(int_cn_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(int_cn_bytes);

        // rsa_bits
        out.extend_from_slice(&(self.rsa_bits as u32).to_be_bytes());

        // validity periods
        out.extend_from_slice(&self.root_validity_days.to_be_bytes());
        out.extend_from_slice(&self.intermediate_validity_days.to_be_bytes());
        out.extend_from_slice(&self.leaf_validity_days.to_be_bytes());

        // not_before offsets and intermediate overrides
        encode_optional_not_before(&mut out, self.leaf_not_before);
        encode_optional_not_before(&mut out, self.intermediate_not_before);

        match self.intermediate_is_ca {
            None => out.push(0),
            Some(false) => out.push(1),
            Some(true) => out.push(2),
        }

        match self.intermediate_key_usage {
            None => out.push(0),
            Some(key_usage) => {
                out.push(1);
                out.extend_from_slice(&key_usage.stable_bytes());
            }
        }

        out
    }
}

fn encode_optional_not_before(out: &mut Vec<u8>, offset: Option<NotBeforeOffset>) {
    match offset {
        None => out.push(0),
        Some(NotBeforeOffset::DaysAgo(days)) => {
            out.push(1);
            out.extend_from_slice(&days.to_be_bytes());
        }
        Some(NotBeforeOffset::DaysFromNow(days)) => {
            out.push(2);
            out.extend_from_slice(&days.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let spec = ChainSpec::new("test.example.com");
        assert_eq!(spec.leaf_cn, "test.example.com");
        assert_eq!(spec.leaf_sans, vec!["test.example.com"]);
        assert_eq!(spec.root_cn, "test.example.com Root CA");
        assert_eq!(spec.intermediate_cn, "test.example.com Intermediate CA");
        assert_eq!(spec.rsa_bits, 2048);
        assert_eq!(spec.root_validity_days, 3650);
        assert_eq!(spec.intermediate_validity_days, 1825);
        assert_eq!(spec.leaf_validity_days, 3650);
        assert_eq!(spec.leaf_not_before, None);
        assert_eq!(spec.intermediate_not_before, None);
        assert_eq!(spec.intermediate_is_ca, None);
        assert_eq!(spec.intermediate_key_usage, None);
    }

    #[test]
    fn test_builders() {
        let spec = ChainSpec::new("example.com")
            .with_sans(vec![
                "example.com".to_string(),
                "www.example.com".to_string(),
            ])
            .with_root_cn("My Root CA")
            .with_intermediate_cn("My Int CA")
            .with_rsa_bits(4096)
            .with_root_validity_days(7300)
            .with_intermediate_validity_days(3650)
            .with_leaf_validity_days(90)
            .with_leaf_not_before(NotBeforeOffset::DaysFromNow(7))
            .with_intermediate_not_before(NotBeforeOffset::DaysAgo(30))
            .with_intermediate_is_ca(false)
            .with_intermediate_key_usage(KeyUsage::leaf());

        assert_eq!(spec.leaf_sans.len(), 2);
        assert_eq!(spec.root_cn, "My Root CA");
        assert_eq!(spec.intermediate_cn, "My Int CA");
        assert_eq!(spec.rsa_bits, 4096);
        assert_eq!(spec.root_validity_days, 7300);
        assert_eq!(spec.intermediate_validity_days, 3650);
        assert_eq!(spec.leaf_validity_days, 90);
        assert_eq!(spec.leaf_not_before, Some(NotBeforeOffset::DaysFromNow(7)));
        assert_eq!(
            spec.intermediate_not_before,
            Some(NotBeforeOffset::DaysAgo(30))
        );
        assert_eq!(spec.intermediate_is_ca, Some(false));
        assert_eq!(spec.intermediate_key_usage, Some(KeyUsage::leaf()));
    }

    #[test]
    fn test_stable_bytes_determinism() {
        let spec1 = ChainSpec::new("test.example.com");
        let spec2 = ChainSpec::new("test.example.com");
        assert_eq!(spec1.stable_bytes(), spec2.stable_bytes());

        let spec3 = ChainSpec::new("other.example.com");
        assert_ne!(spec1.stable_bytes(), spec3.stable_bytes());
    }

    #[test]
    fn test_stable_bytes_san_order_independent() {
        let spec1 = ChainSpec::new("test.example.com").with_sans(vec![
            "a.example.com".to_string(),
            "b.example.com".to_string(),
        ]);
        let spec2 = ChainSpec::new("test.example.com").with_sans(vec![
            "b.example.com".to_string(),
            "a.example.com".to_string(),
        ]);
        assert_eq!(spec1.stable_bytes(), spec2.stable_bytes());
    }

    #[test]
    fn test_stable_bytes_field_sensitivity() {
        let base = ChainSpec::new("test.example.com");
        let base_bytes = base.stable_bytes();

        // Changing rsa_bits
        let changed = base.clone().with_rsa_bits(4096);
        assert_ne!(
            changed.stable_bytes(),
            base_bytes,
            "rsa_bits must affect stable_bytes"
        );

        // Changing root_validity_days
        let changed = base.clone().with_root_validity_days(999);
        assert_ne!(
            changed.stable_bytes(),
            base_bytes,
            "root_validity_days must affect stable_bytes"
        );

        // Changing intermediate_validity_days
        let changed = base.clone().with_intermediate_validity_days(999);
        assert_ne!(
            changed.stable_bytes(),
            base_bytes,
            "intermediate_validity_days must affect stable_bytes"
        );

        // Changing leaf_validity_days
        let changed = base.clone().with_leaf_validity_days(999);
        assert_ne!(
            changed.stable_bytes(),
            base_bytes,
            "leaf_validity_days must affect stable_bytes"
        );

        // Changing root_cn
        let changed = base.clone().with_root_cn("Other Root CA");
        assert_ne!(
            changed.stable_bytes(),
            base_bytes,
            "root_cn must affect stable_bytes"
        );

        // Changing intermediate_cn
        let changed = base.clone().with_intermediate_cn("Other Int CA");
        assert_ne!(
            changed.stable_bytes(),
            base_bytes,
            "intermediate_cn must affect stable_bytes"
        );

        // Changing leaf_sans
        let changed = base
            .clone()
            .with_sans(vec!["extra.example.com".to_string()]);
        assert_ne!(
            changed.stable_bytes(),
            base_bytes,
            "leaf_sans must affect stable_bytes"
        );
    }

    #[test]
    fn test_stable_bytes_optional_offset_sensitivity() {
        let base = ChainSpec::new("test.example.com");
        let base_bytes = base.stable_bytes();

        // leaf_not_before_offset_days: None vs Some(100)
        let mut with_leaf_offset = base.clone();
        with_leaf_offset.leaf_not_before = Some(NotBeforeOffset::DaysAgo(100));
        assert_ne!(
            with_leaf_offset.stable_bytes(),
            base_bytes,
            "leaf_not_before None vs Some must differ"
        );

        // leaf_not_before: DaysAgo(100) vs DaysFromNow(100)
        let mut with_leaf_offset2 = base.clone();
        with_leaf_offset2.leaf_not_before = Some(NotBeforeOffset::DaysFromNow(100));
        assert_ne!(
            with_leaf_offset.stable_bytes(),
            with_leaf_offset2.stable_bytes(),
            "leaf_not_before days-ago vs days-from-now must differ"
        );

        // intermediate_not_before: None vs Some(100)
        let mut with_int_offset = base.clone();
        with_int_offset.intermediate_not_before = Some(NotBeforeOffset::DaysAgo(100));
        assert_ne!(
            with_int_offset.stable_bytes(),
            base_bytes,
            "intermediate_not_before None vs Some must differ"
        );

        // intermediate_not_before: Some(100) vs Some(200)
        let mut with_int_offset2 = base.clone();
        with_int_offset2.intermediate_not_before = Some(NotBeforeOffset::DaysAgo(200));
        assert_ne!(
            with_int_offset.stable_bytes(),
            with_int_offset2.stable_bytes(),
            "intermediate_not_before Some(100) vs Some(200) must differ"
        );

        let with_int_is_ca = base.clone().with_intermediate_is_ca(false);
        assert_ne!(
            with_int_is_ca.stable_bytes(),
            base_bytes,
            "intermediate_is_ca must affect stable_bytes"
        );

        let with_int_ku = base.clone().with_intermediate_key_usage(KeyUsage::leaf());
        assert_ne!(
            with_int_ku.stable_bytes(),
            base_bytes,
            "intermediate_key_usage must affect stable_bytes"
        );
    }
}
