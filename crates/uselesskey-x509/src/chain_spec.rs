//! X.509 certificate chain specification.

/// Specification for generating a three-level X.509 certificate chain
/// (root CA → intermediate CA → leaf).
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
            leaf_validity_days: 365,
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

    /// Stable byte representation for deterministic derivation.
    ///
    /// SANs are sorted before encoding for ordering stability.
    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Version prefix
        out.push(1);

        // leaf_cn
        let leaf_cn_bytes = self.leaf_cn.as_bytes();
        out.extend_from_slice(&(leaf_cn_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(leaf_cn_bytes);

        // leaf_sans (sorted for stability)
        let mut sorted_sans = self.leaf_sans.clone();
        sorted_sans.sort();
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

        out
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
        assert_eq!(spec.leaf_validity_days, 365);
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
            .with_leaf_validity_days(90);

        assert_eq!(spec.leaf_sans.len(), 2);
        assert_eq!(spec.root_cn, "My Root CA");
        assert_eq!(spec.intermediate_cn, "My Int CA");
        assert_eq!(spec.rsa_bits, 4096);
        assert_eq!(spec.root_validity_days, 7300);
        assert_eq!(spec.intermediate_validity_days, 3650);
        assert_eq!(spec.leaf_validity_days, 90);
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
}
