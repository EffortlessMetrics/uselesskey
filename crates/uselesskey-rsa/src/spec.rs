/// Specification for RSA key generation.
///
/// This struct defines the parameters for generating RSA keypairs.
///
/// # Examples
///
/// ```
/// use uselesskey_rsa::RsaSpec;
///
/// // Common preset for JWT RS256 signing
/// let spec = RsaSpec::rs256();
/// assert_eq!(spec.bits, 2048);
/// assert_eq!(spec.exponent, 65537);
///
/// // Custom bit size (exponent defaults to 65537)
/// let spec = RsaSpec::new(4096);
/// assert_eq!(spec.bits, 4096);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RsaSpec {
    /// RSA modulus size in bits. Must be at least 1024.
    pub bits: usize,
    /// Public exponent. Currently only 65537 is supported.
    pub exponent: u32,
}

impl RsaSpec {
    /// Spec suitable for RS256 JWT signing in most ecosystems.
    ///
    /// Returns a spec with 2048 bits and exponent 65537.
    ///
    /// # Examples
    ///
    /// ```
    /// use uselesskey_rsa::RsaSpec;
    ///
    /// let spec = RsaSpec::rs256();
    /// assert_eq!(spec.bits, 2048);
    /// assert_eq!(spec.exponent, 65537);
    /// ```
    pub fn rs256() -> Self {
        Self {
            bits: 2048,
            exponent: 65537,
        }
    }

    /// Create a spec with custom bit size and default exponent (65537).
    ///
    /// # Panics
    ///
    /// The factory will panic if `bits < 1024`.
    ///
    /// # Examples
    ///
    /// ```
    /// use uselesskey_rsa::RsaSpec;
    ///
    /// let spec = RsaSpec::new(4096);
    /// assert_eq!(spec.bits, 4096);
    /// assert_eq!(spec.exponent, 65537);
    /// ```
    pub fn new(bits: usize) -> Self {
        Self {
            bits,
            exponent: 65537,
        }
    }

    /// Stable encoding for cache keys / deterministic derivation.
    ///
    /// If you change this, bump the derivation version in `uselesskey-core`.
    pub fn stable_bytes(&self) -> [u8; 8] {
        let bits = u32::try_from(self.bits).unwrap_or(u32::MAX);
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&bits.to_be_bytes());
        out[4..].copy_from_slice(&self.exponent.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rs256_defaults_are_expected() {
        let spec = RsaSpec::rs256();
        assert_eq!(spec.bits, 2048);
        assert_eq!(spec.exponent, 65537);
    }

    #[test]
    fn new_sets_bits_and_default_exponent() {
        let spec = RsaSpec::new(4096);
        assert_eq!(spec.bits, 4096);
        assert_eq!(spec.exponent, 65537);
    }

    #[test]
    fn stable_bytes_encodes_bits_and_exponent() {
        let spec = RsaSpec::rs256();
        let bytes = spec.stable_bytes();
        assert_eq!(&bytes[..4], &2048u32.to_be_bytes());
        assert_eq!(&bytes[4..], &65537u32.to_be_bytes());
    }

    #[test]
    fn stable_bytes_clamps_large_bits() {
        let spec = RsaSpec::new(usize::MAX);
        let bytes = spec.stable_bytes();
        assert_eq!(&bytes[..4], &u32::MAX.to_be_bytes());
    }
}
