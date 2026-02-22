#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Arc;

use uselesskey_core::Error;
use uselesskey_core::negative::{
    CorruptPem, corrupt_der_deterministic, corrupt_pem, corrupt_pem_deterministic, truncate_der,
};
use uselesskey_core::sink::TempArtifact;
use uselesskey_core_kid::kid_from_bytes;

/// Common PKCS#8/SPKI key material shared by multiple fixture crates.
#[derive(Clone)]
pub struct Pkcs8SpkiKeyMaterial {
    pkcs8_der: Arc<[u8]>,
    pkcs8_pem: String,
    spki_der: Arc<[u8]>,
    spki_pem: String,
}

impl fmt::Debug for Pkcs8SpkiKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs8SpkiKeyMaterial")
            .field("pkcs8_der_len", &self.pkcs8_der.len())
            .field("pkcs8_pem_len", &self.pkcs8_pem.len())
            .field("spki_der_len", &self.spki_der.len())
            .field("spki_pem_len", &self.spki_pem.len())
            .finish_non_exhaustive()
    }
}

impl Pkcs8SpkiKeyMaterial {
    /// Build a material container from PKCS#8 and SPKI forms.
    pub fn new(
        pkcs8_der: impl Into<Arc<[u8]>>,
        pkcs8_pem: impl Into<String>,
        spki_der: impl Into<Arc<[u8]>>,
        spki_pem: impl Into<String>,
    ) -> Self {
        Self {
            pkcs8_der: pkcs8_der.into(),
            pkcs8_pem: pkcs8_pem.into(),
            spki_der: spki_der.into(),
            spki_pem: spki_pem.into(),
        }
    }

    /// PKCS#8 DER-encoded private key bytes.
    pub fn private_key_pkcs8_der(&self) -> &[u8] {
        &self.pkcs8_der
    }

    /// PKCS#8 PEM-encoded private key.
    pub fn private_key_pkcs8_pem(&self) -> &str {
        &self.pkcs8_pem
    }

    /// SPKI DER-encoded public key bytes.
    pub fn public_key_spki_der(&self) -> &[u8] {
        &self.spki_der
    }

    /// SPKI PEM-encoded public key.
    pub fn public_key_spki_pem(&self) -> &str {
        &self.spki_pem
    }

    /// Write the PKCS#8 PEM private key to a tempfile and return the handle.
    pub fn write_private_key_pkcs8_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".pkcs8.pem", self.private_key_pkcs8_pem())
    }

    /// Write the SPKI PEM public key to a tempfile and return the handle.
    pub fn write_public_key_spki_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".spki.pem", self.public_key_spki_pem())
    }

    /// Produce a corrupted variant of the PKCS#8 PEM.
    pub fn private_key_pkcs8_pem_corrupt(&self, how: CorruptPem) -> String {
        corrupt_pem(self.private_key_pkcs8_pem(), how)
    }

    /// Produce a deterministic corrupted PKCS#8 PEM using a variant string.
    pub fn private_key_pkcs8_pem_corrupt_deterministic(&self, variant: &str) -> String {
        corrupt_pem_deterministic(self.private_key_pkcs8_pem(), variant)
    }

    /// Produce a truncated variant of the PKCS#8 DER.
    pub fn private_key_pkcs8_der_truncated(&self, len: usize) -> Vec<u8> {
        truncate_der(self.private_key_pkcs8_der(), len)
    }

    /// Produce a deterministic corrupted PKCS#8 DER using a variant string.
    pub fn private_key_pkcs8_der_corrupt_deterministic(&self, variant: &str) -> Vec<u8> {
        corrupt_der_deterministic(self.private_key_pkcs8_der(), variant)
    }

    /// A stable key identifier derived from the SPKI bytes.
    pub fn kid(&self) -> String {
        kid_from_bytes(self.public_key_spki_der())
    }
}

#[cfg(test)]
mod tests {
    use super::Pkcs8SpkiKeyMaterial;
    use uselesskey_core::negative::CorruptPem;

    fn sample_material() -> Pkcs8SpkiKeyMaterial {
        Pkcs8SpkiKeyMaterial::new(
            vec![0x30, 0x82, 0x01, 0x22],
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n".to_string(),
            vec![0x30, 0x59, 0x30, 0x13],
            "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----\n".to_string(),
        )
    }

    #[test]
    fn accessors_expose_material() {
        let material = sample_material();

        assert_eq!(material.private_key_pkcs8_der(), &[0x30, 0x82, 0x01, 0x22]);
        assert!(
            material
                .private_key_pkcs8_pem()
                .contains("BEGIN PRIVATE KEY")
        );
        assert_eq!(material.public_key_spki_der(), &[0x30, 0x59, 0x30, 0x13]);
        assert!(material.public_key_spki_pem().contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn debug_does_not_include_key_pem() {
        let material = sample_material();
        let dbg = format!("{material:?}");
        assert!(dbg.contains("Pkcs8SpkiKeyMaterial"));
        assert!(!dbg.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn private_key_pkcs8_pem_corrupt() {
        let material = sample_material();
        let corrupted = material.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
        assert_ne!(corrupted, material.private_key_pkcs8_pem());
        assert!(corrupted.contains("CORRUPTED KEY"));
    }

    #[test]
    fn deterministic_corruption_is_stable() {
        let material = sample_material();
        let a = material.private_key_pkcs8_pem_corrupt_deterministic("core-keypair:v1");
        let b = material.private_key_pkcs8_pem_corrupt_deterministic("core-keypair:v1");
        assert_eq!(a, b);
        assert_ne!(a, material.private_key_pkcs8_pem());
        // Must still look like (corrupted) PEM, not a constant like "" or "xyzzy"
        assert!(a.contains("-----"));
    }

    #[test]
    fn truncation_respects_requested_length() {
        let material = sample_material();
        let truncated = material.private_key_pkcs8_der_truncated(2);
        assert_eq!(truncated.len(), 2);
    }

    #[test]
    fn private_key_pkcs8_der_corrupt_deterministic() {
        let material = sample_material();
        let a = material.private_key_pkcs8_der_corrupt_deterministic("variant-a");
        let b = material.private_key_pkcs8_der_corrupt_deterministic("variant-a");
        assert_eq!(a, b);
        assert_ne!(a, material.private_key_pkcs8_der());
        // Different variants must produce different corruption — a constant return can't satisfy this
        let c = material.private_key_pkcs8_der_corrupt_deterministic("variant-b");
        assert_ne!(a, c);
    }

    #[test]
    fn kid_is_deterministic() {
        let material = sample_material();
        let a = material.kid();
        let b = material.kid();
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn kid_depends_on_spki_bytes() {
        let m1 = sample_material();
        let m2 = Pkcs8SpkiKeyMaterial::new(
            vec![0x30, 0x82, 0x01, 0x22],
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            vec![0xFF, 0xFE, 0xFD, 0xFC],
            "-----BEGIN PUBLIC KEY-----\nCCCC\n-----END PUBLIC KEY-----\n",
        );
        assert_ne!(m1.kid(), m2.kid());
    }

    #[test]
    fn tempfile_writers_round_trip_content() {
        let material = sample_material();

        let private = material
            .write_private_key_pkcs8_pem()
            .expect("write private");
        let public = material.write_public_key_spki_pem().expect("write public");

        let private_text = private.read_to_string().expect("read private");
        let public_text = public.read_to_string().expect("read public");

        assert!(private_text.contains("BEGIN PRIVATE KEY"));
        assert!(public_text.contains("BEGIN PUBLIC KEY"));
    }
}
