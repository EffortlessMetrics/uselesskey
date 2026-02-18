use std::fmt;
use std::sync::Arc;

use pgp::composed::{EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedPublicKey};
use pgp::ser::Serialize;
use pgp::types::KeyDetails;
use uselesskey_core::negative::{
    CorruptPem, corrupt_der_deterministic, corrupt_pem, corrupt_pem_deterministic, truncate_der,
};
use uselesskey_core::sink::TempArtifact;
use uselesskey_core::{Error, Factory};

use crate::PgpSpec;

/// Cache domain for OpenPGP keypair fixtures.
///
/// Keep this stable: changing it changes deterministic outputs.
pub const DOMAIN_PGP_KEYPAIR: &str = "uselesskey:pgp:keypair";

#[derive(Clone)]
pub struct PgpKeyPair {
    factory: Factory,
    label: String,
    spec: PgpSpec,
    inner: Arc<Inner>,
}

struct Inner {
    user_id: String,
    fingerprint: String,
    private_binary: Arc<[u8]>,
    private_armor: String,
    public_binary: Arc<[u8]>,
    public_armor: String,
}

impl fmt::Debug for PgpKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgpKeyPair")
            .field("label", &self.label)
            .field("spec", &self.spec)
            .field("fingerprint", &self.inner.fingerprint)
            .finish_non_exhaustive()
    }
}

/// Extension trait to hang OpenPGP helpers off the core [`Factory`].
pub trait PgpFactoryExt {
    fn pgp(&self, label: impl AsRef<str>, spec: PgpSpec) -> PgpKeyPair;
}

impl PgpFactoryExt for Factory {
    fn pgp(&self, label: impl AsRef<str>, spec: PgpSpec) -> PgpKeyPair {
        PgpKeyPair::new(self.clone(), label.as_ref(), spec)
    }
}

impl PgpKeyPair {
    fn new(factory: Factory, label: &str, spec: PgpSpec) -> Self {
        let inner = load_inner(&factory, label, spec, "good");
        Self {
            factory,
            label: label.to_string(),
            spec,
            inner,
        }
    }

    fn load_variant(&self, variant: &str) -> Arc<Inner> {
        load_inner(&self.factory, &self.label, self.spec, variant)
    }

    /// Returns the fixture spec.
    pub fn spec(&self) -> PgpSpec {
        self.spec
    }

    /// Returns the generated OpenPGP user id.
    pub fn user_id(&self) -> &str {
        &self.inner.user_id
    }

    /// Returns the OpenPGP key fingerprint.
    pub fn fingerprint(&self) -> &str {
        &self.inner.fingerprint
    }

    /// Binary transferable secret key bytes.
    pub fn private_key_binary(&self) -> &[u8] {
        &self.inner.private_binary
    }

    /// Armored transferable secret key.
    pub fn private_key_armored(&self) -> &str {
        &self.inner.private_armor
    }

    /// Binary transferable public key bytes.
    pub fn public_key_binary(&self) -> &[u8] {
        &self.inner.public_binary
    }

    /// Armored transferable public key.
    pub fn public_key_armored(&self) -> &str {
        &self.inner.public_armor
    }

    /// Write the armored private key to a tempfile.
    pub fn write_private_key_armored(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".pgp.priv.asc", self.private_key_armored())
    }

    /// Write the armored public key to a tempfile.
    pub fn write_public_key_armored(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".pgp.pub.asc", self.public_key_armored())
    }

    /// Produce a corrupted armored private key variant.
    pub fn private_key_armored_corrupt(&self, how: CorruptPem) -> String {
        corrupt_pem(self.private_key_armored(), how)
    }

    /// Produce a deterministic corrupted armored private key using a variant string.
    pub fn private_key_armored_corrupt_deterministic(&self, variant: &str) -> String {
        corrupt_pem_deterministic(self.private_key_armored(), variant)
    }

    /// Produce a truncated private key binary variant.
    pub fn private_key_binary_truncated(&self, len: usize) -> Vec<u8> {
        truncate_der(self.private_key_binary(), len)
    }

    /// Produce a deterministic corrupted private key binary using a variant string.
    pub fn private_key_binary_corrupt_deterministic(&self, variant: &str) -> Vec<u8> {
        corrupt_der_deterministic(self.private_key_binary(), variant)
    }

    /// Return a valid (parseable) public key that does not match this private key.
    pub fn mismatched_public_key_binary(&self) -> Vec<u8> {
        let other = self.load_variant("mismatch");
        other.public_binary.as_ref().to_vec()
    }

    /// Return an armored public key that does not match this private key.
    pub fn mismatched_public_key_armored(&self) -> String {
        let other = self.load_variant("mismatch");
        other.public_armor.clone()
    }
}

fn load_inner(factory: &Factory, label: &str, spec: PgpSpec, variant: &str) -> Arc<Inner> {
    let spec_bytes = spec.stable_bytes();

    factory.get_or_init(DOMAIN_PGP_KEYPAIR, label, &spec_bytes, variant, |rng| {
        let user_id = build_user_id(label);

        let mut key_params = SecretKeyParamsBuilder::default();
        key_params
            .key_type(spec_to_key_type(spec))
            .can_certify(true)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id(user_id.clone());

        let secret_key_params = key_params
            .build()
            .expect("failed to build OpenPGP secret key params");

        let secret_key = secret_key_params
            .generate(rng)
            .expect("OpenPGP key generation failed");
        let public_key = SignedPublicKey::from(secret_key.clone());

        let mut private_binary = Vec::new();
        secret_key
            .to_writer(&mut private_binary)
            .expect("failed to encode OpenPGP private key bytes");

        let mut public_binary = Vec::new();
        public_key
            .to_writer(&mut public_binary)
            .expect("failed to encode OpenPGP public key bytes");

        let private_armor = secret_key
            .to_armored_string(None.into())
            .expect("failed to armor OpenPGP private key");
        let public_armor = public_key
            .to_armored_string(None.into())
            .expect("failed to armor OpenPGP public key");

        Inner {
            user_id,
            fingerprint: secret_key.fingerprint().to_string(),
            private_binary: Arc::from(private_binary),
            private_armor,
            public_binary: Arc::from(public_binary),
            public_armor,
        }
    })
}

fn spec_to_key_type(spec: PgpSpec) -> KeyType {
    match spec {
        PgpSpec::Rsa2048 => KeyType::Rsa(2048),
        PgpSpec::Rsa3072 => KeyType::Rsa(3072),
        PgpSpec::Ed25519 => KeyType::Ed25519,
    }
}

fn build_user_id(label: &str) -> String {
    let display = if label.trim().is_empty() {
        "fixture"
    } else {
        label.trim()
    };

    let mut local = String::new();
    for ch in display.chars() {
        if ch.is_ascii_alphanumeric() {
            local.push(ch.to_ascii_lowercase());
        } else if !local.ends_with('-') {
            local.push('-');
        }
    }

    let local = local.trim_matches('-');
    let local = if local.is_empty() { "fixture" } else { local };

    format!("{display} <{local}@uselesskey.test>")
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};
    use pgp::types::KeyDetails;
    use uselesskey_core::Seed;

    use super::*;

    #[test]
    fn deterministic_key_is_stable() {
        let fx = Factory::deterministic(Seed::from_env_value("pgp-det").unwrap());
        let a = fx.pgp("issuer", PgpSpec::ed25519());
        let b = fx.pgp("issuer", PgpSpec::ed25519());

        assert_eq!(a.private_key_armored(), b.private_key_armored());
        assert_eq!(a.public_key_armored(), b.public_key_armored());
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn random_mode_caches_per_identity() {
        let fx = Factory::random();
        let a = fx.pgp("issuer", PgpSpec::rsa_2048());
        let b = fx.pgp("issuer", PgpSpec::rsa_2048());

        assert_eq!(a.private_key_armored(), b.private_key_armored());
    }

    #[test]
    fn different_labels_produce_different_keys() {
        let fx = Factory::deterministic(Seed::from_env_value("pgp-label").unwrap());
        let a = fx.pgp("a", PgpSpec::rsa_3072());
        let b = fx.pgp("b", PgpSpec::rsa_3072());

        assert_ne!(a.private_key_binary(), b.private_key_binary());
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn armored_outputs_have_expected_headers() {
        let fx = Factory::random();
        let key = fx.pgp("issuer", PgpSpec::ed25519());

        assert!(
            key.private_key_armored()
                .contains("BEGIN PGP PRIVATE KEY BLOCK")
        );
        assert!(
            key.public_key_armored()
                .contains("BEGIN PGP PUBLIC KEY BLOCK")
        );
    }

    #[test]
    fn armored_outputs_parse_and_match_fingerprint() {
        let fx = Factory::random();
        let key = fx.pgp("parser", PgpSpec::ed25519());

        let (secret, _) =
            SignedSecretKey::from_armor_single(Cursor::new(key.private_key_armored()))
                .expect("parse armored private key");
        secret.verify_bindings().expect("verify private bindings");

        let (public, _) = SignedPublicKey::from_armor_single(Cursor::new(key.public_key_armored()))
            .expect("parse armored public key");
        public.verify_bindings().expect("verify public bindings");

        assert_eq!(secret.fingerprint().to_string(), key.fingerprint());
        assert_eq!(public.fingerprint().to_string(), key.fingerprint());
    }

    #[test]
    fn binary_outputs_parse() {
        let fx = Factory::random();
        let key = fx.pgp("binary", PgpSpec::rsa_2048());

        let secret = SignedSecretKey::from_bytes(Cursor::new(key.private_key_binary()))
            .expect("parse private key bytes");
        let public = SignedPublicKey::from_bytes(Cursor::new(key.public_key_binary()))
            .expect("parse public key bytes");

        assert_eq!(secret.fingerprint().to_string(), key.fingerprint());
        assert_eq!(public.fingerprint().to_string(), key.fingerprint());
    }

    #[test]
    fn mismatched_public_key_differs() {
        let fx = Factory::deterministic(Seed::from_env_value("pgp-mismatch").unwrap());
        let key = fx.pgp("issuer", PgpSpec::ed25519());

        let mismatch = key.mismatched_public_key_binary();
        assert_ne!(mismatch, key.public_key_binary());
    }

    #[test]
    fn user_id_is_exposed_and_sanitized() {
        let fx = Factory::deterministic(Seed::from_env_value("pgp-user-id").unwrap());
        let key = fx.pgp("Test User!@#", PgpSpec::ed25519());
        let blank = fx.pgp("   ", PgpSpec::ed25519());

        assert_eq!(key.user_id(), "Test User!@# <test-user@uselesskey.test>");
        assert_eq!(blank.user_id(), "fixture <fixture@uselesskey.test>");
    }

    #[test]
    fn armored_corruption_helpers_are_invalid_and_stable() {
        let fx = Factory::deterministic(Seed::from_env_value("pgp-corrupt-armor").unwrap());
        let key = fx.pgp("issuer", PgpSpec::ed25519());

        let bad = key.private_key_armored_corrupt(CorruptPem::BadBase64);
        assert_ne!(bad, key.private_key_armored());
        assert!(bad.contains("THIS_IS_NOT_BASE64!!!"));
        assert!(SignedSecretKey::from_armor_single(Cursor::new(&bad)).is_err());

        let det_a = key.private_key_armored_corrupt_deterministic("corrupt:v1");
        let det_b = key.private_key_armored_corrupt_deterministic("corrupt:v1");
        assert_eq!(det_a, det_b);
        assert_ne!(det_a, key.private_key_armored());
        assert!(det_a.starts_with('-'));
        assert!(SignedSecretKey::from_armor_single(Cursor::new(&det_a)).is_err());
    }

    #[test]
    fn binary_corruption_helpers_are_invalid_and_stable() {
        let fx = Factory::deterministic(Seed::from_env_value("pgp-corrupt-bin").unwrap());
        let key = fx.pgp("issuer", PgpSpec::ed25519());

        let truncated = key.private_key_binary_truncated(32);
        assert_eq!(truncated.len(), 32);
        assert!(SignedSecretKey::from_bytes(Cursor::new(&truncated)).is_err());

        let det_a = key.private_key_binary_corrupt_deterministic("corrupt:v1");
        let det_b = key.private_key_binary_corrupt_deterministic("corrupt:v1");
        assert_eq!(det_a, det_b);
        assert_ne!(det_a, key.private_key_binary());
        assert_eq!(det_a.len(), key.private_key_binary().len());
    }

    #[test]
    fn mismatched_public_key_variants_parse_and_fingerprint_differs() {
        let fx = Factory::deterministic(Seed::from_env_value("pgp-mismatch-parse").unwrap());
        let key = fx.pgp("issuer", PgpSpec::ed25519());

        let mismatch_bin = key.mismatched_public_key_binary();
        let mismatch_pub = SignedPublicKey::from_bytes(Cursor::new(&mismatch_bin))
            .expect("parse mismatched public binary");
        assert_ne!(mismatch_pub.fingerprint().to_string(), key.fingerprint());

        let mismatch_arm = key.mismatched_public_key_armored();
        assert_ne!(mismatch_arm, key.public_key_armored());
        let (mismatch_pub_arm, _) = SignedPublicKey::from_armor_single(Cursor::new(&mismatch_arm))
            .expect("parse mismatched public armor");
        assert_ne!(
            mismatch_pub_arm.fingerprint().to_string(),
            key.fingerprint()
        );
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let fx = Factory::random();
        let key = fx.pgp("debug", PgpSpec::ed25519());
        let dbg = format!("{key:?}");

        assert!(dbg.contains("PgpKeyPair"));
        assert!(dbg.contains("debug"));
        assert!(!dbg.contains("BEGIN PGP PRIVATE KEY BLOCK"));
    }
}
