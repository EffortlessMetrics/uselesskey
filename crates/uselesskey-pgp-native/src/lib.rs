#![forbid(unsafe_code)]

//! OpenPGP native adapters for uselesskey fixtures.
//!
//! Provides conversions to native `pgp` crate key types from
//! `uselesskey-pgp` generated fixtures.

use std::io::Cursor;

use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};

/// Conversion surface for OpenPGP native key types.
pub trait PgpNativeExt {
    /// Parse and return a native `SignedSecretKey`.
    fn secret_key(&self) -> SignedSecretKey;

    /// Parse and return a native `SignedPublicKey`.
    fn public_key(&self) -> SignedPublicKey;

    /// Parse and return an armored native secret key.
    fn secret_key_armor(&self) -> SignedSecretKey;

    /// Parse and return an armored native public key.
    fn public_key_armor(&self) -> SignedPublicKey;
}

impl PgpNativeExt for uselesskey_pgp::PgpKeyPair {
    fn secret_key(&self) -> SignedSecretKey {
        SignedSecretKey::from_bytes(Cursor::new(self.private_key_binary()))
            .expect("failed to parse uselesskey PGP private key bytes")
    }

    fn public_key(&self) -> SignedPublicKey {
        SignedPublicKey::from_bytes(Cursor::new(self.public_key_binary()))
            .expect("failed to parse uselesskey PGP public key bytes")
    }

    fn secret_key_armor(&self) -> SignedSecretKey {
        let (key, _) = SignedSecretKey::from_armor_single(Cursor::new(self.private_key_armored()))
            .expect("failed to parse armored uselesskey PGP private key");
        key
    }

    fn public_key_armor(&self) -> SignedPublicKey {
        let (key, _) = SignedPublicKey::from_armor_single(Cursor::new(self.public_key_armored()))
            .expect("failed to parse armored uselesskey PGP public key");
        key
    }
}

#[cfg(test)]
mod tests {
    use pgp::types::KeyDetails;
    use uselesskey_core::Factory;
    use uselesskey_pgp::{PgpFactoryExt, PgpSpec};

    use super::PgpNativeExt;

    #[test]
    fn parse_round_trip_binary_and_armor() {
        let fx = Factory::random();
        let keypair = fx.pgp("fixture", PgpSpec::ed25519());

        assert_eq!(keypair.fingerprint(), keypair.secret_key().fingerprint().to_string());
        assert_eq!(keypair.fingerprint(), keypair.secret_key_armor().fingerprint().to_string());
        assert_eq!(keypair.fingerprint(), keypair.public_key().fingerprint().to_string());
        assert_eq!(keypair.fingerprint(), keypair.public_key_armor().fingerprint().to_string());
    }
}
