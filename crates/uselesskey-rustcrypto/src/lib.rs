#![forbid(unsafe_code)]

//! Integration between uselesskey test fixtures and the RustCrypto ecosystem.
//!
//! This crate provides extension traits that convert uselesskey fixtures into
//! native RustCrypto types, making it easy to use test fixtures with code
//! that depends on the RustCrypto crates directly.
//!
//! # Features
//!
//! Enable the key types you need:
//!
//! - `rsa` - RSA keypairs -> `rsa::RsaPrivateKey` / `rsa::RsaPublicKey`
//! - `ecdsa` - ECDSA keypairs -> `p256::ecdsa::SigningKey` / `p384::ecdsa::SigningKey`
//! - `ed25519` - Ed25519 keypairs -> `ed25519_dalek::SigningKey` / `VerifyingKey`
//! - `hmac` - HMAC secrets -> `hmac::Hmac<Sha256>` / `Sha384` / `Sha512`
//! - `all` - All of the above
//!
//! # Example: RSA sign and verify
//!
#![cfg_attr(feature = "rsa", doc = "```")]
#![cfg_attr(not(feature = "rsa"), doc = "```ignore")]
//! use uselesskey_core::Factory;
//! use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
//! use uselesskey_rustcrypto::RustCryptoRsaExt;
//! use rsa::pkcs1v15::SigningKey;
//! use rsa::signature::{Signer, Verifier};
//! use sha2::Sha256;
//!
//! let fx = Factory::random();
//! let keypair = fx.rsa("test", RsaSpec::rs256());
//!
//! let private_key = keypair.rsa_private_key();
//! let signing_key = SigningKey::<Sha256>::new_unprefixed(private_key);
//! let signature = signing_key.sign(b"hello world");
//!
//! let public_key = keypair.rsa_public_key();
//! let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new_unprefixed(public_key);
//! verifying_key.verify(b"hello world", &signature).unwrap();
//! ```

// =========================================================================
// RSA
// =========================================================================

/// Extension trait to convert uselesskey RSA fixtures into RustCrypto `rsa` types.
#[cfg(feature = "rsa")]
pub trait RustCryptoRsaExt {
    /// Convert the RSA fixture to an `rsa::RsaPrivateKey`.
    fn rsa_private_key(&self) -> rsa::RsaPrivateKey;

    /// Derive the `rsa::RsaPublicKey` from the fixture's private key.
    fn rsa_public_key(&self) -> rsa::RsaPublicKey;
}

#[cfg(feature = "rsa")]
impl RustCryptoRsaExt for uselesskey_rsa::RsaKeyPair {
    fn rsa_private_key(&self) -> rsa::RsaPrivateKey {
        use rsa::pkcs8::DecodePrivateKey;
        rsa::RsaPrivateKey::from_pkcs8_der(self.private_key_pkcs8_der())
            .expect("valid RSA PKCS#8 DER")
    }

    fn rsa_public_key(&self) -> rsa::RsaPublicKey {
        rsa::RsaPublicKey::from(self.rsa_private_key())
    }
}

// =========================================================================
// ECDSA
// =========================================================================

/// Extension trait to convert uselesskey ECDSA fixtures into RustCrypto `p256`/`p384` types.
///
/// Call the method matching your curve. Calling a P-256 method on a P-384 key (or vice versa)
/// will panic.
#[cfg(feature = "ecdsa")]
pub trait RustCryptoEcdsaExt {
    /// Get the P-256 signing key. Panics if the key is not P-256.
    fn p256_signing_key(&self) -> p256::ecdsa::SigningKey;

    /// Get the P-256 verifying key. Panics if the key is not P-256.
    fn p256_verifying_key(&self) -> p256::ecdsa::VerifyingKey;

    /// Get the P-384 signing key. Panics if the key is not P-384.
    fn p384_signing_key(&self) -> p384::ecdsa::SigningKey;

    /// Get the P-384 verifying key. Panics if the key is not P-384.
    fn p384_verifying_key(&self) -> p384::ecdsa::VerifyingKey;
}

#[cfg(feature = "ecdsa")]
impl RustCryptoEcdsaExt for uselesskey_ecdsa::EcdsaKeyPair {
    fn p256_signing_key(&self) -> p256::ecdsa::SigningKey {
        assert!(
            matches!(self.spec(), uselesskey_ecdsa::EcdsaSpec::Es256),
            "expected P-256 key, got {:?}",
            self.spec()
        );
        use p256::pkcs8::DecodePrivateKey;
        p256::ecdsa::SigningKey::from_pkcs8_der(self.private_key_pkcs8_der())
            .expect("valid P-256 PKCS#8 DER")
    }

    fn p256_verifying_key(&self) -> p256::ecdsa::VerifyingKey {
        *self.p256_signing_key().verifying_key()
    }

    fn p384_signing_key(&self) -> p384::ecdsa::SigningKey {
        assert!(
            matches!(self.spec(), uselesskey_ecdsa::EcdsaSpec::Es384),
            "expected P-384 key, got {:?}",
            self.spec()
        );
        use p384::pkcs8::DecodePrivateKey;
        p384::ecdsa::SigningKey::from_pkcs8_der(self.private_key_pkcs8_der())
            .expect("valid P-384 PKCS#8 DER")
    }

    fn p384_verifying_key(&self) -> p384::ecdsa::VerifyingKey {
        *self.p384_signing_key().verifying_key()
    }
}

// =========================================================================
// Ed25519
// =========================================================================

/// Extension trait to convert uselesskey Ed25519 fixtures into `ed25519-dalek` types.
#[cfg(feature = "ed25519")]
pub trait RustCryptoEd25519Ext {
    /// Convert the Ed25519 fixture to an `ed25519_dalek::SigningKey`.
    fn ed25519_signing_key(&self) -> ed25519_dalek::SigningKey;

    /// Derive the `ed25519_dalek::VerifyingKey` from the fixture.
    fn ed25519_verifying_key(&self) -> ed25519_dalek::VerifyingKey;
}

#[cfg(feature = "ed25519")]
impl RustCryptoEd25519Ext for uselesskey_ed25519::Ed25519KeyPair {
    fn ed25519_signing_key(&self) -> ed25519_dalek::SigningKey {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        ed25519_dalek::SigningKey::from_pkcs8_der(self.private_key_pkcs8_der())
            .expect("valid Ed25519 PKCS#8 DER")
    }

    fn ed25519_verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.ed25519_signing_key().verifying_key()
    }
}

// =========================================================================
// HMAC
// =========================================================================

/// Extension trait to convert uselesskey HMAC fixtures into `hmac::Hmac` types.
#[cfg(feature = "hmac")]
pub trait RustCryptoHmacExt {
    /// Create an `Hmac<Sha256>` from the HMAC secret.
    fn hmac_sha256(&self) -> hmac::Hmac<sha2::Sha256>;

    /// Create an `Hmac<Sha384>` from the HMAC secret.
    fn hmac_sha384(&self) -> hmac::Hmac<sha2::Sha384>;

    /// Create an `Hmac<Sha512>` from the HMAC secret.
    fn hmac_sha512(&self) -> hmac::Hmac<sha2::Sha512>;
}

#[cfg(feature = "hmac")]
impl RustCryptoHmacExt for uselesskey_hmac::HmacSecret {
    fn hmac_sha256(&self) -> hmac::Hmac<sha2::Sha256> {
        use hmac::Mac;
        hmac::Hmac::<sha2::Sha256>::new_from_slice(self.secret_bytes())
            .expect("HMAC accepts any key length")
    }

    fn hmac_sha384(&self) -> hmac::Hmac<sha2::Sha384> {
        use hmac::Mac;
        hmac::Hmac::<sha2::Sha384>::new_from_slice(self.secret_bytes())
            .expect("HMAC accepts any key length")
    }

    fn hmac_sha512(&self) -> hmac::Hmac<sha2::Sha512> {
        use hmac::Mac;
        hmac::Hmac::<sha2::Sha512>::new_from_slice(self.secret_bytes())
            .expect("HMAC accepts any key length")
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    #[cfg(feature = "rsa")]
    mod rsa_tests {
        use crate::RustCryptoRsaExt;
        use rsa::pkcs1v15::{SigningKey, VerifyingKey};
        use rsa::signature::{Signer, Verifier};
        use sha2::Sha256;
        use uselesskey_core::Factory;
        use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

        #[test]
        fn test_rsa_sign_verify() {
            let fx = Factory::random();
            let keypair = fx.rsa("test", RsaSpec::rs256());

            let private_key = keypair.rsa_private_key();
            let signing_key = SigningKey::<Sha256>::new_unprefixed(private_key);
            let signature = signing_key.sign(b"test message");

            let public_key = keypair.rsa_public_key();
            let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(public_key);
            verifying_key
                .verify(b"test message", &signature)
                .expect("verify");
        }

        #[test]
        fn test_rsa_deterministic() {
            use uselesskey_core::Seed;

            let seed = Seed::from_env_value("test-seed").unwrap();
            let fx = Factory::deterministic(seed);
            let keypair = fx.rsa("det-test", RsaSpec::rs256());

            let private_key = keypair.rsa_private_key();
            let signing_key = SigningKey::<Sha256>::new_unprefixed(private_key);
            let signature = signing_key.sign(b"deterministic");

            let public_key = keypair.rsa_public_key();
            let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(public_key);
            verifying_key
                .verify(b"deterministic", &signature)
                .expect("verify");
        }
    }

    #[cfg(feature = "ecdsa")]
    mod ecdsa_tests {
        use crate::RustCryptoEcdsaExt;
        use uselesskey_core::Factory;
        use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

        #[test]
        fn test_p256_sign_verify() {
            use p256::ecdsa::signature::{Signer, Verifier};

            let fx = Factory::random();
            let keypair = fx.ecdsa("test", EcdsaSpec::es256());

            let signing_key = keypair.p256_signing_key();
            let signature: p256::ecdsa::Signature = signing_key.sign(b"test message");

            let verifying_key = keypair.p256_verifying_key();
            verifying_key
                .verify(b"test message", &signature)
                .expect("verify");
        }

        #[test]
        fn test_p384_sign_verify() {
            use p384::ecdsa::signature::{Signer, Verifier};

            let fx = Factory::random();
            let keypair = fx.ecdsa("test", EcdsaSpec::es384());

            let signing_key = keypair.p384_signing_key();
            let signature: p384::ecdsa::Signature = signing_key.sign(b"test message");

            let verifying_key = keypair.p384_verifying_key();
            verifying_key
                .verify(b"test message", &signature)
                .expect("verify");
        }

        #[test]
        #[should_panic(expected = "expected P-384")]
        fn test_p384_on_p256_key_panics() {
            let fx = Factory::random();
            let keypair = fx.ecdsa("test", EcdsaSpec::es256());
            let _ = keypair.p384_signing_key();
        }

        #[test]
        #[should_panic(expected = "expected P-256")]
        fn test_p256_on_p384_key_panics() {
            let fx = Factory::random();
            let keypair = fx.ecdsa("test", EcdsaSpec::es384());
            let _ = keypair.p256_signing_key();
        }
    }

    #[cfg(feature = "ed25519")]
    mod ed25519_tests {
        use crate::RustCryptoEd25519Ext;
        use ed25519_dalek::Signer;
        use ed25519_dalek::Verifier;
        use uselesskey_core::Factory;
        use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

        #[test]
        fn test_ed25519_sign_verify() {
            let fx = Factory::random();
            let keypair = fx.ed25519("test", Ed25519Spec::new());

            let signing_key = keypair.ed25519_signing_key();
            let signature = signing_key.sign(b"test message");

            let verifying_key = keypair.ed25519_verifying_key();
            verifying_key
                .verify(b"test message", &signature)
                .expect("verify");
        }
    }

    #[cfg(feature = "hmac")]
    mod hmac_tests {
        use crate::RustCryptoHmacExt;
        use hmac::Mac;
        use uselesskey_core::Factory;
        use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

        #[test]
        fn test_hmac_sha256() {
            let fx = Factory::random();
            let secret = fx.hmac("test", HmacSpec::hs256());

            let mut mac = secret.hmac_sha256();
            mac.update(b"test message");
            let result = mac.finalize();

            // Verify with a fresh instance
            let mut mac2 = secret.hmac_sha256();
            mac2.update(b"test message");
            mac2.verify(&result.into_bytes()).expect("verify");
        }

        #[test]
        fn test_hmac_sha384() {
            let fx = Factory::random();
            let secret = fx.hmac("test", HmacSpec::hs384());

            let mut mac = secret.hmac_sha384();
            mac.update(b"test message");
            let result = mac.finalize();

            let mut mac2 = secret.hmac_sha384();
            mac2.update(b"test message");
            mac2.verify(&result.into_bytes()).expect("verify");
        }

        #[test]
        fn test_hmac_sha512() {
            let fx = Factory::random();
            let secret = fx.hmac("test", HmacSpec::hs512());

            let mut mac = secret.hmac_sha512();
            mac.update(b"test message");
            let result = mac.finalize();

            let mut mac2 = secret.hmac_sha512();
            mac2.update(b"test message");
            mac2.verify(&result.into_bytes()).expect("verify");
        }
    }
}
