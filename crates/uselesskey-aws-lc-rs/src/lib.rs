#![forbid(unsafe_code)]

//! Integration between uselesskey test fixtures and `aws-lc-rs`.
//!
//! This crate provides extension traits that convert uselesskey fixtures into
//! `aws-lc-rs` native signing key types.
//!
//! # Features
//!
//! - `native` - Enable `aws-lc-rs` dependency (requires NASM on Windows). Disable for wasm-safe builds.
//! - `rsa` - RSA keypairs -> `aws_lc_rs::rsa::KeyPair`
//! - `ecdsa` - ECDSA keypairs -> `aws_lc_rs::signature::EcdsaKeyPair`
//! - `ed25519` - Ed25519 keypairs -> `aws_lc_rs::signature::Ed25519KeyPair`
//! - `all` - All key types above
//!
//! When the `native` feature is disabled, this crate compiles as a no-op
//! with no traits or implementations available.
//!
//! # Example: RSA sign and verify
//!
#![cfg_attr(
    all(feature = "native", any(not(windows), has_nasm), feature = "rsa"),
    doc = "```"
)]
#![cfg_attr(
    not(all(feature = "native", any(not(windows), has_nasm), feature = "rsa")),
    doc = "```ignore"
)]
//! use uselesskey_core::Factory;
//! use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
//! use uselesskey_aws_lc_rs::AwsLcRsRsaKeyPairExt;
//! use aws_lc_rs::signature;
//!
//! let fx = Factory::random();
//! let keypair = fx.rsa("test", RsaSpec::rs256());
//! let ring_kp = keypair.rsa_key_pair_aws_lc_rs();
//!
//! let rng = aws_lc_rs::rand::SystemRandom::new();
//! let msg = b"hello world";
//! let mut sig = vec![0u8; ring_kp.public_modulus_len()];
//! ring_kp.sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig).unwrap();
//! ```

// =========================================================================
// RSA
// =========================================================================

/// Extension trait to convert uselesskey RSA fixtures into `aws_lc_rs::rsa::KeyPair`.
#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "rsa"))]
pub trait AwsLcRsRsaKeyPairExt {
    /// Convert the RSA private key to an `aws_lc_rs::rsa::KeyPair`.
    fn rsa_key_pair_aws_lc_rs(&self) -> aws_lc_rs::rsa::KeyPair;
}

#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "rsa"))]
impl AwsLcRsRsaKeyPairExt for uselesskey_rsa::RsaKeyPair {
    fn rsa_key_pair_aws_lc_rs(&self) -> aws_lc_rs::rsa::KeyPair {
        aws_lc_rs::rsa::KeyPair::from_pkcs8(self.private_key_pkcs8_der())
            .expect("valid RSA PKCS#8 DER")
    }
}

// =========================================================================
// ECDSA
// =========================================================================

#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "ecdsa"))]
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING,
    EcdsaKeyPair as AwsLcRsEcdsaKeyPair, EcdsaSigningAlgorithm,
};

/// Extension trait to convert uselesskey ECDSA fixtures into `aws_lc_rs::signature::EcdsaKeyPair`.
#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "ecdsa"))]
pub trait AwsLcRsEcdsaKeyPairExt {
    /// Convert the ECDSA private key to an `aws_lc_rs::signature::EcdsaKeyPair`.
    ///
    /// The correct signing algorithm is chosen based on the curve (P-256 or P-384).
    fn ecdsa_key_pair_aws_lc_rs(&self) -> AwsLcRsEcdsaKeyPair;
}

#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "ecdsa"))]
impl AwsLcRsEcdsaKeyPairExt for uselesskey_ecdsa::EcdsaKeyPair {
    fn ecdsa_key_pair_aws_lc_rs(&self) -> AwsLcRsEcdsaKeyPair {
        let alg: &'static EcdsaSigningAlgorithm = match self.spec() {
            uselesskey_ecdsa::EcdsaSpec::Es256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
            uselesskey_ecdsa::EcdsaSpec::Es384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
        };
        AwsLcRsEcdsaKeyPair::from_pkcs8(alg, self.private_key_pkcs8_der())
            .expect("valid ECDSA PKCS#8 DER")
    }
}

// =========================================================================
// Ed25519
// =========================================================================

/// Extension trait to convert uselesskey Ed25519 fixtures into `aws_lc_rs::signature::Ed25519KeyPair`.
#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "ed25519"))]
pub trait AwsLcRsEd25519KeyPairExt {
    /// Convert the Ed25519 private key to an `aws_lc_rs::signature::Ed25519KeyPair`.
    fn ed25519_key_pair_aws_lc_rs(&self) -> aws_lc_rs::signature::Ed25519KeyPair;
}

#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "ed25519"))]
impl AwsLcRsEd25519KeyPairExt for uselesskey_ed25519::Ed25519KeyPair {
    fn ed25519_key_pair_aws_lc_rs(&self) -> aws_lc_rs::signature::Ed25519KeyPair {
        aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(self.private_key_pkcs8_der())
            .expect("valid Ed25519 PKCS#8 DER")
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;
    use uselesskey_core::{Factory, Seed};

    #[allow(dead_code)]
    static FX: OnceLock<Factory> = OnceLock::new();

    #[allow(dead_code)]
    fn fx() -> Factory {
        FX.get_or_init(|| {
            let seed = Seed::from_env_value("uselesskey-aws-lc-rs-inline-test-seed-v1")
                .expect("test seed should always parse");
            Factory::deterministic(seed)
        })
        .clone()
    }

    #[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "rsa"))]
    mod rsa_tests {
        use crate::AwsLcRsRsaKeyPairExt;
        use aws_lc_rs::signature::{self, KeyPair};
        use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

        #[test]
        fn test_rsa_sign_verify() {
            let fx = super::fx();
            let rsa = fx.rsa("test", RsaSpec::rs256());
            let kp = rsa.rsa_key_pair_aws_lc_rs();

            let msg = b"test message";
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let mut sig = vec![0u8; kp.public_modulus_len()];
            kp.sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
                .expect("sign");

            let public_key = kp.public_key();
            let public_key = signature::UnparsedPublicKey::new(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                public_key.as_ref(),
            );
            public_key.verify(msg, &sig).expect("verify");
        }
    }

    #[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "ecdsa"))]
    mod ecdsa_tests {
        use crate::AwsLcRsEcdsaKeyPairExt;
        use aws_lc_rs::signature::{self, KeyPair};
        use uselesskey_core::Factory;
        use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

        #[test]
        fn test_ecdsa_p256_sign_verify() {
            let fx = Factory::random();
            let ecdsa = fx.ecdsa("test", EcdsaSpec::es256());
            let kp = ecdsa.ecdsa_key_pair_aws_lc_rs();

            let msg = b"test message";
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let sig = kp.sign(&rng, msg).expect("sign");

            let public_key_bytes = kp.public_key().as_ref();
            let public_key = signature::UnparsedPublicKey::new(
                &signature::ECDSA_P256_SHA256_ASN1,
                public_key_bytes,
            );
            public_key.verify(msg, sig.as_ref()).expect("verify");
        }

        #[test]
        fn test_ecdsa_p384_sign_verify() {
            let fx = Factory::random();
            let ecdsa = fx.ecdsa("test", EcdsaSpec::es384());
            let kp = ecdsa.ecdsa_key_pair_aws_lc_rs();

            let msg = b"test message";
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let sig = kp.sign(&rng, msg).expect("sign");

            let public_key_bytes = kp.public_key().as_ref();
            let public_key = signature::UnparsedPublicKey::new(
                &signature::ECDSA_P384_SHA384_ASN1,
                public_key_bytes,
            );
            public_key.verify(msg, sig.as_ref()).expect("verify");
        }
    }

    #[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "ed25519"))]
    mod ed25519_tests {
        use crate::AwsLcRsEd25519KeyPairExt;
        use aws_lc_rs::signature::{self, KeyPair};
        use uselesskey_core::Factory;
        use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

        #[test]
        fn test_ed25519_sign_verify() {
            let fx = Factory::random();
            let ed = fx.ed25519("test", Ed25519Spec::new());
            let kp = ed.ed25519_key_pair_aws_lc_rs();

            let msg = b"test message";
            let sig = kp.sign(msg);

            let public_key_bytes = kp.public_key().as_ref();
            let public_key =
                signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
            public_key.verify(msg, sig.as_ref()).expect("verify");
        }
    }
}
