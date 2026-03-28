#![forbid(unsafe_code)]

//! proptest strategy builders for `uselesskey` fixtures.
//!
//! This crate helps downstream tests and fuzz harnesses sample realistic,
//! deterministic fixture *objects* (not tuples).

use proptest::prelude::*;
use proptest::strategy::BoxedStrategy;
use uselesskey::{
    ChainNegative, ChainSpec, EcdsaFactoryExt, EcdsaKeyPair, EcdsaSpec, Ed25519FactoryExt,
    Ed25519KeyPair, Ed25519Spec, Factory, HmacFactoryExt, HmacSecret, HmacSpec, RsaFactoryExt,
    RsaKeyPair, RsaSpec, TokenFactoryExt, TokenFixture, TokenSpec, X509Chain, X509FactoryExt,
};

/// A valid asymmetric fixture sampled from RSA, ECDSA, or Ed25519.
#[derive(Clone, Debug)]
pub enum ValidAsymmetricFixture {
    /// RSA keypair fixture.
    Rsa(RsaKeyPair),
    /// ECDSA keypair fixture.
    Ecdsa(EcdsaKeyPair),
    /// Ed25519 keypair fixture.
    Ed25519(Ed25519KeyPair),
}

/// A deterministic negative PEM/DER fixture built from an underlying valid key fixture.
#[derive(Clone, Debug)]
pub struct NegativePemDerFixture {
    /// Human-readable family marker.
    pub family: &'static str,
    /// Fixture label used for generation.
    pub label: String,
    /// Corrupted private-key PEM.
    pub private_key_pem_corrupt: String,
    /// Corrupted private-key DER.
    pub private_key_der_corrupt: Vec<u8>,
}

/// A valid-or-corrupt JWK profile output.
#[derive(Clone, Debug)]
pub enum JwkFixture {
    /// Valid JWK JSON value.
    Valid(serde_json::Value),
    /// Corrupt JWK JSON value.
    Corrupt(serde_json::Value),
}

/// A negative X.509 chain profile output.
#[derive(Clone, Debug)]
pub struct X509ChainNegativeFixture {
    /// The negative variant used to derive the chain.
    pub variant: ChainNegative,
    /// The resulting negative chain fixture.
    pub chain: X509Chain,
}

fn deterministic_factory(id: u64) -> Factory {
    Factory::deterministic_from_str(&format!("uselesskey-proptest:{id}"))
}

fn label(prefix: &str, n: u32) -> String {
    format!("{prefix}-{n:08x}")
}

/// Strategy for valid RSA fixtures.
pub fn valid_rsa_fixture() -> BoxedStrategy<RsaKeyPair> {
    (any::<u64>(), prop_oneof![Just(RsaSpec::rs256()), Just(RsaSpec::new(3072))])
        .prop_map(|(seed, spec)| {
            let fx = deterministic_factory(seed);
            fx.rsa(label("rsa", seed as u32), spec)
        })
        .boxed()
}

/// Strategy for valid ECDSA fixtures.
pub fn valid_ecdsa_fixture() -> BoxedStrategy<EcdsaKeyPair> {
    (any::<u64>(), prop_oneof![Just(EcdsaSpec::es256()), Just(EcdsaSpec::es384())])
        .prop_map(|(seed, spec)| {
            let fx = deterministic_factory(seed);
            fx.ecdsa(label("ecdsa", seed as u32), spec)
        })
        .boxed()
}

/// Strategy for valid Ed25519 fixtures.
pub fn valid_ed25519_fixture() -> BoxedStrategy<Ed25519KeyPair> {
    any::<u64>()
        .prop_map(|seed| {
            let fx = deterministic_factory(seed);
            fx.ed25519(label("ed25519", seed as u32), Ed25519Spec::new())
        })
        .boxed()
}

/// Strategy for valid HMAC fixtures.
pub fn valid_hmac_fixture() -> BoxedStrategy<HmacSecret> {
    (
        any::<u64>(),
        prop_oneof![
            Just(HmacSpec::hs256()),
            Just(HmacSpec::hs384()),
            Just(HmacSpec::hs512())
        ],
    )
        .prop_map(|(seed, spec)| {
            let fx = deterministic_factory(seed);
            fx.hmac(label("hmac", seed as u32), spec)
        })
        .boxed()
}

/// Strategy for token fixtures.
pub fn token_fixture() -> BoxedStrategy<TokenFixture> {
    (
        any::<u64>(),
        prop_oneof![
            Just(TokenSpec::api_key()),
            Just(TokenSpec::bearer()),
            Just(TokenSpec::oauth_access_token())
        ],
    )
        .prop_map(|(seed, spec)| {
            let fx = deterministic_factory(seed);
            fx.token(label("token", seed as u32), spec)
        })
        .boxed()
}

/// Strategy for valid X.509 chains.
pub fn valid_x509_chain() -> BoxedStrategy<X509Chain> {
    any::<u64>()
        .prop_map(|seed| {
            let fx = deterministic_factory(seed);
            fx.x509_chain(
                label("chain", seed as u32),
                ChainSpec::new(format!("svc-{seed}.example.test")),
            )
        })
        .boxed()
}

/// Strategy for negative PEM/DER fixtures.
///
/// Reuses deterministic corruption builders from fixture keypair types.
pub fn negative_pem_der_fixture() -> BoxedStrategy<NegativePemDerFixture> {
    (any::<u64>(), any::<u8>())
        .prop_map(|(seed, variant_idx)| {
            let fx = deterministic_factory(seed);
            let variant = format!("corrupt:v{variant_idx}");
            let tag = label("neg", seed as u32);

            match variant_idx % 3 {
                0 => {
                    let kp = fx.rsa(&tag, RsaSpec::rs256());
                    NegativePemDerFixture {
                        family: "rsa",
                        label: tag,
                        private_key_pem_corrupt: kp
                            .private_key_pkcs8_pem_corrupt_deterministic(&variant),
                        private_key_der_corrupt: kp
                            .private_key_pkcs8_der_corrupt_deterministic(&variant),
                    }
                }
                1 => {
                    let kp = fx.ecdsa(&tag, EcdsaSpec::es256());
                    NegativePemDerFixture {
                        family: "ecdsa",
                        label: tag,
                        private_key_pem_corrupt: kp
                            .private_key_pkcs8_pem_corrupt_deterministic(&variant),
                        private_key_der_corrupt: kp
                            .private_key_pkcs8_der_corrupt_deterministic(&variant),
                    }
                }
                _ => {
                    let kp = fx.ed25519(&tag, Ed25519Spec::new());
                    NegativePemDerFixture {
                        family: "ed25519",
                        label: tag,
                        private_key_pem_corrupt: kp
                            .private_key_pkcs8_pem_corrupt_deterministic(&variant),
                        private_key_der_corrupt: kp
                            .private_key_pkcs8_der_corrupt_deterministic(&variant),
                    }
                }
            }
        })
        .boxed()
}

/// Strategy for X.509 chain negative variants.
pub fn x509_chain_negative() -> BoxedStrategy<X509ChainNegativeFixture> {
    let variants = prop_oneof![
        Just(ChainNegative::UnknownCa),
        Just(ChainNegative::ExpiredLeaf),
        Just(ChainNegative::NotYetValidLeaf),
        Just(ChainNegative::ExpiredIntermediate),
        Just(ChainNegative::NotYetValidIntermediate),
        Just(ChainNegative::IntermediateNotCa),
        Just(ChainNegative::IntermediateWrongKeyUsage),
        Just(ChainNegative::RevokedLeaf),
        any::<u16>().prop_map(|n| ChainNegative::HostnameMismatch {
            wrong_hostname: format!("wrong-{n}.example.test"),
        }),
    ];

    (any::<u64>(), variants)
        .prop_map(|(seed, variant)| {
            let fx = deterministic_factory(seed);
            let chain = fx.x509_chain(
                label("chain-neg", seed as u32),
                ChainSpec::new(format!("ok-{seed}.example.test")),
            );
            let negative = chain.negative(variant.clone());
            X509ChainNegativeFixture {
                variant,
                chain: negative,
            }
        })
        .boxed()
}

/// Composable profile: any JWT-capable fixture.
pub fn any_jwt_fixture() -> BoxedStrategy<ValidAsymmetricFixture> {
    prop_oneof![
        valid_rsa_fixture().prop_map(ValidAsymmetricFixture::Rsa),
        valid_ecdsa_fixture().prop_map(ValidAsymmetricFixture::Ecdsa),
        valid_ed25519_fixture().prop_map(ValidAsymmetricFixture::Ed25519),
    ]
    .boxed()
}

/// Composable profile: any negative X.509 chain fixture.
pub fn any_x509_chain_negative() -> BoxedStrategy<X509ChainNegativeFixture> {
    x509_chain_negative()
}

/// Composable profile: valid or corrupt JWK JSON.
///
/// Corrupt variants are generated from valid JWKs by deterministic field-level
/// edits (remove required fields or alter `kty`).
pub fn valid_or_corrupt_jwk() -> BoxedStrategy<JwkFixture> {
    let valid = prop_oneof![
        valid_rsa_fixture().prop_map(|kp| JwkFixture::Valid(kp.public_jwk_json())),
        valid_ecdsa_fixture().prop_map(|kp| JwkFixture::Valid(kp.public_jwk_json())),
        valid_ed25519_fixture().prop_map(|kp| JwkFixture::Valid(kp.public_jwk_json())),
        valid_hmac_fixture().prop_map(|s| JwkFixture::Valid(s.jwk().to_value())),
    ];

    let corrupt = (any::<u64>(), any::<u8>()).prop_map(|(seed, selector)| {
        let fx = deterministic_factory(seed);
        let mut v = fx.rsa(label("jwk", seed as u32), RsaSpec::rs256()).public_jwk_json();
        match selector % 3 {
            0 => {
                if let Some(obj) = v.as_object_mut() {
                    obj.remove("kty");
                }
            }
            1 => {
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("kty".to_string(), serde_json::Value::String("NOPE".to_string()));
                }
            }
            _ => {
                if let Some(obj) = v.as_object_mut() {
                    obj.remove("n");
                }
            }
        }
        JwkFixture::Corrupt(v)
    });

    prop_oneof![3 => valid, 2 => corrupt].boxed()
}
