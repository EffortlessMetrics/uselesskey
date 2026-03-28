#![forbid(unsafe_code)]

//! `proptest` strategy builders for `uselesskey` fixture structs.
//!
//! This crate is a test-fixture integration layer: it emits high-level
//! `uselesskey` fixtures directly so downstream property tests can stay
//! focused on behavior instead of key-generation glue.

use proptest::prelude::*;
use proptest::strategy::BoxedStrategy;
use uselesskey::negative::{CorruptPem, corrupt_der_deterministic, corrupt_pem};
pub mod fuzz;

use uselesskey::{
    ChainNegative, ChainSpec, EcdsaFactoryExt, EcdsaKeyPair, EcdsaSpec, Ed25519FactoryExt,
    Ed25519KeyPair, Ed25519Spec, Factory, HmacFactoryExt, HmacSecret, HmacSpec, RsaFactoryExt,
    RsaKeyPair, RsaSpec, Seed, TokenFactoryExt, TokenFixture, TokenSpec, X509Cert, X509Chain,
    X509FactoryExt, X509Negative, X509Spec,
};

/// A DER negative fixture generated from a valid fixture.
#[derive(Clone, Debug)]
pub struct DerNegativeFixture {
    /// The valid DER bytes used as the source.
    pub original_der: Vec<u8>,
    /// The deterministic corrupted DER bytes.
    pub corrupted_der: Vec<u8>,
    /// Stable variant label used for deterministic corruption.
    pub variant: String,
}

/// A PEM negative fixture generated from a valid fixture.
#[derive(Clone, Debug)]
pub struct PemNegativeFixture {
    /// The valid PEM text used as the source.
    pub original_pem: String,
    /// Corrupted PEM text.
    pub corrupted_pem: String,
    /// Corruption mode used to generate `corrupted_pem`.
    pub corruption: CorruptPem,
}

/// Self-signed X.509 certificate with an explicit negative variant.
#[derive(Clone, Debug)]
pub struct X509NegativeFixture {
    /// Valid baseline certificate fixture.
    pub valid: X509Cert,
    /// Invalid certificate generated via `X509Negative`.
    pub negative: X509Cert,
    /// Negative policy variant that produced `negative`.
    pub variant: X509Negative,
}

/// X.509 certificate chain with an explicit chain-negative variant.
#[derive(Clone, Debug)]
pub struct X509ChainNegativeFixture {
    /// Valid baseline chain fixture.
    pub valid: X509Chain,
    /// Invalid chain generated via `ChainNegative`.
    pub negative: X509Chain,
    /// Negative policy variant that produced `negative`.
    pub variant: ChainNegative,
}

/// JWT-oriented fixture profile spanning asymmetric, symmetric, and token shapes.
#[derive(Clone, Debug)]
pub enum JwtFixture {
    /// RSA key fixture.
    Rsa(RsaKeyPair),
    /// ECDSA key fixture.
    Ecdsa(EcdsaKeyPair),
    /// Ed25519 key fixture.
    Ed25519(Ed25519KeyPair),
    /// HMAC secret fixture.
    Hmac(HmacSecret),
    /// OAuth/JWT-shaped token fixture.
    Token(TokenFixture),
}

/// Result of requesting either a valid JWK value or a deterministically corrupted one.
#[derive(Clone, Debug)]
pub enum ValidOrCorruptJwk {
    /// Valid JSON JWK object.
    Valid(serde_json::Value),
    /// Corrupted JSON-ish payload (deterministic corruption over JWK bytes).
    Corrupt(String),
}

fn seeded_factory(seed_tag: u64) -> Factory {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed_tag.to_be_bytes());
    Factory::deterministic(Seed::new(bytes))
}

fn label(prefix: &str, seed_tag: u64) -> String {
    format!("{prefix}-{seed_tag}")
}

fn any_seed() -> impl Strategy<Value = u64> {
    any::<u64>()
}

/// Strategy for valid RSA fixtures.
pub fn valid_rsa_fixture() -> impl Strategy<Value = RsaKeyPair> {
    (any_seed(), prop_oneof![Just(RsaSpec::rs256()), Just(RsaSpec::new(4096))]).prop_map(
        |(seed_tag, spec)| {
            let fx = seeded_factory(seed_tag);
            fx.rsa(label("rsa", seed_tag), spec)
        },
    )
}

/// Strategy for valid ECDSA fixtures.
pub fn valid_ecdsa_fixture() -> impl Strategy<Value = EcdsaKeyPair> {
    (any_seed(), prop_oneof![Just(EcdsaSpec::es256()), Just(EcdsaSpec::es384())]).prop_map(
        |(seed_tag, spec)| {
            let fx = seeded_factory(seed_tag);
            fx.ecdsa(label("ecdsa", seed_tag), spec)
        },
    )
}

/// Strategy for valid Ed25519 fixtures.
pub fn valid_ed25519_fixture() -> impl Strategy<Value = Ed25519KeyPair> {
    any_seed().prop_map(|seed_tag| {
        let fx = seeded_factory(seed_tag);
        fx.ed25519(label("ed25519", seed_tag), Ed25519Spec::new())
    })
}

/// Strategy for valid HMAC fixtures.
pub fn valid_hmac_fixture() -> impl Strategy<Value = HmacSecret> {
    (
        any_seed(),
        prop_oneof![
            Just(HmacSpec::hs256()),
            Just(HmacSpec::hs384()),
            Just(HmacSpec::hs512())
        ],
    )
        .prop_map(|(seed_tag, spec)| {
            let fx = seeded_factory(seed_tag);
            fx.hmac(label("hmac", seed_tag), spec)
        })
}

/// Strategy for token fixtures.
pub fn token_fixture() -> impl Strategy<Value = TokenFixture> {
    (
        any_seed(),
        prop_oneof![
            Just(TokenSpec::api_key()),
            Just(TokenSpec::bearer()),
            Just(TokenSpec::oauth_access_token()),
        ],
    )
        .prop_map(|(seed_tag, spec)| {
            let fx = seeded_factory(seed_tag);
            fx.token(label("token", seed_tag), spec)
        })
}

/// Strategy for valid X.509 chain fixtures.
pub fn x509_chain_fixture() -> impl Strategy<Value = X509Chain> {
    any_seed().prop_map(|seed_tag| {
        let fx = seeded_factory(seed_tag);
        let host = format!("svc-{seed_tag}.example.test");
        fx.x509_chain(label("x509-chain", seed_tag), ChainSpec::new(host))
    })
}

/// Strategy for PEM negative fixtures reusing core corruption helpers.
pub fn negative_pem_fixture() -> impl Strategy<Value = PemNegativeFixture> {
    (
        valid_rsa_fixture(),
        prop_oneof![
            Just(CorruptPem::BadHeader),
            Just(CorruptPem::BadFooter),
            Just(CorruptPem::BadBase64),
            Just(CorruptPem::ExtraBlankLine),
            (1usize..256usize).prop_map(|bytes| CorruptPem::Truncate { bytes }),
        ],
    )
        .prop_map(|(fixture, corruption)| {
            let original_pem = fixture.private_key_pkcs8_pem().to_string();
            let corrupted_pem = corrupt_pem(&original_pem, corruption);
            PemNegativeFixture {
                original_pem,
                corrupted_pem,
                corruption,
            }
        })
}

/// Strategy for DER negative fixtures reusing deterministic DER corruption helper.
pub fn negative_der_fixture() -> impl Strategy<Value = DerNegativeFixture> {
    (valid_rsa_fixture(), any_seed()).prop_map(|(fixture, variant_seed)| {
        let original_der = fixture.private_key_pkcs8_der().to_vec();
        let variant = format!("corrupt:der:{variant_seed}");
        let corrupted_der = corrupt_der_deterministic(&original_der, &variant);
        DerNegativeFixture {
            original_der,
            corrupted_der,
            variant,
        }
    })
}

/// Strategy for self-signed X.509 negative variants.
pub fn x509_negative_fixture() -> impl Strategy<Value = X509NegativeFixture> {
    (
        any_seed(),
        prop_oneof![
            Just(X509Negative::Expired),
            Just(X509Negative::NotYetValid),
            Just(X509Negative::WrongKeyUsage),
            Just(X509Negative::SelfSignedButClaimsCA),
        ],
    )
        .prop_map(|(seed_tag, variant)| {
            let fx = seeded_factory(seed_tag);
            let host = format!("cert-{seed_tag}.example.test");
            let valid = fx.x509_self_signed(label("x509-cert", seed_tag), X509Spec::self_signed(host));
            let negative = valid.negative(variant.clone());
            X509NegativeFixture {
                valid,
                negative,
                variant,
            }
        })
}

/// Strategy for X.509 chain negative variants.
pub fn x509_chain_negative_fixture() -> impl Strategy<Value = X509ChainNegativeFixture> {
    (
        any_seed(),
        prop_oneof![
            Just(ChainNegative::UnknownCa),
            Just(ChainNegative::ExpiredLeaf),
            Just(ChainNegative::NotYetValidLeaf),
            Just(ChainNegative::ExpiredIntermediate),
            Just(ChainNegative::NotYetValidIntermediate),
            Just(ChainNegative::IntermediateNotCa),
            Just(ChainNegative::IntermediateWrongKeyUsage),
            Just(ChainNegative::RevokedLeaf),
            any_seed().prop_map(|n| ChainNegative::HostnameMismatch {
                wrong_hostname: format!("wrong-{n}.example.test"),
            }),
        ],
    )
        .prop_map(|(seed_tag, variant)| {
            let fx = seeded_factory(seed_tag);
            let host = format!("chain-{seed_tag}.example.test");
            let valid = fx.x509_chain(label("x509-chain-neg", seed_tag), ChainSpec::new(host));
            let negative = valid.negative(variant.clone());
            X509ChainNegativeFixture {
                valid,
                negative,
                variant,
            }
        })
}

/// Composable profile builder for JWT-oriented fixtures.
pub fn any_jwt_fixture() -> impl Strategy<Value = JwtFixture> {
    prop_oneof![
        valid_rsa_fixture().prop_map(JwtFixture::Rsa),
        valid_ecdsa_fixture().prop_map(JwtFixture::Ecdsa),
        valid_ed25519_fixture().prop_map(JwtFixture::Ed25519),
        valid_hmac_fixture().prop_map(JwtFixture::Hmac),
        any_seed().prop_map(|seed_tag| {
            let fx = seeded_factory(seed_tag);
            JwtFixture::Token(fx.token(
                label("jwt-token", seed_tag),
                TokenSpec::oauth_access_token(),
            ))
        }),
    ]
}

/// Composable profile builder for any negative X.509 chain.
pub fn any_x509_chain_negative() -> impl Strategy<Value = X509ChainNegativeFixture> {
    x509_chain_negative_fixture()
}

fn valid_jwk_strategy() -> BoxedStrategy<serde_json::Value> {
    prop_oneof![
        valid_rsa_fixture().prop_map(|k| k.public_jwk().to_value()),
        valid_ecdsa_fixture().prop_map(|k| k.public_jwk().to_value()),
        valid_ed25519_fixture().prop_map(|k| k.public_jwk().to_value()),
        valid_hmac_fixture().prop_map(|k| k.jwk().to_value()),
    ]
    .boxed()
}

/// Composable profile builder yielding valid JWK values or deterministic corruption.
pub fn valid_or_corrupt_jwk() -> impl Strategy<Value = ValidOrCorruptJwk> {
    prop_oneof![
        valid_jwk_strategy().prop_map(ValidOrCorruptJwk::Valid),
        (valid_jwk_strategy(), any_seed()).prop_map(|(jwk, seed_tag)| {
            let encoded = jwk.to_string();
            let variant = format!("corrupt:jwk:{seed_tag}");
            let corrupted = corrupt_der_deterministic(encoded.as_bytes(), &variant);
            ValidOrCorruptJwk::Corrupt(String::from_utf8_lossy(&corrupted).into_owned())
        }),
    ]
}
