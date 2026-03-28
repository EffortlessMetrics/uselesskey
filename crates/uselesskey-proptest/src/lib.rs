#![forbid(unsafe_code)]

//! proptest strategies for `uselesskey` fixture structs.
//!
//! This crate stays in the test-fixture layer: it generates realistic fixture
//! objects from `uselesskey` and reuses existing negative/corruption builders.

use proptest::prelude::*;
use proptest::strategy::BoxedStrategy;
use uselesskey_core::{Factory, Seed};
use uselesskey_core_negative_der::corrupt_der_deterministic;
use uselesskey_core_negative_pem::corrupt_pem_deterministic;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaKeyPair, EcdsaSpec};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519KeyPair, Ed25519Spec};
use uselesskey_hmac::{HmacFactoryExt, HmacSecret, HmacSpec};
use uselesskey_rsa::{RsaFactoryExt, RsaKeyPair, RsaSpec};
use uselesskey_token::{TokenFactoryExt, TokenFixture, TokenSpec};
use uselesskey_x509::{ChainNegative, ChainSpec, X509Chain, X509FactoryExt};

#[derive(Clone, Debug)]
pub enum JwtFixture {
    Rsa(RsaKeyPair),
    Ecdsa(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
    Hmac(HmacSecret),
}

#[derive(Clone, Debug)]
pub struct X509ChainNegativeFixture {
    pub base: X509Chain,
    pub negative: X509Chain,
    pub variant: ChainNegative,
}

#[derive(Clone, Copy, Debug)]
pub enum DerFixtureSource {
    RsaPrivateKey,
    EcdsaPrivateKey,
    Ed25519PrivateKey,
    X509Cert,
}

#[derive(Clone, Debug)]
pub struct NegativeDerFixture {
    pub source: DerFixtureSource,
    pub valid_der: Vec<u8>,
    pub corrupt_der: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub enum PemFixtureSource {
    RsaPrivateKey,
    EcdsaPrivateKey,
    Ed25519PrivateKey,
    X509Cert,
}

#[derive(Clone, Debug)]
pub struct NegativePemFixture {
    pub source: PemFixtureSource,
    pub valid_pem: String,
    pub corrupt_pem: String,
}

#[derive(Clone, Debug)]
pub struct ValidJwkFixture {
    pub jwk_json: serde_json::Value,
}

#[derive(Clone, Debug)]
pub struct CorruptJwkFixture {
    pub original_json: String,
    pub corrupt_json: String,
}

#[derive(Clone, Debug)]
pub enum ValidOrCorruptJwkFixture {
    Valid(ValidJwkFixture),
    Corrupt(CorruptJwkFixture),
}

pub fn rsa_fixture() -> BoxedStrategy<RsaKeyPair> {
    seeded_label("rsa").prop_flat_map(|(seed, label)| {
        prop_oneof![Just(RsaSpec::rs256()), Just(RsaSpec::new(3072)), Just(RsaSpec::new(4096)),]
            .prop_map(move |spec| deterministic_factory(seed).rsa(label.clone(), spec))
    }).boxed()
}

pub fn ecdsa_fixture() -> BoxedStrategy<EcdsaKeyPair> {
    seeded_label("ecdsa")
        .prop_flat_map(|(seed, label)| {
            prop_oneof![Just(EcdsaSpec::es256()), Just(EcdsaSpec::es384()),]
                .prop_map(move |spec| deterministic_factory(seed).ecdsa(label.clone(), spec))
        })
        .boxed()
}

pub fn ed25519_fixture() -> BoxedStrategy<Ed25519KeyPair> {
    seeded_label("ed25519")
        .prop_map(|(seed, label)| deterministic_factory(seed).ed25519(label, Ed25519Spec::new()))
        .boxed()
}

pub fn hmac_fixture() -> BoxedStrategy<HmacSecret> {
    seeded_label("hmac")
        .prop_flat_map(|(seed, label)| {
            prop_oneof![
                Just(HmacSpec::hs256()),
                Just(HmacSpec::hs384()),
                Just(HmacSpec::hs512()),
            ]
            .prop_map(move |spec| deterministic_factory(seed).hmac(label.clone(), spec))
        })
        .boxed()
}

pub fn token_fixture() -> BoxedStrategy<TokenFixture> {
    seeded_label("token")
        .prop_flat_map(|(seed, label)| {
            prop_oneof![
                Just(TokenSpec::api_key()),
                Just(TokenSpec::bearer()),
                Just(TokenSpec::oauth_access_token()),
            ]
            .prop_map(move |spec| deterministic_factory(seed).token(label.clone(), spec))
        })
        .boxed()
}

pub fn x509_chain_fixture() -> BoxedStrategy<X509Chain> {
    seeded_hostname("x509").prop_map(|(seed, label, host)| {
        deterministic_factory(seed).x509_chain(label, ChainSpec::new(host))
    }).boxed()
}

pub fn negative_der_fixture() -> BoxedStrategy<NegativeDerFixture> {
    prop_oneof![
        seeded_label("neg-der-rsa").prop_map(|(seed, label)| {
            let fx = deterministic_factory(seed);
            let kp = fx.rsa(label, RsaSpec::rs256());
            build_der_fixture(
                DerFixtureSource::RsaPrivateKey,
                kp.private_key_pkcs8_der(),
                seed,
            )
        }),
        seeded_label("neg-der-ecdsa").prop_map(|(seed, label)| {
            let fx = deterministic_factory(seed);
            let kp = fx.ecdsa(label, EcdsaSpec::es256());
            build_der_fixture(
                DerFixtureSource::EcdsaPrivateKey,
                kp.private_key_pkcs8_der(),
                seed,
            )
        }),
        seeded_label("neg-der-ed25519").prop_map(|(seed, label)| {
            let fx = deterministic_factory(seed);
            let kp = fx.ed25519(label, Ed25519Spec::new());
            build_der_fixture(
                DerFixtureSource::Ed25519PrivateKey,
                kp.private_key_pkcs8_der(),
                seed,
            )
        }),
        seeded_hostname("neg-der-x509").prop_map(|(seed, label, host)| {
            let fx = deterministic_factory(seed);
            let cert = fx.x509_self_signed(label, uselesskey_x509::X509Spec::self_signed(host));
            build_der_fixture(DerFixtureSource::X509Cert, cert.cert_der(), seed)
        })
    ]
    .boxed()
}

pub fn negative_pem_fixture() -> BoxedStrategy<NegativePemFixture> {
    prop_oneof![
        seeded_label("neg-pem-rsa").prop_map(|(seed, label)| {
            let fx = deterministic_factory(seed);
            let kp = fx.rsa(label, RsaSpec::rs256());
            build_pem_fixture(
                PemFixtureSource::RsaPrivateKey,
                kp.private_key_pkcs8_pem(),
                seed,
            )
        }),
        seeded_label("neg-pem-ecdsa").prop_map(|(seed, label)| {
            let fx = deterministic_factory(seed);
            let kp = fx.ecdsa(label, EcdsaSpec::es256());
            build_pem_fixture(
                PemFixtureSource::EcdsaPrivateKey,
                kp.private_key_pkcs8_pem(),
                seed,
            )
        }),
        seeded_label("neg-pem-ed25519").prop_map(|(seed, label)| {
            let fx = deterministic_factory(seed);
            let kp = fx.ed25519(label, Ed25519Spec::new());
            build_pem_fixture(
                PemFixtureSource::Ed25519PrivateKey,
                kp.private_key_pkcs8_pem(),
                seed,
            )
        }),
        seeded_hostname("neg-pem-x509").prop_map(|(seed, label, host)| {
            let fx = deterministic_factory(seed);
            let cert = fx.x509_self_signed(label, uselesskey_x509::X509Spec::self_signed(host));
            build_pem_fixture(PemFixtureSource::X509Cert, cert.cert_pem(), seed)
        })
    ]
    .boxed()
}

pub fn x509_chain_negative_fixture() -> BoxedStrategy<X509ChainNegativeFixture> {
    seeded_hostname("x509-neg")
        .prop_flat_map(|(seed, label, host)| {
            let variants = chain_negative_variants();
            (Just(seed), Just(label), Just(host), variants)
        })
        .prop_map(|(seed, label, host, variant)| {
            let fx = deterministic_factory(seed);
            let base = fx.x509_chain(label, ChainSpec::new(host));
            let negative = apply_chain_negative(&base, &variant);
            X509ChainNegativeFixture {
                base,
                negative,
                variant,
            }
        })
        .boxed()
}

pub fn any_jwt_fixture() -> BoxedStrategy<JwtFixture> {
    prop_oneof![
        rsa_fixture().prop_map(JwtFixture::Rsa),
        ecdsa_fixture().prop_map(JwtFixture::Ecdsa),
        ed25519_fixture().prop_map(JwtFixture::Ed25519),
        hmac_fixture().prop_map(JwtFixture::Hmac),
    ]
    .boxed()
}

pub fn any_x509_chain_negative() -> BoxedStrategy<X509ChainNegativeFixture> {
    x509_chain_negative_fixture()
}

pub fn valid_or_corrupt_jwk() -> BoxedStrategy<ValidOrCorruptJwkFixture> {
    prop_oneof![
        any_valid_jwk_json().prop_map(|jwk_json| {
            ValidOrCorruptJwkFixture::Valid(ValidJwkFixture { jwk_json })
        }),
        any_valid_jwk_json().prop_map(|jwk_json| {
            let original_json = jwk_json.to_string();
            let variant = format!("corrupt:jwk:{}", original_json.len());
            let corrupt = corrupt_der_deterministic(original_json.as_bytes(), &variant);
            let corrupt_json = String::from_utf8_lossy(&corrupt).into_owned();
            ValidOrCorruptJwkFixture::Corrupt(CorruptJwkFixture {
                original_json,
                corrupt_json,
            })
        }),
    ]
    .boxed()
}

/// Entry point suitable for fuzz harnesses that only checks generation and shape
/// code paths for panics.
pub fn fuzz_no_panic_entrypoint(data: &[u8]) {
    let mut seed_bytes = [0u8; 32];
    for (i, b) in data.iter().take(32).enumerate() {
        seed_bytes[i] = *b;
    }
    let seed = Seed::new(seed_bytes);
    let fx = Factory::deterministic(seed);

    let rsa = fx.rsa("fuzz-rsa", RsaSpec::rs256());
    let _ = rsa.private_key_pkcs8_der();
    let _ = rsa.public_jwk_json();

    let ecdsa = fx.ecdsa("fuzz-ecdsa", EcdsaSpec::es256());
    let _ = ecdsa.private_key_pkcs8_pem();
    let _ = ecdsa.public_jwk_json();

    let ed = fx.ed25519("fuzz-ed25519", Ed25519Spec::new());
    let _ = ed.public_jwk_json();

    let hmac = fx.hmac("fuzz-hmac", HmacSpec::hs256());
    let _ = hmac.secret_bytes();
    let _ = hmac.jwk();

    let _ = fx.token("fuzz-token", TokenSpec::oauth_access_token());

    let cert = fx.x509_self_signed("fuzz-cert", uselesskey_x509::X509Spec::self_signed("fuzz.example"));
    let _ = cert.expired().cert_der();

    let chain = fx.x509_chain("fuzz-chain", ChainSpec::new("fuzz.example"));
    let _ = chain.revoked_leaf().chain_pem();
}

fn deterministic_factory(seed: u64) -> Factory {
    Factory::deterministic(Seed::from_text(&format!("uselesskey-proptest:{seed}")))
}

fn seeded_label(prefix: &'static str) -> BoxedStrategy<(u64, String)> {
    (any::<u64>(), proptest::string::string_regex("[a-z][a-z0-9_]{0,15}").expect("valid regex"))
        .prop_map(move |(seed, label)| (seed, format!("{prefix}-{label}")))
        .boxed()
}

fn seeded_hostname(prefix: &'static str) -> BoxedStrategy<(u64, String, String)> {
    (
        any::<u64>(),
        proptest::string::string_regex("[a-z][a-z0-9_]{0,10}").expect("valid regex"),
        proptest::string::string_regex("[a-z][a-z0-9]{0,8}\\.example\\.test")
            .expect("valid regex"),
    )
        .prop_map(move |(seed, label, host)| (seed, format!("{prefix}-{label}"), host))
        .boxed()
}

fn build_der_fixture(source: DerFixtureSource, valid_der: &[u8], seed: u64) -> NegativeDerFixture {
    let valid_der = valid_der.to_vec();
    let corrupt_der = corrupt_der_deterministic(&valid_der, &format!("corrupt:der:{seed}"));
    NegativeDerFixture {
        source,
        valid_der,
        corrupt_der,
    }
}

fn build_pem_fixture(source: PemFixtureSource, valid_pem: &str, seed: u64) -> NegativePemFixture {
    let valid_pem = valid_pem.to_string();
    let corrupt_pem = corrupt_pem_deterministic(&valid_pem, &format!("corrupt:pem:{seed}"));
    NegativePemFixture {
        source,
        valid_pem,
        corrupt_pem,
    }
}

fn chain_negative_variants() -> BoxedStrategy<ChainNegative> {
    prop_oneof![
        Just(ChainNegative::UnknownCa),
        Just(ChainNegative::ExpiredLeaf),
        Just(ChainNegative::NotYetValidLeaf),
        Just(ChainNegative::ExpiredIntermediate),
        Just(ChainNegative::NotYetValidIntermediate),
        Just(ChainNegative::IntermediateNotCa),
        Just(ChainNegative::IntermediateWrongKeyUsage),
        Just(ChainNegative::RevokedLeaf),
        proptest::string::string_regex("[a-z][a-z0-9]{0,8}\\.example\\.test")
            .expect("valid regex")
            .prop_map(|wrong_hostname| ChainNegative::HostnameMismatch { wrong_hostname }),
    ]
    .boxed()
}

fn apply_chain_negative(base: &X509Chain, variant: &ChainNegative) -> X509Chain {
    match variant {
        ChainNegative::HostnameMismatch { wrong_hostname } => base.hostname_mismatch(wrong_hostname),
        ChainNegative::UnknownCa => base.unknown_ca(),
        ChainNegative::ExpiredLeaf => base.expired_leaf(),
        ChainNegative::NotYetValidLeaf => base.not_yet_valid_leaf(),
        ChainNegative::ExpiredIntermediate => base.expired_intermediate(),
        ChainNegative::NotYetValidIntermediate => base.not_yet_valid_intermediate(),
        ChainNegative::IntermediateNotCa => base.intermediate_not_ca(),
        ChainNegative::IntermediateWrongKeyUsage => base.intermediate_wrong_key_usage(),
        ChainNegative::RevokedLeaf => base.revoked_leaf(),
    }
}

fn any_valid_jwk_json() -> BoxedStrategy<serde_json::Value> {
    prop_oneof![
        rsa_fixture().prop_map(|kp| kp.public_jwk_json()),
        ecdsa_fixture().prop_map(|kp| kp.public_jwk_json()),
        ed25519_fixture().prop_map(|kp| kp.public_jwk_json()),
        hmac_fixture().prop_map(|secret| secret.jwk().to_value()),
    ]
    .boxed()
}
