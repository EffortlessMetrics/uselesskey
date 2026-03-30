#![forbid(unsafe_code)]

//! `proptest` strategies for generating `uselesskey` fixture structs.

use proptest::prelude::*;
use uselesskey_core::Factory;
use uselesskey_core::negative::CorruptPem;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaKeyPair, EcdsaSpec};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519KeyPair, Ed25519Spec};
use uselesskey_hmac::{HmacFactoryExt, HmacSecret, HmacSpec};
use uselesskey_jwk::AnyJwk;
use uselesskey_rsa::{RsaFactoryExt, RsaKeyPair, RsaSpec};
use uselesskey_token::{TokenFactoryExt, TokenFixture};
use uselesskey_token_spec::TokenSpec;
use uselesskey_x509::{ChainNegative, ChainSpec, X509Chain, X509FactoryExt};

#[derive(Clone, Debug)]
pub struct NegativePemFixture {
    pub source: &'static str,
    pub variant: CorruptPem,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct NegativeDerFixture {
    pub source: &'static str,
    pub variant: String,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct X509NegativeChainFixture {
    pub variant: ChainNegative,
    pub chain: X509Chain,
}

#[derive(Clone, Debug)]
pub enum JwtFixture {
    Rsa(RsaKeyPair),
    Ecdsa(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
    Hmac(HmacSecret),
    OAuthToken(TokenFixture),
}

#[derive(Clone)]
pub enum JwkFixture {
    Valid(AnyJwk),
    CorruptJson(String),
}

impl core::fmt::Debug for JwkFixture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Valid(jwk) => f.debug_tuple("Valid").field(&jwk.to_string()).finish(),
            Self::CorruptJson(value) => f.debug_tuple("CorruptJson").field(value).finish(),
        }
    }
}

fn label_strategy(prefix: &'static str) -> BoxedStrategy<String> {
    (0u16..=u16::MAX)
        .prop_map(move |id| format!("{prefix}-{id}"))
        .boxed()
}

fn deterministic_factory(seed: u64) -> Factory {
    Factory::deterministic_from_str(&format!("uselesskey-proptest:{seed}"))
}

pub fn valid_rsa_fixture() -> BoxedStrategy<RsaKeyPair> {
    (
        any::<u64>(),
        label_strategy("rsa"),
        prop_oneof![
            Just(RsaSpec::rs256()),
            Just(RsaSpec::new(3072)),
            Just(RsaSpec::new(4096))
        ],
    )
        .prop_map(|(seed, label, spec)| deterministic_factory(seed).rsa(label, spec))
        .boxed()
}

pub fn valid_ecdsa_fixture() -> BoxedStrategy<EcdsaKeyPair> {
    (
        any::<u64>(),
        label_strategy("ecdsa"),
        prop_oneof![Just(EcdsaSpec::es256()), Just(EcdsaSpec::es384())],
    )
        .prop_map(|(seed, label, spec)| deterministic_factory(seed).ecdsa(label, spec))
        .boxed()
}

pub fn valid_ed25519_fixture() -> BoxedStrategy<Ed25519KeyPair> {
    (any::<u64>(), label_strategy("ed25519"))
        .prop_map(|(seed, label)| deterministic_factory(seed).ed25519(label, Ed25519Spec::new()))
        .boxed()
}

pub fn valid_hmac_fixture() -> BoxedStrategy<HmacSecret> {
    (
        any::<u64>(),
        label_strategy("hmac"),
        prop_oneof![
            Just(HmacSpec::hs256()),
            Just(HmacSpec::hs384()),
            Just(HmacSpec::hs512())
        ],
    )
        .prop_map(|(seed, label, spec)| deterministic_factory(seed).hmac(label, spec))
        .boxed()
}

pub fn token_fixture() -> BoxedStrategy<TokenFixture> {
    (
        any::<u64>(),
        label_strategy("token"),
        prop_oneof![
            Just(TokenSpec::api_key()),
            Just(TokenSpec::bearer()),
            Just(TokenSpec::oauth_access_token())
        ],
    )
        .prop_map(|(seed, label, spec)| deterministic_factory(seed).token(label, spec))
        .boxed()
}

pub fn x509_chain_fixture() -> BoxedStrategy<X509Chain> {
    (any::<u64>(), label_strategy("x509"), label_strategy("leaf"))
        .prop_map(|(seed, label, leaf_cn)| {
            deterministic_factory(seed).x509_chain(label, ChainSpec::new(leaf_cn))
        })
        .boxed()
}

pub fn negative_pem_fixture() -> BoxedStrategy<NegativePemFixture> {
    (
        valid_rsa_fixture(),
        prop_oneof![
            Just(CorruptPem::BadHeader),
            Just(CorruptPem::BadFooter),
            Just(CorruptPem::BadBase64),
            Just(CorruptPem::ExtraBlankLine),
            Just(CorruptPem::Truncate { bytes: 32 }),
        ],
    )
        .prop_map(|(fixture, variant)| NegativePemFixture {
            source: "rsa_pkcs8_private",
            variant,
            value: fixture.private_key_pkcs8_pem_corrupt(variant),
        })
        .boxed()
}

pub fn negative_der_fixture() -> BoxedStrategy<NegativeDerFixture> {
    (valid_rsa_fixture(), 0u8..=7u8)
        .prop_map(|(fixture, bucket)| {
            let variant = format!("corrupt:der:{bucket}");
            let value = fixture.private_key_pkcs8_der_corrupt_deterministic(&variant);
            NegativeDerFixture {
                source: "rsa_pkcs8_private",
                variant,
                value,
            }
        })
        .boxed()
}

pub fn x509_negative_variants() -> BoxedStrategy<X509NegativeChainFixture> {
    (
        x509_chain_fixture(),
        prop_oneof![
            Just(ChainNegative::UnknownCa),
            Just(ChainNegative::ExpiredLeaf),
            Just(ChainNegative::NotYetValidLeaf),
            Just(ChainNegative::ExpiredIntermediate),
            Just(ChainNegative::NotYetValidIntermediate),
            Just(ChainNegative::IntermediateNotCa),
            Just(ChainNegative::IntermediateWrongKeyUsage),
            Just(ChainNegative::RevokedLeaf),
        ],
    )
        .prop_map(|(chain, variant)| {
            let neg_chain = chain.negative(variant.clone());
            X509NegativeChainFixture {
                variant,
                chain: neg_chain,
            }
        })
        .boxed()
}

pub fn any_jwt_fixture() -> BoxedStrategy<JwtFixture> {
    prop_oneof![
        valid_rsa_fixture().prop_map(JwtFixture::Rsa),
        valid_ecdsa_fixture().prop_map(JwtFixture::Ecdsa),
        valid_ed25519_fixture().prop_map(JwtFixture::Ed25519),
        valid_hmac_fixture().prop_map(JwtFixture::Hmac),
        (any::<u64>(), label_strategy("oauth-token")).prop_map(|(seed, label)| {
            JwtFixture::OAuthToken(
                deterministic_factory(seed).token(label, TokenSpec::oauth_access_token()),
            )
        }),
    ]
    .boxed()
}

pub fn any_x509_chain_negative() -> BoxedStrategy<X509NegativeChainFixture> {
    x509_negative_variants()
}

pub fn valid_or_corrupt_jwk() -> BoxedStrategy<JwkFixture> {
    let valid = prop_oneof![
        valid_rsa_fixture()
            .prop_map(|fixture| JwkFixture::Valid(AnyJwk::from(fixture.public_jwk()))),
        valid_ecdsa_fixture()
            .prop_map(|fixture| JwkFixture::Valid(AnyJwk::from(fixture.public_jwk()))),
        valid_ed25519_fixture()
            .prop_map(|fixture| JwkFixture::Valid(AnyJwk::from(fixture.public_jwk()))),
        valid_hmac_fixture().prop_map(|fixture| JwkFixture::Valid(AnyJwk::from(fixture.jwk()))),
    ];

    let corrupt = valid.clone().prop_map(|item| match item {
        JwkFixture::Valid(jwk) => {
            let mut as_json = jwk.to_string();
            if as_json.len() > 2 {
                as_json.replace_range(1..2, "#");
            } else {
                as_json.push('#');
            }
            JwkFixture::CorruptJson(as_json)
        }
        JwkFixture::CorruptJson(value) => JwkFixture::CorruptJson(value),
    });

    prop_oneof![3 => valid, 1 => corrupt].boxed()
}

pub fn fuzz_entry_no_panic(data: &[u8]) {
    use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

    let mut seed = [0u8; 32];
    for (idx, byte) in data.iter().take(32).enumerate() {
        seed[idx] = *byte;
    }

    let mut runner = TestRunner::new_with_rng(
        Config {
            cases: 8,
            max_shrink_iters: 64,
            ..Config::default()
        },
        TestRng::from_seed(RngAlgorithm::ChaCha, &seed),
    );

    if let Ok(tree) = valid_or_corrupt_jwk().new_tree(&mut runner) {
        let _ = tree.current();
    }
    if let Ok(tree) = any_x509_chain_negative().new_tree(&mut runner) {
        let _ = tree.current();
    }
}
