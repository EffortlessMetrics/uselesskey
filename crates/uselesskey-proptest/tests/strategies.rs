use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use uselesskey_proptest::{
    DerNegativeFixture, JwtFixture, PemNegativeFixture, ValidOrCorruptJwk, any_jwt_fixture,
    any_x509_chain_negative, negative_der_fixture, negative_pem_fixture, valid_or_corrupt_jwk,
    valid_rsa_fixture,
};

fn deterministic_runner(seed: u64) -> TestRunner {
    let mut raw = [0u8; 32];
    raw[..8].copy_from_slice(&seed.to_be_bytes());
    let rng = TestRng::from_seed(RngAlgorithm::ChaCha, &raw);
    TestRunner::new_with_rng(Config::default(), rng)
}

#[test]
fn deterministic_strategy_smoke_fixed_seed() {
    let strat = valid_rsa_fixture();

    let mut first_runner = deterministic_runner(0xA11CE);
    let first = strat
        .new_tree(&mut first_runner)
        .expect("tree")
        .current()
        .private_key_pkcs8_pem()
        .to_string();

    let mut second_runner = deterministic_runner(0xA11CE);
    let second = strat
        .new_tree(&mut second_runner)
        .expect("tree")
        .current()
        .private_key_pkcs8_pem()
        .to_string();

    assert_eq!(first, second);
}

#[test]
fn no_panics_profile_entrypoints_smoke() {
    let mut runner = deterministic_runner(0xBEEF);

    for _ in 0..24 {
        let jwt = any_jwt_fixture()
            .new_tree(&mut runner)
            .expect("jwt tree")
            .current();
        match jwt {
            JwtFixture::Rsa(k) => assert!(!k.private_key_pkcs8_der().is_empty()),
            JwtFixture::Ecdsa(k) => assert!(!k.private_key_pkcs8_der().is_empty()),
            JwtFixture::Ed25519(k) => assert!(!k.private_key_pkcs8_der().is_empty()),
            JwtFixture::Hmac(k) => assert!(!k.secret_bytes().is_empty()),
            JwtFixture::Token(t) => assert!(!t.value().is_empty()),
        }

        let chain_neg = any_x509_chain_negative()
            .new_tree(&mut runner)
            .expect("chain neg tree")
            .current();
        assert!(!chain_neg.negative.leaf_cert_der().is_empty());

        let jwk = valid_or_corrupt_jwk()
            .new_tree(&mut runner)
            .expect("jwk tree")
            .current();
        match jwk {
            ValidOrCorruptJwk::Valid(value) => assert!(value.get("kty").is_some()),
            ValidOrCorruptJwk::Corrupt(s) => assert!(!s.is_empty()),
        }
    }
}

#[test]
fn size_and_shrink_sanity_for_negative_fixtures() {
    let mut runner = deterministic_runner(0xC0FFEE);

    let mut pem_tree = negative_pem_fixture().new_tree(&mut runner).expect("pem tree");
    let start_pem: PemNegativeFixture = pem_tree.current();
    assert!(!start_pem.corrupted_pem.is_empty());
    let mut shrink_steps = 0usize;
    while shrink_steps < 8 && pem_tree.simplify() {
        shrink_steps += 1;
    }
    let shrunk_pem = pem_tree.current();
    assert!(!shrunk_pem.corrupted_pem.is_empty());

    let mut der_tree = negative_der_fixture().new_tree(&mut runner).expect("der tree");
    let start_der: DerNegativeFixture = der_tree.current();
    assert!(!start_der.corrupted_der.is_empty());
    let mut der_shrink_steps = 0usize;
    while der_shrink_steps < 8 && der_tree.simplify() {
        der_shrink_steps += 1;
    }
    let shrunk_der = der_tree.current();
    assert!(!shrunk_der.corrupted_der.is_empty());
    assert!(shrunk_der.corrupted_der.len() <= start_der.corrupted_der.len());
}
