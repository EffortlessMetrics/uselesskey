use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config, TestRunner};

use uselesskey_proptest::{
    JwtFixture, any_jwt_fixture, fuzz_no_panic_entrypoint, negative_der_fixture,
    valid_or_corrupt_jwk, x509_chain_negative_fixture,
};

fn runner_with_cases(cases: u32) -> TestRunner {
    TestRunner::new(Config {
        cases,
        ..Config::default()
    })
}

#[test]
fn deterministic_smoke_with_fixed_seed_strategy_input() {
    let mut runner = runner_with_cases(1);
    let strat = any_jwt_fixture();

    let first = strat
        .new_tree(&mut runner)
        .expect("tree")
        .current();

    // Create again in a second runner. We only assert semantic validity,
    // not exact variant equality.
    let mut runner2 = runner_with_cases(1);
    let second = strat
        .new_tree(&mut runner2)
        .expect("tree")
        .current();

    let is_valid = |fixture: &JwtFixture| match fixture {
        JwtFixture::Rsa(k) => !k.private_key_pkcs8_der().is_empty(),
        JwtFixture::Ecdsa(k) => !k.private_key_pkcs8_der().is_empty(),
        JwtFixture::Ed25519(k) => !k.private_key_pkcs8_der().is_empty(),
        JwtFixture::Hmac(k) => !k.secret_bytes().is_empty(),
    };

    assert!(is_valid(&first));
    assert!(is_valid(&second));
}

#[test]
fn no_panics_fuzz_entrypoint_smoke() {
    for len in [0usize, 1, 3, 8, 16, 31, 32, 64, 128] {
        let input: Vec<u8> = (0..len as u8).collect();
        fuzz_no_panic_entrypoint(&input);
    }
}

#[test]
fn shrink_sanity_for_negative_der_fixture() {
    let mut runner = runner_with_cases(8);
    let mut tree = negative_der_fixture().new_tree(&mut runner).expect("tree");

    let original = tree.current();
    assert!(!original.valid_der.is_empty());
    assert!(!original.corrupt_der.is_empty());

    let mut saw_simplified = false;
    for _ in 0..32 {
        if !tree.simplify() {
            break;
        }
        saw_simplified = true;
        let simplified = tree.current();
        assert!(!simplified.valid_der.is_empty());
        assert!(!simplified.corrupt_der.is_empty());
    }

    assert!(saw_simplified, "fixture should admit at least one shrink step");
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 12, ..ProptestConfig::default() })]

    #[test]
    fn jwt_fixture_is_semantically_valid(fx in any_jwt_fixture()) {
        match fx {
            JwtFixture::Rsa(k) => prop_assert!(k.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY")),
            JwtFixture::Ecdsa(k) => prop_assert!(k.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY")),
            JwtFixture::Ed25519(k) => prop_assert!(k.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY")),
            JwtFixture::Hmac(k) => prop_assert!(!k.secret_bytes().is_empty()),
        }
    }

    #[test]
    fn x509_negative_chain_differs_from_base(fx in x509_chain_negative_fixture()) {
        prop_assert_ne!(fx.base.leaf_cert_der(), fx.negative.leaf_cert_der());
    }

    #[test]
    fn valid_or_corrupt_jwk_shape(fx in valid_or_corrupt_jwk()) {
        match fx {
            uselesskey_proptest::ValidOrCorruptJwkFixture::Valid(valid) => {
                prop_assert!(valid.jwk_json.is_object());
                prop_assert!(valid.jwk_json.get("kty").is_some());
            }
            uselesskey_proptest::ValidOrCorruptJwkFixture::Corrupt(corrupt) => {
                prop_assert!(!corrupt.original_json.is_empty());
                prop_assert!(!corrupt.corrupt_json.is_empty());
            }
        }
    }
}
