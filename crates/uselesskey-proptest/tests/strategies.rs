use proptest::prelude::*;
use proptest::test_runner::{Config, TestRng, RngAlgorithm, TestRunner};
use uselesskey_proptest::{
    JwkFixture, ValidAsymmetricFixture, any_jwt_fixture, any_x509_chain_negative,
    negative_pem_der_fixture, token_fixture, valid_or_corrupt_jwk, valid_x509_chain,
};

#[test]
fn deterministic_smoke_with_fixed_seed() {
    let cfg = Config::default();
    let mut runner_a = TestRunner::new_with_rng(
        cfg.clone(),
        TestRng::from_seed(RngAlgorithm::ChaCha, &[7u8; 32]),
    );
    let mut runner_b = TestRunner::new_with_rng(
        cfg,
        TestRng::from_seed(RngAlgorithm::ChaCha, &[7u8; 32]),
    );

    let strat = any_jwt_fixture();
    let a = strat.new_tree(&mut runner_a).expect("tree a").current();
    let b = strat.new_tree(&mut runner_b).expect("tree b").current();

    match (a, b) {
        (ValidAsymmetricFixture::Rsa(a), ValidAsymmetricFixture::Rsa(b)) => {
            assert_eq!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
        }
        (ValidAsymmetricFixture::Ecdsa(a), ValidAsymmetricFixture::Ecdsa(b)) => {
            assert_eq!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
        }
        (ValidAsymmetricFixture::Ed25519(a), ValidAsymmetricFixture::Ed25519(b)) => {
            assert_eq!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
        }
        _ => panic!("strategy changed variant under fixed seed"),
    }
}

#[test]
fn no_panics_entrypoints() {
    let mut runner = TestRunner::default();

    let _ = any_jwt_fixture().new_tree(&mut runner).expect("jwt").current();
    let _ = token_fixture().new_tree(&mut runner).expect("token").current();
    let _ = valid_x509_chain().new_tree(&mut runner).expect("x509").current();
    let _ = any_x509_chain_negative()
        .new_tree(&mut runner)
        .expect("x509-neg")
        .current();
    let _ = negative_pem_der_fixture()
        .new_tree(&mut runner)
        .expect("neg-pem-der")
        .current();
    let _ = valid_or_corrupt_jwk()
        .new_tree(&mut runner)
        .expect("jwk")
        .current();
}

proptest! {
    #[test]
    fn size_sanity_negative_der_is_non_empty(fx in negative_pem_der_fixture()) {
        prop_assert!(!fx.private_key_der_corrupt.is_empty());
        prop_assert!(!fx.private_key_pem_corrupt.is_empty());
    }

    #[test]
    fn shrink_sanity_jwk_remains_json(fx in valid_or_corrupt_jwk()) {
        match fx {
            JwkFixture::Valid(v) | JwkFixture::Corrupt(v) => {
                let s = serde_json::to_string(&v).expect("serialize");
                let _: serde_json::Value = serde_json::from_str(&s).expect("round-trip json");
            }
        }
    }
}
