use uselesskey_core_x509_negative::{ChainNegative, X509Negative};
use uselesskey_core_x509_spec::{ChainSpec, X509Spec};

#[test]
fn external_users_can_apply_x509_negative_variant() {
    let base = X509Spec::self_signed("integration-test.example");
    let mutated = X509Negative::WrongKeyUsage.apply_to_spec(&base);

    assert!(mutated.is_ca);
    assert!(!mutated.key_usage.key_cert_sign);
}

#[test]
fn external_users_can_apply_chain_negative_variant() {
    let base = ChainSpec::new("integration.example");
    let wrong = ChainNegative::HostnameMismatch {
        wrong_hostname: "wrong.integration.example".to_string(),
    };
    let mutated = wrong.apply_to_spec(&base);

    assert_eq!(mutated.leaf_cn, "wrong.integration.example");
    assert_eq!(mutated.leaf_sans, vec!["wrong.integration.example"]);
}
