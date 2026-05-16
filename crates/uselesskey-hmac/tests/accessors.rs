use uselesskey_core::Factory;
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

#[test]
fn accessors_round_trip_label_and_spec() {
    let spec = HmacSpec::hs512();
    let secret = Factory::random().hmac("hmac-accessor", spec);

    assert_eq!(secret.spec(), spec);
    assert_eq!(secret.label(), "hmac-accessor");
}

#[test]
fn accessors_round_trip_for_all_specs() {
    let fx = Factory::random();
    let cases = [
        ("hs256-label", HmacSpec::hs256(), 32),
        ("hs384-label", HmacSpec::hs384(), 48),
        ("hs512-label", HmacSpec::hs512(), 64),
    ];

    for (label, spec, expected_len) in cases {
        let secret = fx.hmac(label, spec);
        assert_eq!(secret.label(), label, "label accessor for {spec:?}");
        assert_eq!(secret.spec(), spec, "spec accessor for {spec:?}");
        assert_eq!(
            secret.secret_bytes().len(),
            expected_len,
            "secret_bytes length for {spec:?}"
        );
    }
}

#[test]
fn cloned_secret_preserves_bytes_and_accessors_for_all_specs() {
    let fx = Factory::deterministic_from_str("hmac-clone-accessors");

    for spec in [HmacSpec::hs256(), HmacSpec::hs384(), HmacSpec::hs512()] {
        let original = fx.hmac("clone-target", spec);
        let cloned = original.clone();

        assert_eq!(original.label(), cloned.label());
        assert_eq!(original.spec(), cloned.spec());
        assert_eq!(
            original.secret_bytes(),
            cloned.secret_bytes(),
            "cloned secret bytes must match for {spec:?}"
        );
    }
}

#[test]
#[cfg(feature = "jwk")]
fn jwk_use_field_is_sig_for_all_specs() {
    let fx = Factory::random();

    for spec in [HmacSpec::hs256(), HmacSpec::hs384(), HmacSpec::hs512()] {
        let secret = fx.hmac("jwk-use", spec);
        let jwk = secret.jwk().to_value();
        assert_eq!(jwk["use"], "sig", "use field for {spec:?}");
    }
}

#[test]
#[cfg(feature = "jwk")]
fn kid_is_deterministic_for_all_specs() {
    let fx = Factory::deterministic_from_str("hmac-kid-determinism");

    for spec in [HmacSpec::hs256(), HmacSpec::hs384(), HmacSpec::hs512()] {
        let a = fx.hmac("kid-issuer", spec);
        let b = fx.hmac("kid-issuer", spec);
        assert_eq!(a.kid(), b.kid(), "kid must be deterministic for {spec:?}");
        assert!(!a.kid().is_empty(), "kid must be non-empty for {spec:?}");
    }
}

#[test]
#[cfg(feature = "jwk")]
fn kid_differs_across_specs_for_same_label() {
    let fx = Factory::deterministic_from_str("hmac-kid-cross-spec");

    let h256 = fx.hmac("issuer", HmacSpec::hs256()).kid();
    let h384 = fx.hmac("issuer", HmacSpec::hs384()).kid();
    let h512 = fx.hmac("issuer", HmacSpec::hs512()).kid();

    assert_ne!(h256, h384, "HS256 and HS384 must yield distinct kids");
    assert_ne!(h256, h512, "HS256 and HS512 must yield distinct kids");
    assert_ne!(h384, h512, "HS384 and HS512 must yield distinct kids");
}
