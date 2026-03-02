use uselesskey_core_hmac_spec::HmacSpec;

#[test]
fn constructors_return_correct_variants() {
    assert_eq!(HmacSpec::hs256(), HmacSpec::Hs256);
    assert_eq!(HmacSpec::hs384(), HmacSpec::Hs384);
    assert_eq!(HmacSpec::hs512(), HmacSpec::Hs512);
}

#[test]
fn alg_names_exact() {
    assert_eq!(HmacSpec::Hs256.alg_name(), "HS256");
    assert_eq!(HmacSpec::Hs384.alg_name(), "HS384");
    assert_eq!(HmacSpec::Hs512.alg_name(), "HS512");
}

#[test]
fn byte_lens_exact() {
    assert_eq!(HmacSpec::Hs256.byte_len(), 32);
    assert_eq!(HmacSpec::Hs384.byte_len(), 48);
    assert_eq!(HmacSpec::Hs512.byte_len(), 64);
}

#[test]
fn stable_bytes_exact_values() {
    assert_eq!(HmacSpec::Hs256.stable_bytes(), [0, 0, 0, 1]);
    assert_eq!(HmacSpec::Hs384.stable_bytes(), [0, 0, 0, 2]);
    assert_eq!(HmacSpec::Hs512.stable_bytes(), [0, 0, 0, 3]);
}

#[test]
fn byte_lens_are_strictly_increasing() {
    assert!(HmacSpec::Hs256.byte_len() < HmacSpec::Hs384.byte_len());
    assert!(HmacSpec::Hs384.byte_len() < HmacSpec::Hs512.byte_len());
}
