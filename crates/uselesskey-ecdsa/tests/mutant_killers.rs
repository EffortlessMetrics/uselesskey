use uselesskey_ecdsa::EcdsaSpec;

#[test]
fn constructors_return_correct_variants() {
    assert_eq!(EcdsaSpec::es256(), EcdsaSpec::Es256);
    assert_eq!(EcdsaSpec::es384(), EcdsaSpec::Es384);
}

#[test]
fn alg_names_exact() {
    assert_eq!(EcdsaSpec::Es256.alg_name(), "ES256");
    assert_eq!(EcdsaSpec::Es384.alg_name(), "ES384");
}

#[test]
fn curve_names_exact() {
    assert_eq!(EcdsaSpec::Es256.curve_name(), "P-256");
    assert_eq!(EcdsaSpec::Es384.curve_name(), "P-384");
}

#[test]
fn coordinate_len_exact() {
    assert_eq!(EcdsaSpec::Es256.coordinate_len_bytes(), 32);
    assert_eq!(EcdsaSpec::Es384.coordinate_len_bytes(), 48);
}

#[test]
fn stable_bytes_exact() {
    assert_eq!(EcdsaSpec::Es256.stable_bytes(), [0, 0, 0, 1]);
    assert_eq!(EcdsaSpec::Es384.stable_bytes(), [0, 0, 0, 2]);
}

#[test]
fn coordinate_len_matches_curve() {
    assert_eq!(EcdsaSpec::Es256.coordinate_len_bytes(), 256 / 8);
    assert_eq!(EcdsaSpec::Es384.coordinate_len_bytes(), 384 / 8);
}
