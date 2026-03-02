use uselesskey_pgp::PgpSpec;

#[test]
fn constructors_return_correct_variants() {
    assert_eq!(PgpSpec::rsa_2048(), PgpSpec::Rsa2048);
    assert_eq!(PgpSpec::rsa_3072(), PgpSpec::Rsa3072);
    assert_eq!(PgpSpec::ed25519(), PgpSpec::Ed25519);
}

#[test]
fn kind_names_exact() {
    assert_eq!(PgpSpec::Rsa2048.kind_name(), "rsa2048");
    assert_eq!(PgpSpec::Rsa3072.kind_name(), "rsa3072");
    assert_eq!(PgpSpec::Ed25519.kind_name(), "ed25519");
}

#[test]
fn stable_bytes_exact() {
    assert_eq!(PgpSpec::Rsa2048.stable_bytes(), [0, 0, 0, 1]);
    assert_eq!(PgpSpec::Rsa3072.stable_bytes(), [0, 0, 0, 2]);
    assert_eq!(PgpSpec::Ed25519.stable_bytes(), [0, 0, 0, 3]);
}
