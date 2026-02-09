use ed25519_dalek::{SigningKey, VerifyingKey};
use uselesskey_core::negative::CorruptPem;
use uselesskey_core::{Factory, Seed};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

fn assert_private_key_parseable(pem: &str, der: &[u8]) {
    use ed25519_dalek::pkcs8::DecodePrivateKey as _;
    SigningKey::from_pkcs8_der(der).expect("Ed25519 DER should parse");
    SigningKey::from_pkcs8_pem(pem).expect("Ed25519 PEM should parse");
}

fn assert_public_key_parseable(pem: &str, der: &[u8]) {
    use ed25519_dalek::pkcs8::DecodePublicKey as _;
    VerifyingKey::from_public_key_der(der).expect("Ed25519 DER should parse");
    VerifyingKey::from_public_key_pem(pem).expect("Ed25519 PEM should parse");
}

fn assert_public_keys_differ(good: &[u8], other: &[u8]) {
    use ed25519_dalek::pkcs8::DecodePublicKey as _;
    let good = VerifyingKey::from_public_key_der(good).expect("good spki");
    let other = VerifyingKey::from_public_key_der(other).expect("other spki");
    assert_ne!(good.as_bytes(), other.as_bytes());
}

fn assert_private_key_rejects(pem: &str, der: &[u8]) {
    use ed25519_dalek::pkcs8::DecodePrivateKey as _;
    assert!(SigningKey::from_pkcs8_pem(pem).is_err());
    assert!(SigningKey::from_pkcs8_der(der).is_err());
}

#[test]
fn pkcs8_and_spki_are_parseable() {
    let fx = Factory::deterministic(Seed::from_env_value("ed25519-parse").unwrap());
    let key = fx.ed25519("issuer", Ed25519Spec::new());

    assert_private_key_parseable(
        key.private_key_pkcs8_pem(),
        key.private_key_pkcs8_der(),
    );
    assert_public_key_parseable(key.public_key_spki_pem(), key.public_key_spki_der());
}

#[test]
fn deterministic_key_is_stable() {
    let fx = Factory::deterministic(Seed::from_env_value("ed25519-det").unwrap());
    let k1 = fx.ed25519("issuer", Ed25519Spec::new());
    let k2 = fx.ed25519("issuer", Ed25519Spec::new());
    assert_eq!(k1.private_key_pkcs8_der(), k2.private_key_pkcs8_der());
    assert_eq!(k1.public_key_spki_der(), k2.public_key_spki_der());
}

#[test]
fn mismatched_public_key_is_parseable_and_different() {
    let fx = Factory::random();
    let key = fx.ed25519("issuer", Ed25519Spec::new());
    let good = key.public_key_spki_der().to_vec();
    let other = key.mismatched_public_key_spki_der();
    assert_public_keys_differ(&good, &other);
}

#[test]
fn corrupt_pem_and_truncate_der_fail_to_parse() {
    let fx = Factory::random();
    let key = fx.ed25519("issuer", Ed25519Spec::new());

    let bad_pem = key.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    let truncated = key.private_key_pkcs8_der_truncated(10);
    assert_eq!(truncated.len(), 10);

    assert_private_key_rejects(&bad_pem, &truncated);
}

#[test]
fn tempfiles_match_in_memory() {
    let fx = Factory::random();
    let key = fx.ed25519("issuer", Ed25519Spec::new());

    let priv_tf = key.write_private_key_pkcs8_pem().expect("private tempfile");
    let pub_tf = key.write_public_key_spki_pem().expect("public tempfile");

    let priv_contents = std::fs::read_to_string(priv_tf.path()).expect("read private tempfile");
    let pub_contents = std::fs::read_to_string(pub_tf.path()).expect("read public tempfile");

    assert_eq!(priv_contents, key.private_key_pkcs8_pem());
    assert_eq!(pub_contents, key.public_key_spki_pem());
}

#[test]
fn debug_includes_label_and_type() {
    let fx = Factory::random();
    let key = fx.ed25519("debug-label", Ed25519Spec::new());

    let dbg = format!("{:?}", key);
    assert!(dbg.contains("Ed25519KeyPair"));
    assert!(dbg.contains("debug-label"));
}
