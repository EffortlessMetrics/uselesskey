use uselesskey_core::negative::CorruptPem;
use uselesskey_core::{Factory, Seed};
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

fn assert_private_key_parseable(spec: EcdsaSpec, pem: &str, der: &[u8]) {
    match spec {
        EcdsaSpec::Es256 => {
            use p256::pkcs8::DecodePrivateKey as _;
            p256::SecretKey::from_pkcs8_der(der).expect("P-256 DER should parse");
            p256::SecretKey::from_pkcs8_pem(pem).expect("P-256 PEM should parse");
        }
        EcdsaSpec::Es384 => {
            use p384::pkcs8::DecodePrivateKey as _;
            p384::SecretKey::from_pkcs8_der(der).expect("P-384 DER should parse");
            p384::SecretKey::from_pkcs8_pem(pem).expect("P-384 PEM should parse");
        }
    }
}

fn assert_public_key_parseable(spec: EcdsaSpec, pem: &str, der: &[u8]) {
    match spec {
        EcdsaSpec::Es256 => {
            use p256::pkcs8::DecodePublicKey as _;
            p256::PublicKey::from_public_key_der(der).expect("P-256 DER should parse");
            p256::PublicKey::from_public_key_pem(pem).expect("P-256 PEM should parse");
        }
        EcdsaSpec::Es384 => {
            use p384::pkcs8::DecodePublicKey as _;
            p384::PublicKey::from_public_key_der(der).expect("P-384 DER should parse");
            p384::PublicKey::from_public_key_pem(pem).expect("P-384 PEM should parse");
        }
    }
}

fn assert_public_keys_differ(spec: EcdsaSpec, good: &[u8], other: &[u8]) {
    match spec {
        EcdsaSpec::Es256 => {
            use p256::pkcs8::DecodePublicKey as _;
            let good = p256::PublicKey::from_public_key_der(good).expect("good P-256 spki");
            let other = p256::PublicKey::from_public_key_der(other).expect("other P-256 spki");
            assert_ne!(good.to_sec1_bytes(), other.to_sec1_bytes());
        }
        EcdsaSpec::Es384 => {
            use p384::pkcs8::DecodePublicKey as _;
            let good = p384::PublicKey::from_public_key_der(good).expect("good P-384 spki");
            let other = p384::PublicKey::from_public_key_der(other).expect("other P-384 spki");
            assert_ne!(good.to_sec1_bytes(), other.to_sec1_bytes());
        }
    }
}

fn assert_private_key_rejects(spec: EcdsaSpec, pem: &str, der: &[u8]) {
    match spec {
        EcdsaSpec::Es256 => {
            use p256::pkcs8::DecodePrivateKey as _;
            assert!(p256::SecretKey::from_pkcs8_pem(pem).is_err());
            assert!(p256::SecretKey::from_pkcs8_der(der).is_err());
        }
        EcdsaSpec::Es384 => {
            use p384::pkcs8::DecodePrivateKey as _;
            assert!(p384::SecretKey::from_pkcs8_pem(pem).is_err());
            assert!(p384::SecretKey::from_pkcs8_der(der).is_err());
        }
    }
}

#[test]
fn pkcs8_and_spki_are_parseable_for_both_specs() {
    let fx = Factory::deterministic(Seed::from_env_value("ecdsa-parse").unwrap());

    for spec in [EcdsaSpec::es256(), EcdsaSpec::es384()] {
        let key = fx.ecdsa("issuer", spec);
        assert_private_key_parseable(
            spec,
            key.private_key_pkcs8_pem(),
            key.private_key_pkcs8_der(),
        );
        assert_public_key_parseable(
            spec,
            key.public_key_spki_pem(),
            key.public_key_spki_der(),
        );
    }
}

#[test]
fn deterministic_key_is_stable() {
    let fx = Factory::deterministic(Seed::from_env_value("ecdsa-det").unwrap());
    let k1 = fx.ecdsa("issuer", EcdsaSpec::es256());
    let k2 = fx.ecdsa("issuer", EcdsaSpec::es256());
    assert_eq!(k1.private_key_pkcs8_der(), k2.private_key_pkcs8_der());
    assert_eq!(k1.public_key_spki_der(), k2.public_key_spki_der());
}

#[test]
fn mismatched_public_key_is_parseable_and_different() {
    let fx = Factory::random();

    for spec in [EcdsaSpec::es256(), EcdsaSpec::es384()] {
        let key = fx.ecdsa("issuer", spec);
        let good = key.public_key_spki_der().to_vec();
        let other = key.mismatched_public_key_spki_der();
        assert_public_keys_differ(spec, &good, &other);
    }
}

#[test]
fn corrupt_pem_and_truncate_der_fail_to_parse() {
    let fx = Factory::random();

    for spec in [EcdsaSpec::es256(), EcdsaSpec::es384()] {
        let key = fx.ecdsa("issuer", spec);
        let bad_pem = key.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
        let truncated = key.private_key_pkcs8_der_truncated(10);
        assert_eq!(truncated.len(), 10);
        assert_private_key_rejects(spec, &bad_pem, &truncated);
    }
}

#[test]
fn tempfiles_match_in_memory() {
    let fx = Factory::random();
    let key = fx.ecdsa("issuer", EcdsaSpec::es256());

    let priv_tf = key.write_private_key_pkcs8_pem().expect("private tempfile");
    let pub_tf = key.write_public_key_spki_pem().expect("public tempfile");

    let priv_contents = std::fs::read_to_string(priv_tf.path()).expect("read private tempfile");
    let pub_contents = std::fs::read_to_string(pub_tf.path()).expect("read public tempfile");

    assert_eq!(priv_contents, key.private_key_pkcs8_pem());
    assert_eq!(pub_contents, key.public_key_spki_pem());
}

#[test]
fn spec_round_trips() {
    let fx = Factory::random();
    let key = fx.ecdsa("issuer", EcdsaSpec::es384());
    assert_eq!(key.spec(), EcdsaSpec::es384());
}

#[test]
fn debug_includes_label_and_type() {
    let fx = Factory::random();
    let key = fx.ecdsa("debug-label", EcdsaSpec::es256());

    let dbg = format!("{:?}", key);
    assert!(dbg.contains("EcdsaKeyPair"));
    assert!(dbg.contains("debug-label"));
}
