use uselesskey_core::{Factory, Seed};
use uselesskey_pqc::{PqcAlgorithm, PqcFactoryExt, PqcSecurityLevel, PqcSpec, PrivateMaterial};

#[test]
fn deterministic_regeneration_matches() {
    let fx = Factory::deterministic(Seed::from_env_value("pqc-regen").unwrap());
    let spec = PqcSpec::opaque(PqcAlgorithm::MlKem, PqcSecurityLevel::L5);

    let fixture_a = fx.pqc("kem-a", spec).unwrap();
    let fixture_b = fx.pqc("kem-a", spec).unwrap();

    assert_eq!(fixture_a.public_bytes(), fixture_b.public_bytes());
    assert_eq!(fixture_a.ciphertext_bytes(), fixture_b.ciphertext_bytes());
}

#[test]
fn parser_and_size_bound_examples() {
    let fx = Factory::random();
    let fixture = fx
        .pqc(
            "bound-check",
            PqcSpec::opaque(PqcAlgorithm::MlDsa, PqcSecurityLevel::L3),
        )
        .unwrap();

    assert!(fixture.public_bytes().len() >= 1900);
    assert!(fixture.signature_bytes().len() >= 3200);

    let bad = fixture.malformed_size_vectors();
    assert!(bad.truncated_public.len() < fixture.public_bytes().len());
    assert!(bad.truncated_signature.len() < fixture.signature_bytes().len());
}

#[test]
fn opaque_mode_uses_private_handle() {
    let fx = Factory::random();
    let fixture = fx
        .pqc(
            "opaque-private",
            PqcSpec::opaque(PqcAlgorithm::MlKem, PqcSecurityLevel::L1),
        )
        .unwrap();

    match fixture.private_material() {
        PrivateMaterial::OpaqueHandle(value) => assert!(value.starts_with("pqc://ml-kem/1/opaque")),
        PrivateMaterial::Bytes(_) => panic!("opaque mode should not expose private bytes"),
    }
}
