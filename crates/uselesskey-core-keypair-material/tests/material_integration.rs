use uselesskey_core_keypair_material::Pkcs8SpkiKeyMaterial;
use uselesskey_test_support::{TestResult, require_ok};

#[test]
fn material_is_usable_from_public_api() -> TestResult<()> {
    let material = Pkcs8SpkiKeyMaterial::new(
        vec![0x30, 0x82, 0x01, 0x22],
        "-----BEGIN PRIVATE KEY-----\nMHg=\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x59, 0x30, 0x13],
        "-----BEGIN PUBLIC KEY-----\nMFk=\n-----END PUBLIC KEY-----\n",
    );

    assert!(!material.private_key_pkcs8_pem().is_empty());
    assert!(!material.public_key_spki_pem().is_empty());
    assert_eq!(material.private_key_pkcs8_der(), &[0x30, 0x82, 0x01, 0x22]);

    let private = require_ok(
        material.write_private_key_pkcs8_pem(),
        "write private key temp artifact",
    )?;
    let public = require_ok(
        material.write_public_key_spki_pem(),
        "write public key temp artifact",
    )?;

    assert!(require_ok(private.read_to_string(), "read private")?.contains("PRIVATE KEY"));
    assert!(require_ok(public.read_to_string(), "read public")?.contains("PUBLIC KEY"));
    Ok(())
}
