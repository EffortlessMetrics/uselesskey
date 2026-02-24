#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

use uselesskey_core_keypair_material::Pkcs8SpkiKeyMaterial;

static SAMPLE_MATERIAL: OnceLock<Pkcs8SpkiKeyMaterial> = OnceLock::new();

fn sample_material() -> &'static Pkcs8SpkiKeyMaterial {
    SAMPLE_MATERIAL
        .get_or_init(|| {
            Pkcs8SpkiKeyMaterial::new(
                vec![0x30, 0x82, 0x01, 0x22, 0x04, 0x20, 0xAA, 0xBB],
                "-----BEGIN PRIVATE KEY-----\nMHg=\n-----END PRIVATE KEY-----\n".to_string(),
                vec![0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86],
                "-----BEGIN PUBLIC KEY-----\nMFk=\n-----END PUBLIC KEY-----\n".to_string(),
            )
        })
}

fuzz_target!(|data: &[u8]| {
    let material = sample_material();
    let variant = std::str::from_utf8(data).unwrap_or("<invalid>");

    let _private = material.private_key_pkcs8_pem_corrupt(uselesskey::negative::CorruptPem::BadHeader);
    let _private = material.private_key_pkcs8_pem_corrupt(uselesskey::negative::CorruptPem::BadFooter);
    let _private = material.private_key_pkcs8_pem_corrupt(uselesskey::negative::CorruptPem::BadBase64);
    let _private = material.private_key_pkcs8_pem_corrupt(uselesskey::negative::CorruptPem::ExtraBlankLine);
    let _private = material.private_key_pkcs8_pem_corrupt_deterministic(variant);
    let _der = material.private_key_pkcs8_der_truncated(data.len());
    let _der = material.private_key_pkcs8_der_corrupt_deterministic(variant);

    let _private_tmp = material
        .write_private_key_pkcs8_pem()
        .expect("failed to write private key temp artifact");
    let _public_tmp = material
        .write_public_key_spki_pem()
        .expect("failed to write public key temp artifact");

    assert!(!material.kid().is_empty());
});
