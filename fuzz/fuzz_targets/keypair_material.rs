#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey_core_keypair_material::Pkcs8SpkiKeyMaterial;

#[derive(Arbitrary, Debug)]
struct KeypairInput {
    pkcs8_der: Vec<u8>,
    spki_der: Vec<u8>,
    private_pem: String,
    public_pem: String,
    truncate_len: u8,
    variant_bytes: Vec<u8>,
}

fuzz_target!(|input: KeypairInput| {
    let material = Pkcs8SpkiKeyMaterial::new(
        input.pkcs8_der.clone(),
        input.private_pem.clone(),
        input.spki_der.clone(),
        input.public_pem.clone(),
    );

    // Roundtrip: accessors must return the original data.
    assert_eq!(material.private_key_pkcs8_der(), input.pkcs8_der.as_slice());
    assert_eq!(material.private_key_pkcs8_pem(), input.private_pem);
    assert_eq!(material.public_key_spki_der(), input.spki_der.as_slice());
    assert_eq!(material.public_key_spki_pem(), input.public_pem);

    // kid() is deterministic and non-empty.
    let kid1 = material.kid();
    let kid2 = material.kid();
    assert_eq!(kid1, kid2);
    assert!(!kid1.is_empty());

    // Truncated DER must not panic for any length.
    let trunc = input.truncate_len as usize;
    let _ = material.private_key_pkcs8_der_truncated(trunc);
    let _ = material.private_key_pkcs8_der_truncated(0);
    let _ = material.private_key_pkcs8_der_truncated(input.pkcs8_der.len());
    let _ = material.private_key_pkcs8_der_truncated(input.pkcs8_der.len() + 100);

    // Deterministic corruption must not panic with arbitrary variant strings.
    let variant = String::from_utf8_lossy(&input.variant_bytes);
    let _ = material.private_key_pkcs8_pem_corrupt_deterministic(&variant);
    let _ = material.private_key_pkcs8_der_corrupt_deterministic(&variant);
});
