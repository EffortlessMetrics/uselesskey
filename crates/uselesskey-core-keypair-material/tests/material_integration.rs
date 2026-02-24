use uselesskey_core_keypair_material::Pkcs8SpkiKeyMaterial;

#[test]
fn material_is_usable_from_public_api() {
    let material = Pkcs8SpkiKeyMaterial::new(
        vec![0x30, 0x82, 0x01, 0x22],
        "-----BEGIN PRIVATE KEY-----\nMHg=\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x59, 0x30, 0x13],
        "-----BEGIN PUBLIC KEY-----\nMFk=\n-----END PUBLIC KEY-----\n",
    );

    assert!(!material.private_key_pkcs8_pem().is_empty());
    assert!(!material.public_key_spki_pem().is_empty());
    assert_eq!(material.private_key_pkcs8_der(), &[0x30, 0x82, 0x01, 0x22]);

    let private = material
        .write_private_key_pkcs8_pem()
        .expect("write private key temp artifact");
    let public = material
        .write_public_key_spki_pem()
        .expect("write public key temp artifact");

    assert!(
        private
            .read_to_string()
            .expect("read private")
            .contains("PRIVATE KEY")
    );
    assert!(
        public
            .read_to_string()
            .expect("read public")
            .contains("PUBLIC KEY")
    );
}
