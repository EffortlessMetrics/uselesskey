use proptest::prelude::*;

use uselesskey_core_keypair::Pkcs8SpkiKeyMaterial;

/// Strategy for generating fake PEM-like strings with a given label.
fn fake_pem(label: &'static str) -> impl Strategy<Value = String> {
    // Generate a base64-like body (4-128 chars of valid base64 alphabet).
    "[A-Za-z0-9+/]{4,128}"
        .prop_map(move |body| format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Constructing and reading back DER bytes is a roundtrip.
    #[test]
    fn der_roundtrip(
        pkcs8_der in prop::collection::vec(any::<u8>(), 1..128),
        spki_der in prop::collection::vec(any::<u8>(), 1..128),
    ) {
        let material = Pkcs8SpkiKeyMaterial::new(
            pkcs8_der.clone(),
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            spki_der.clone(),
            "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----\n",
        );

        prop_assert_eq!(material.private_key_pkcs8_der(), pkcs8_der.as_slice());
        prop_assert_eq!(material.public_key_spki_der(), spki_der.as_slice());
    }

    /// Constructing and reading back PEM strings is a roundtrip.
    #[test]
    fn pem_roundtrip(
        pkcs8_pem in fake_pem("PRIVATE KEY"),
        spki_pem in fake_pem("PUBLIC KEY"),
    ) {
        let material = Pkcs8SpkiKeyMaterial::new(
            vec![0x30],
            pkcs8_pem.clone(),
            vec![0x30],
            spki_pem.clone(),
        );

        prop_assert_eq!(material.private_key_pkcs8_pem(), pkcs8_pem.as_str());
        prop_assert_eq!(material.public_key_spki_pem(), spki_pem.as_str());
    }

    /// kid is determined solely by SPKI bytes.
    #[test]
    fn kid_depends_only_on_spki(
        spki_der in prop::collection::vec(any::<u8>(), 1..128),
        pkcs8_a in prop::collection::vec(any::<u8>(), 1..64),
        pkcs8_b in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        let m1 = Pkcs8SpkiKeyMaterial::new(
            pkcs8_a,
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            spki_der.clone(),
            "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----\n",
        );
        let m2 = Pkcs8SpkiKeyMaterial::new(
            pkcs8_b,
            "-----BEGIN PRIVATE KEY-----\nCCCC\n-----END PRIVATE KEY-----\n",
            spki_der,
            "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----\n",
        );

        prop_assert_eq!(m1.kid(), m2.kid());
    }

    /// Truncation length is capped at DER length.
    #[test]
    fn truncation_capped_at_der_length(
        der in prop::collection::vec(any::<u8>(), 0..128),
        request in 0usize..256,
    ) {
        let material = Pkcs8SpkiKeyMaterial::new(
            der.clone(),
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            vec![0x30],
            "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----\n",
        );

        let truncated = material.private_key_pkcs8_der_truncated(request);
        prop_assert_eq!(truncated.len(), request.min(der.len()));
    }

    /// Deterministic PEM corruption is reproducible.
    #[test]
    fn deterministic_pem_corruption_reproducible(
        variant in "[a-zA-Z0-9]{1,24}",
    ) {
        let material = Pkcs8SpkiKeyMaterial::new(
            vec![0x30, 0x82, 0x01, 0x22],
            "-----BEGIN PRIVATE KEY-----\nAAAABBBBCCCC\n-----END PRIVATE KEY-----\n",
            vec![0x30, 0x59],
            "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----\n",
        );

        let a = material.private_key_pkcs8_pem_corrupt_deterministic(&variant);
        let b = material.private_key_pkcs8_pem_corrupt_deterministic(&variant);
        prop_assert_eq!(&a, &b);
    }
}
