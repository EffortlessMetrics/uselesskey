use proptest::prelude::*;
use uselesskey_core::negative::CorruptPem;
use uselesskey_core_keypair_material::Pkcs8SpkiKeyMaterial;

fn sample_material() -> Pkcs8SpkiKeyMaterial {
    Pkcs8SpkiKeyMaterial::new(
        vec![0x30, 0x82, 0x01, 0x22],
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x59, 0x30, 0x13],
        "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----\n",
    )
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// kid is deterministic for fixed SPKI bytes.
    #[test]
    fn kid_is_deterministic(spki in any::<[u8; 4]>()) {
        let m = Pkcs8SpkiKeyMaterial::new(
            vec![0x30],
            "-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----\n",
            spki.to_vec(),
            "-----BEGIN PUBLIC KEY-----\nY\n-----END PUBLIC KEY-----\n",
        );
        prop_assert_eq!(m.kid(), m.kid());
        prop_assert!(!m.kid().is_empty());
    }

    /// Different SPKI bytes produce different kids.
    #[test]
    fn different_spki_different_kid(
        spki_a in any::<[u8; 4]>(),
        spki_b in any::<[u8; 4]>(),
    ) {
        prop_assume!(spki_a != spki_b);
        let m_a = Pkcs8SpkiKeyMaterial::new(vec![0x30], "pem", spki_a.to_vec(), "pub");
        let m_b = Pkcs8SpkiKeyMaterial::new(vec![0x30], "pem", spki_b.to_vec(), "pub");
        prop_assert_ne!(m_a.kid(), m_b.kid());
    }

    /// Deterministic PEM corruption is stable for the same variant.
    #[test]
    fn deterministic_pem_corruption_stable(variant in "[a-zA-Z0-9]{1,24}") {
        let m = sample_material();
        let a = m.private_key_pkcs8_pem_corrupt_deterministic(&variant);
        let b = m.private_key_pkcs8_pem_corrupt_deterministic(&variant);
        prop_assert_eq!(a, b);
    }

    /// Deterministic DER corruption is stable for the same variant.
    #[test]
    fn deterministic_der_corruption_stable(variant in "[a-zA-Z0-9]{1,24}") {
        let m = sample_material();
        let a = m.private_key_pkcs8_der_corrupt_deterministic(&variant);
        let b = m.private_key_pkcs8_der_corrupt_deterministic(&variant);
        prop_assert_eq!(a, b);
    }

    /// Truncation length is capped at the DER length.
    #[test]
    fn truncation_capped(
        der in prop::collection::vec(any::<u8>(), 0..64),
        request in 0usize..128,
    ) {
        let m = Pkcs8SpkiKeyMaterial::new(
            der.clone(),
            "pem",
            vec![0x30],
            "pub",
        );
        let truncated = m.private_key_pkcs8_der_truncated(request);
        prop_assert_eq!(truncated.len(), request.min(der.len()));
    }

    /// BadHeader corruption always produces output containing "CORRUPTED KEY".
    #[test]
    fn bad_header_produces_corrupted_key(
        body in "[A-Za-z0-9+/=]{4,32}",
    ) {
        let m = Pkcs8SpkiKeyMaterial::new(
            vec![0x30],
            format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"),
            vec![0x30],
            "pub",
        );
        let corrupted = m.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
        prop_assert!(corrupted.contains("CORRUPTED KEY"));
    }

    /// Debug output never leaks PEM material.
    #[test]
    fn debug_no_pem_leak(
        body in "[A-Za-z0-9+/=]{8,32}",
    ) {
        let m = Pkcs8SpkiKeyMaterial::new(
            vec![0x30],
            format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"),
            vec![0x30],
            "pub",
        );
        let dbg = format!("{m:?}");
        prop_assert!(!dbg.contains(&body));
    }
}
