//! Property-based tests for `uselesskey-core-keypair`.

use proptest::prelude::*;
use uselesskey_core_keypair::Pkcs8SpkiKeyMaterial;

fn make_material(pkcs8_der: Vec<u8>, spki_der: Vec<u8>) -> Pkcs8SpkiKeyMaterial {
    Pkcs8SpkiKeyMaterial::new(
        pkcs8_der,
        "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
        spki_der,
        "-----BEGIN PUBLIC KEY-----\nBB==\n-----END PUBLIC KEY-----\n",
    )
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn kid_is_deterministic(
        spki in proptest::collection::vec(any::<u8>(), 1..128),
    ) {
        let m = make_material(vec![0x30], spki);
        prop_assert_eq!(m.kid(), m.kid());
    }

    #[test]
    fn kid_depends_only_on_spki(
        pkcs8_a in proptest::collection::vec(any::<u8>(), 1..64),
        pkcs8_b in proptest::collection::vec(any::<u8>(), 1..64),
        spki in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        let m1 = Pkcs8SpkiKeyMaterial::new(
            pkcs8_a,
            "pem-a",
            spki.clone(),
            "pub-pem",
        );
        let m2 = Pkcs8SpkiKeyMaterial::new(
            pkcs8_b,
            "pem-b",
            spki,
            "pub-pem",
        );
        prop_assert_eq!(m1.kid(), m2.kid());
    }

    #[test]
    fn different_spki_different_kid(
        spki_a in proptest::collection::vec(any::<u8>(), 4..64),
        spki_b in proptest::collection::vec(any::<u8>(), 4..64),
    ) {
        prop_assume!(spki_a != spki_b);
        let m1 = make_material(vec![0x30], spki_a);
        let m2 = make_material(vec![0x30], spki_b);
        // Extremely unlikely to collide for different SPKI bytes
        prop_assert_ne!(m1.kid(), m2.kid());
    }

    #[test]
    fn kid_is_non_empty(
        spki in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        let m = make_material(vec![0x30], spki);
        prop_assert!(!m.kid().is_empty());
    }

    #[test]
    fn accessors_return_construction_values(
        pkcs8_der in proptest::collection::vec(any::<u8>(), 1..64),
        spki_der in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        let m = Pkcs8SpkiKeyMaterial::new(
            pkcs8_der.clone(),
            "private-pem",
            spki_der.clone(),
            "public-pem",
        );
        prop_assert_eq!(m.private_key_pkcs8_der(), pkcs8_der.as_slice());
        prop_assert_eq!(m.private_key_pkcs8_pem(), "private-pem");
        prop_assert_eq!(m.public_key_spki_der(), spki_der.as_slice());
        prop_assert_eq!(m.public_key_spki_pem(), "public-pem");
    }

    #[test]
    fn clone_preserves_all_fields(
        pkcs8_der in proptest::collection::vec(any::<u8>(), 1..64),
        spki_der in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        let m = Pkcs8SpkiKeyMaterial::new(
            pkcs8_der,
            "priv-pem",
            spki_der,
            "pub-pem",
        );
        let c = m.clone();
        prop_assert_eq!(m.private_key_pkcs8_der(), c.private_key_pkcs8_der());
        prop_assert_eq!(m.private_key_pkcs8_pem(), c.private_key_pkcs8_pem());
        prop_assert_eq!(m.public_key_spki_der(), c.public_key_spki_der());
        prop_assert_eq!(m.public_key_spki_pem(), c.public_key_spki_pem());
        prop_assert_eq!(m.kid(), c.kid());
    }

    #[test]
    fn debug_does_not_leak_pem(
        secret in "[A-Z]{16,64}",
    ) {
        let m = Pkcs8SpkiKeyMaterial::new(
            vec![0x30],
            &secret,
            vec![0x30],
            &secret,
        );
        let dbg = format!("{m:?}");
        prop_assert!(dbg.contains("Pkcs8SpkiKeyMaterial"));
        prop_assert!(!dbg.contains(&secret), "Debug must not leak key material");
    }
}
