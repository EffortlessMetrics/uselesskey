use uselesskey_core::negative::CorruptPem;
use uselesskey_core_keypair_material::Pkcs8SpkiKeyMaterial;

// ── helpers ──────────────────────────────────────────────────────────────

fn rsa_like_material() -> Pkcs8SpkiKeyMaterial {
    Pkcs8SpkiKeyMaterial::new(
        vec![0x30, 0x82, 0x04, 0xBE, 0x02, 0x01, 0x00],
        "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg==\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x82, 0x01, 0x22, 0x30, 0x0D],
        "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg==\n-----END PUBLIC KEY-----\n",
    )
}

fn ec_like_material() -> Pkcs8SpkiKeyMaterial {
    Pkcs8SpkiKeyMaterial::new(
        vec![0x30, 0x81, 0x87, 0x02, 0x01, 0x00],
        "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMB==\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x59, 0x30, 0x13],
        "-----BEGIN PUBLIC KEY-----\nMFkwEw==\n-----END PUBLIC KEY-----\n",
    )
}

fn ed25519_like_material() -> Pkcs8SpkiKeyMaterial {
    Pkcs8SpkiKeyMaterial::new(
        vec![0x30, 0x2E, 0x02, 0x01, 0x00],
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAw\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x2A, 0x30, 0x05],
        "-----BEGIN PUBLIC KEY-----\nMCowBQ==\n-----END PUBLIC KEY-----\n",
    )
}

// ── 1. Construction from raw bytes ───────────────────────────────────────

#[test]
fn construction_from_vec() {
    let m = rsa_like_material();
    assert_eq!(m.private_key_pkcs8_der().len(), 7);
    assert_eq!(m.public_key_spki_der().len(), 6);
}

#[test]
fn construction_from_arc_slice() {
    use std::sync::Arc;
    let pkcs8: Arc<[u8]> = Arc::from([0x30, 0x82].as_slice());
    let spki: Arc<[u8]> = Arc::from([0x30, 0x59].as_slice());
    let m = Pkcs8SpkiKeyMaterial::new(
        pkcs8.clone(),
        "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
        spki.clone(),
        "-----BEGIN PUBLIC KEY-----\nBB==\n-----END PUBLIC KEY-----\n",
    );
    assert_eq!(m.private_key_pkcs8_der(), &[0x30, 0x82]);
    assert_eq!(m.public_key_spki_der(), &[0x30, 0x59]);
}

#[test]
fn construction_accepts_string_and_str() {
    let m = Pkcs8SpkiKeyMaterial::new(
        vec![1],
        String::from("-----BEGIN PRIVATE KEY-----\nAQ==\n-----END PRIVATE KEY-----\n"),
        vec![2],
        "-----BEGIN PUBLIC KEY-----\nAg==\n-----END PUBLIC KEY-----\n",
    );
    assert!(m.private_key_pkcs8_pem().contains("PRIVATE KEY"));
    assert!(m.public_key_spki_pem().contains("PUBLIC KEY"));
}

// ── 2. Public key extraction ─────────────────────────────────────────────

#[test]
fn public_key_spki_der_returns_correct_bytes() {
    let m = rsa_like_material();
    assert_eq!(
        m.public_key_spki_der(),
        &[0x30, 0x82, 0x01, 0x22, 0x30, 0x0D]
    );
}

#[test]
fn public_key_spki_pem_has_public_key_markers() {
    let m = rsa_like_material();
    let pem = m.public_key_spki_pem();
    assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    assert!(pem.contains("-----END PUBLIC KEY-----"));
}

// ── 3. Private key extraction ────────────────────────────────────────────

#[test]
fn private_key_pkcs8_der_returns_correct_bytes() {
    let m = rsa_like_material();
    assert_eq!(
        m.private_key_pkcs8_der(),
        &[0x30, 0x82, 0x04, 0xBE, 0x02, 0x01, 0x00]
    );
}

#[test]
fn private_key_pkcs8_pem_has_private_key_markers() {
    let m = rsa_like_material();
    let pem = m.private_key_pkcs8_pem();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(pem.contains("-----END PRIVATE KEY-----"));
}

// ── 4. PEM encoding produces valid PEM structure ─────────────────────────

#[test]
fn pem_private_has_begin_end_markers() {
    for m in [
        rsa_like_material(),
        ec_like_material(),
        ed25519_like_material(),
    ] {
        let pem = m.private_key_pkcs8_pem();
        assert!(
            pem.contains("-----BEGIN PRIVATE KEY-----"),
            "missing BEGIN PRIVATE KEY"
        );
        assert!(
            pem.contains("-----END PRIVATE KEY-----"),
            "missing END PRIVATE KEY"
        );
    }
}

#[test]
fn pem_public_has_begin_end_markers() {
    for m in [
        rsa_like_material(),
        ec_like_material(),
        ed25519_like_material(),
    ] {
        let pem = m.public_key_spki_pem();
        assert!(
            pem.contains("-----BEGIN PUBLIC KEY-----"),
            "missing BEGIN PUBLIC KEY"
        );
        assert!(
            pem.contains("-----END PUBLIC KEY-----"),
            "missing END PUBLIC KEY"
        );
    }
}

// ── 5. DER encoding produces non-empty bytes ─────────────────────────────

#[test]
fn der_private_key_is_non_empty() {
    for m in [
        rsa_like_material(),
        ec_like_material(),
        ed25519_like_material(),
    ] {
        assert!(!m.private_key_pkcs8_der().is_empty());
    }
}

#[test]
fn der_public_key_is_non_empty() {
    for m in [
        rsa_like_material(),
        ec_like_material(),
        ed25519_like_material(),
    ] {
        assert!(!m.public_key_spki_der().is_empty());
    }
}

// ── 6. Debug output does NOT leak key material ───────────────────────────

#[test]
fn debug_does_not_contain_pem_headers() {
    let m = rsa_like_material();
    let dbg = format!("{m:?}");
    assert!(dbg.contains("Pkcs8SpkiKeyMaterial"));
    assert!(
        !dbg.contains("BEGIN PRIVATE KEY"),
        "debug leaked private PEM header"
    );
    assert!(
        !dbg.contains("END PRIVATE KEY"),
        "debug leaked private PEM footer"
    );
    assert!(
        !dbg.contains("BEGIN PUBLIC KEY"),
        "debug leaked public PEM header"
    );
    assert!(
        !dbg.contains("END PUBLIC KEY"),
        "debug leaked public PEM footer"
    );
}

#[test]
fn debug_does_not_contain_base64_body() {
    let m = rsa_like_material();
    let dbg = format!("{m:?}");
    assert!(!dbg.contains("MIIEvg"), "debug leaked base64 body");
    assert!(!dbg.contains("MIIBIj"), "debug leaked base64 body");
}

#[test]
fn debug_shows_lengths_instead() {
    let m = rsa_like_material();
    let dbg = format!("{m:?}");
    assert!(dbg.contains("pkcs8_der_len"), "missing pkcs8_der_len");
    assert!(dbg.contains("spki_der_len"), "missing spki_der_len");
    assert!(dbg.contains("pkcs8_pem_len"), "missing pkcs8_pem_len");
    assert!(dbg.contains("spki_pem_len"), "missing spki_pem_len");
}

// ── 7. Different key types ───────────────────────────────────────────────

#[test]
fn rsa_ec_ed25519_produce_distinct_kids() {
    let rsa = rsa_like_material();
    let ec = ec_like_material();
    let ed = ed25519_like_material();

    let kids = [rsa.kid(), ec.kid(), ed.kid()];
    // All kids are non-empty
    for kid in &kids {
        assert!(!kid.is_empty());
    }
    // All kids are distinct because SPKI bytes differ
    assert_ne!(kids[0], kids[1]);
    assert_ne!(kids[1], kids[2]);
    assert_ne!(kids[0], kids[2]);
}

#[test]
fn ec_material_accessors_work() {
    let m = ec_like_material();
    assert_eq!(
        m.private_key_pkcs8_der(),
        &[0x30, 0x81, 0x87, 0x02, 0x01, 0x00]
    );
    assert_eq!(m.public_key_spki_der(), &[0x30, 0x59, 0x30, 0x13]);
    assert!(m.private_key_pkcs8_pem().contains("PRIVATE KEY"));
    assert!(m.public_key_spki_pem().contains("PUBLIC KEY"));
}

#[test]
fn ed25519_material_accessors_work() {
    let m = ed25519_like_material();
    assert_eq!(m.private_key_pkcs8_der(), &[0x30, 0x2E, 0x02, 0x01, 0x00]);
    assert_eq!(m.public_key_spki_der(), &[0x30, 0x2A, 0x30, 0x05]);
    assert!(m.private_key_pkcs8_pem().contains("PRIVATE KEY"));
    assert!(m.public_key_spki_pem().contains("PUBLIC KEY"));
}

// ── 8. Clone produces identical material ─────────────────────────────────

#[test]
fn clone_preserves_all_fields() {
    let original = rsa_like_material();
    let cloned = original.clone();

    assert_eq!(
        original.private_key_pkcs8_der(),
        cloned.private_key_pkcs8_der()
    );
    assert_eq!(
        original.private_key_pkcs8_pem(),
        cloned.private_key_pkcs8_pem()
    );
    assert_eq!(original.public_key_spki_der(), cloned.public_key_spki_der());
    assert_eq!(original.public_key_spki_pem(), cloned.public_key_spki_pem());
    assert_eq!(original.kid(), cloned.kid());
}

#[test]
fn clone_is_independent() {
    let original = rsa_like_material();
    let cloned = original.clone();
    // Mutating through corruption on one doesn't affect the other
    let corrupted = original.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    // The cloned material still has the original PEM
    assert_ne!(corrupted, cloned.private_key_pkcs8_pem());
    assert_eq!(
        cloned.private_key_pkcs8_pem(),
        rsa_like_material().private_key_pkcs8_pem()
    );
}

// ── Negative fixture methods ─────────────────────────────────────────────

#[test]
fn corrupt_pem_bad_header_changes_header() {
    let m = rsa_like_material();
    let corrupted = m.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert_ne!(corrupted, m.private_key_pkcs8_pem());
    assert!(!corrupted.contains("-----BEGIN PRIVATE KEY-----"));
}

#[test]
fn corrupt_pem_bad_footer_changes_footer() {
    let m = rsa_like_material();
    let corrupted = m.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
    assert_ne!(corrupted, m.private_key_pkcs8_pem());
    assert!(!corrupted.contains("-----END PRIVATE KEY-----"));
}

#[test]
fn corrupt_pem_bad_base64_differs_from_original() {
    let m = rsa_like_material();
    let corrupted = m.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    assert_ne!(corrupted, m.private_key_pkcs8_pem());
}

#[test]
fn corrupt_pem_extra_blank_line() {
    let m = rsa_like_material();
    let corrupted = m.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine);
    assert_ne!(corrupted, m.private_key_pkcs8_pem());
}

#[test]
fn corrupt_pem_truncate() {
    let m = rsa_like_material();
    let corrupted = m.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 10 });
    assert_ne!(corrupted, m.private_key_pkcs8_pem());
    assert!(corrupted.len() <= m.private_key_pkcs8_pem().len());
}

#[test]
fn deterministic_corruption_stable_across_calls() {
    let m = rsa_like_material();
    let a = m.private_key_pkcs8_pem_corrupt_deterministic("test-variant-1");
    let b = m.private_key_pkcs8_pem_corrupt_deterministic("test-variant-1");
    assert_eq!(a, b);
}

#[test]
fn deterministic_corruption_differs_by_variant() {
    let m = rsa_like_material();
    let a = m.private_key_pkcs8_pem_corrupt_deterministic("variant-alpha");
    let b = m.private_key_pkcs8_pem_corrupt_deterministic("variant-beta");
    assert_ne!(a, b);
}

#[test]
fn der_truncation_at_zero_gives_empty() {
    let m = rsa_like_material();
    let truncated = m.private_key_pkcs8_der_truncated(0);
    assert!(truncated.is_empty());
}

#[test]
fn der_truncation_beyond_len_returns_full() {
    let m = rsa_like_material();
    let full_len = m.private_key_pkcs8_der().len();
    let truncated = m.private_key_pkcs8_der_truncated(full_len + 100);
    assert_eq!(truncated.len(), full_len);
}

#[test]
fn der_truncation_preserves_prefix() {
    let m = rsa_like_material();
    let truncated = m.private_key_pkcs8_der_truncated(3);
    assert_eq!(truncated, &m.private_key_pkcs8_der()[..3]);
}

#[test]
fn der_corrupt_deterministic_stable() {
    let m = rsa_like_material();
    let a = m.private_key_pkcs8_der_corrupt_deterministic("der-v1");
    let b = m.private_key_pkcs8_der_corrupt_deterministic("der-v1");
    assert_eq!(a, b);
}

#[test]
fn der_corrupt_deterministic_differs_by_variant() {
    let m = rsa_like_material();
    let a = m.private_key_pkcs8_der_corrupt_deterministic("der-alpha");
    let b = m.private_key_pkcs8_der_corrupt_deterministic("der-beta");
    assert_ne!(a, b);
}

// ── kid ──────────────────────────────────────────────────────────────────

#[test]
fn kid_is_deterministic() {
    let m = rsa_like_material();
    assert_eq!(m.kid(), m.kid());
}

#[test]
fn kid_differs_for_different_spki() {
    let m1 = rsa_like_material();
    let m2 = Pkcs8SpkiKeyMaterial::new(
        m1.private_key_pkcs8_der(),
        m1.private_key_pkcs8_pem(),
        vec![0xFF, 0xFE, 0xFD],
        "-----BEGIN PUBLIC KEY-----\nZZZZ\n-----END PUBLIC KEY-----\n",
    );
    assert_ne!(m1.kid(), m2.kid());
}

#[test]
fn kid_is_non_empty_for_all_key_types() {
    for m in [
        rsa_like_material(),
        ec_like_material(),
        ed25519_like_material(),
    ] {
        assert!(!m.kid().is_empty());
    }
}

// ── Temp file round-trip ─────────────────────────────────────────────────

#[test]
fn tempfile_private_key_round_trip() {
    let m = rsa_like_material();
    let tmp = m.write_private_key_pkcs8_pem().expect("write private");
    let content = tmp.read_to_string().expect("read");
    assert_eq!(content, m.private_key_pkcs8_pem());
}

#[test]
fn tempfile_public_key_round_trip() {
    let m = rsa_like_material();
    let tmp = m.write_public_key_spki_pem().expect("write public");
    let content = tmp.read_to_string().expect("read");
    assert_eq!(content, m.public_key_spki_pem());
}

// ── Property-based tests ─────────────────────────────────────────────────

mod property {
    use proptest::prelude::*;
    use uselesskey_core_keypair_material::Pkcs8SpkiKeyMaterial;

    fn arb_material() -> impl Strategy<Value = Pkcs8SpkiKeyMaterial> {
        (
            prop::collection::vec(any::<u8>(), 1..64),
            prop::collection::vec(any::<u8>(), 1..64),
        )
            .prop_map(|(pkcs8, spki)| {
                Pkcs8SpkiKeyMaterial::new(
                    pkcs8,
                    "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----\n",
                    spki,
                    "-----BEGIN PUBLIC KEY-----\ndata\n-----END PUBLIC KEY-----\n",
                )
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

        #[test]
        fn clone_equals_original(m in arb_material()) {
            let c = m.clone();
            prop_assert_eq!(m.private_key_pkcs8_der(), c.private_key_pkcs8_der());
            prop_assert_eq!(m.private_key_pkcs8_pem(), c.private_key_pkcs8_pem());
            prop_assert_eq!(m.public_key_spki_der(), c.public_key_spki_der());
            prop_assert_eq!(m.public_key_spki_pem(), c.public_key_spki_pem());
            prop_assert_eq!(m.kid(), c.kid());
        }

        #[test]
        fn debug_never_leaks_pem(m in arb_material()) {
            let dbg = format!("{m:?}");
            prop_assert!(!dbg.contains("BEGIN PRIVATE KEY"));
            prop_assert!(!dbg.contains("END PRIVATE KEY"));
            prop_assert!(!dbg.contains("BEGIN PUBLIC KEY"));
            prop_assert!(!dbg.contains("END PUBLIC KEY"));
        }

        #[test]
        fn kid_stable(m in arb_material()) {
            prop_assert_eq!(m.kid(), m.kid());
            prop_assert!(!m.kid().is_empty());
        }

        #[test]
        fn truncation_len_capped(
            der in prop::collection::vec(any::<u8>(), 0..128),
            request in 0usize..256,
        ) {
            let m = Pkcs8SpkiKeyMaterial::new(
                der.clone(),
                "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
                vec![0x30],
                "-----BEGIN PUBLIC KEY-----\nMA==\n-----END PUBLIC KEY-----\n",
            );
            let truncated = m.private_key_pkcs8_der_truncated(request);
            prop_assert_eq!(truncated.len(), request.min(der.len()));
        }

        #[test]
        fn deterministic_pem_corruption_reproducible(
            variant in "[a-z0-9]{1,16}",
        ) {
            let m = Pkcs8SpkiKeyMaterial::new(
                vec![0x30, 0x82, 0x01],
                "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
                vec![0x30],
                "-----BEGIN PUBLIC KEY-----\nMA==\n-----END PUBLIC KEY-----\n",
            );
            let a = m.private_key_pkcs8_pem_corrupt_deterministic(&variant);
            let b = m.private_key_pkcs8_pem_corrupt_deterministic(&variant);
            prop_assert_eq!(a, b);
        }

        #[test]
        fn deterministic_der_corruption_reproducible(
            variant in "[a-z0-9]{1,16}",
        ) {
            let m = Pkcs8SpkiKeyMaterial::new(
                vec![0x30, 0x82, 0x01, 0x22],
                "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
                vec![0x30],
                "-----BEGIN PUBLIC KEY-----\nMA==\n-----END PUBLIC KEY-----\n",
            );
            let a = m.private_key_pkcs8_der_corrupt_deterministic(&variant);
            let b = m.private_key_pkcs8_der_corrupt_deterministic(&variant);
            prop_assert_eq!(a, b);
        }

        #[test]
        fn kid_depends_only_on_spki(
            pkcs8_a in prop::collection::vec(any::<u8>(), 1..32),
            pkcs8_b in prop::collection::vec(any::<u8>(), 1..32),
            spki in prop::collection::vec(any::<u8>(), 1..32),
        ) {
            let m1 = Pkcs8SpkiKeyMaterial::new(
                pkcs8_a,
                "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
                spki.clone(),
                "-----BEGIN PUBLIC KEY-----\nBB==\n-----END PUBLIC KEY-----\n",
            );
            let m2 = Pkcs8SpkiKeyMaterial::new(
                pkcs8_b,
                "-----BEGIN PRIVATE KEY-----\nCC==\n-----END PRIVATE KEY-----\n",
                spki,
                "-----BEGIN PUBLIC KEY-----\nBB==\n-----END PUBLIC KEY-----\n",
            );
            prop_assert_eq!(m1.kid(), m2.kid());
        }
    }
}
