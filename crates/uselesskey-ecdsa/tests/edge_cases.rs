//! Edge-case and boundary tests for ECDSA key fixtures.

mod testutil;
use testutil::fx;

use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

// ── Empty and unusual labels ────────────────────────────────────────

#[test]
fn empty_label_produces_valid_keypair() {
    let kp = fx().ecdsa("", EcdsaSpec::es256());
    assert!(!kp.private_key_pkcs8_pem().is_empty());
    assert!(!kp.public_key_spki_pem().is_empty());
}

#[test]
fn unicode_label_produces_valid_keypair() {
    let kp = fx().ecdsa("日本語🔑", EcdsaSpec::es256());
    assert!(!kp.private_key_pkcs8_der().is_empty());
}

#[test]
fn very_long_label_works() {
    let label = "x".repeat(10_000);
    let kp = fx().ecdsa(&label, EcdsaSpec::es256());
    assert!(!kp.private_key_pkcs8_pem().is_empty());
}

#[test]
fn null_byte_label() {
    let kp = fx().ecdsa("label\0null", EcdsaSpec::es256());
    assert!(!kp.private_key_pkcs8_pem().is_empty());
}

// ── Debug does not leak key material ────────────────────────────────

#[test]
fn debug_does_not_leak_private_key() {
    let kp = fx().ecdsa("debug-test", EcdsaSpec::es256());
    let dbg = format!("{kp:?}");
    let pem = kp.private_key_pkcs8_pem();

    assert!(dbg.contains("EcdsaKeyPair"), "Debug should name the type");
    assert!(dbg.contains("debug-test"), "Debug should show label");
    for line in pem.lines().skip(1) {
        if line.starts_with("-----") {
            continue;
        }
        assert!(!dbg.contains(line), "Debug leaked PEM content: {line}");
    }
}

#[test]
fn debug_uses_non_exhaustive() {
    let kp = fx().ecdsa("ne-test", EcdsaSpec::es256());
    let dbg = format!("{kp:?}");
    assert!(dbg.contains(".."), "Debug should use finish_non_exhaustive");
}

// ── Clone ───────────────────────────────────────────────────────────

#[test]
fn clone_shares_key_material() {
    let kp = fx().ecdsa("clone-test", EcdsaSpec::es256());
    let cloned = kp.clone();
    assert_eq!(kp.private_key_pkcs8_der(), cloned.private_key_pkcs8_der());
    assert_eq!(kp.public_key_spki_der(), cloned.public_key_spki_der());
}

// ── Spec trait coverage ─────────────────────────────────────────────

#[test]
fn spec_clone_copy_eq() {
    let s1 = EcdsaSpec::es256();
    let s2 = s1;
    assert_eq!(s1, s2);

    let s3 = EcdsaSpec::es384();
    assert_ne!(s1, s3);
}

#[test]
fn spec_debug_shows_variant() {
    let dbg = format!("{:?}", EcdsaSpec::es256());
    assert!(dbg.contains("Es256") || dbg.contains("ES256") || dbg.contains("es256"));
}

#[test]
fn spec_alg_name() {
    assert_eq!(EcdsaSpec::es256().alg_name(), "ES256");
    assert_eq!(EcdsaSpec::es384().alg_name(), "ES384");
}

#[test]
fn spec_curve_name() {
    assert_eq!(EcdsaSpec::es256().curve_name(), "P-256");
    assert_eq!(EcdsaSpec::es384().curve_name(), "P-384");
}

#[test]
fn spec_coordinate_len() {
    assert_eq!(EcdsaSpec::es256().coordinate_len_bytes(), 32);
    assert_eq!(EcdsaSpec::es384().coordinate_len_bytes(), 48);
}

#[test]
fn spec_stable_bytes_differ() {
    assert_ne!(
        EcdsaSpec::es256().stable_bytes(),
        EcdsaSpec::es384().stable_bytes()
    );
}

#[test]
fn spec_hash_works() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(EcdsaSpec::es256());
    set.insert(EcdsaSpec::es384());
    set.insert(EcdsaSpec::es256()); // duplicate
    assert_eq!(set.len(), 2);
}

// ── PEM format validation ───────────────────────────────────────────

#[test]
fn private_key_pem_headers() {
    let kp = fx().ecdsa("pem-test", EcdsaSpec::es256());
    let pem = kp.private_key_pkcs8_pem();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(pem.trim_end().ends_with("-----END PRIVATE KEY-----"));
}

#[test]
fn public_key_pem_headers() {
    let kp = fx().ecdsa("pem-pub", EcdsaSpec::es256());
    let pem = kp.public_key_spki_pem();
    assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    assert!(pem.trim_end().ends_with("-----END PUBLIC KEY-----"));
}

// ── Negative fixture edge cases ─────────────────────────────────────

#[test]
fn corrupt_deterministic_empty_variant() {
    let kp = fx().ecdsa("corrupt-empty", EcdsaSpec::es256());
    let corrupted = kp.private_key_pkcs8_pem_corrupt_deterministic("");
    assert_ne!(corrupted, kp.private_key_pkcs8_pem());
}

#[test]
fn der_truncated_zero() {
    let kp = fx().ecdsa("truncate-zero", EcdsaSpec::es256());
    let truncated = kp.private_key_pkcs8_der_truncated(0);
    assert!(truncated.is_empty());
}

#[test]
fn der_truncated_beyond_length() {
    let kp = fx().ecdsa("truncate-beyond", EcdsaSpec::es256());
    let der = kp.private_key_pkcs8_der();
    let truncated = kp.private_key_pkcs8_der_truncated(der.len() + 100);
    assert_eq!(truncated.len(), der.len());
}

#[test]
fn mismatched_public_key_differs() {
    let kp = fx().ecdsa("mismatch", EcdsaSpec::es256());
    let mm = kp.mismatched_public_key_spki_der();
    assert_ne!(mm, kp.public_key_spki_der());
    assert!(!mm.is_empty());
}

// ── Both curves produce valid keys ──────────────────────────────────

#[test]
fn es256_and_es384_both_produce_valid_keys() {
    let kp256 = fx().ecdsa("multi-curve", EcdsaSpec::es256());
    let kp384 = fx().ecdsa("multi-curve", EcdsaSpec::es384());

    // Different curves → different keys
    assert_ne!(kp256.private_key_pkcs8_der(), kp384.private_key_pkcs8_der());
    // P-384 key should be larger
    assert!(kp384.private_key_pkcs8_der().len() > kp256.private_key_pkcs8_der().len());
}

// ── Concurrent access ───────────────────────────────────────────────

#[test]
fn concurrent_ecdsa_same_label() {
    use std::thread;

    let fx = fx();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let fx = fx.clone();
            thread::spawn(move || {
                let kp = fx.ecdsa("concurrent-ec", EcdsaSpec::es256());
                kp.private_key_pkcs8_der().to_vec()
            })
        })
        .collect();

    let results: Vec<Vec<u8>> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for pair in results.windows(2) {
        assert_eq!(pair[0], pair[1]);
    }
}
