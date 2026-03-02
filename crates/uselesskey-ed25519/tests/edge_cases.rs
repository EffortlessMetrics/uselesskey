//! Edge-case and boundary tests for Ed25519 key fixtures.

mod testutil;
use testutil::fx;

use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

// ── Empty and unusual labels ────────────────────────────────────────

#[test]
fn empty_label_produces_valid_keypair() {
    let kp = fx().ed25519("", Ed25519Spec::new());
    assert!(!kp.private_key_pkcs8_pem().is_empty());
    assert!(!kp.public_key_spki_pem().is_empty());
}

#[test]
fn unicode_label_produces_valid_keypair() {
    let kp = fx().ed25519("日本語🔑", Ed25519Spec::new());
    assert!(!kp.private_key_pkcs8_der().is_empty());
}

#[test]
fn very_long_label_works() {
    let label = "x".repeat(10_000);
    let kp = fx().ed25519(&label, Ed25519Spec::new());
    assert!(!kp.private_key_pkcs8_pem().is_empty());
}

#[test]
fn null_byte_label() {
    let kp = fx().ed25519("label\0null", Ed25519Spec::new());
    assert!(!kp.private_key_pkcs8_pem().is_empty());
}

// ── Debug does not leak key material ────────────────────────────────

#[test]
fn debug_does_not_leak_private_key() {
    let kp = fx().ed25519("debug-test", Ed25519Spec::new());
    let dbg = format!("{kp:?}");
    let pem = kp.private_key_pkcs8_pem();

    assert!(dbg.contains("Ed25519KeyPair"), "Debug should name the type");
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
    let kp = fx().ed25519("ne-test", Ed25519Spec::new());
    let dbg = format!("{kp:?}");
    assert!(dbg.contains(".."), "Debug should use finish_non_exhaustive");
}

// ── Clone ───────────────────────────────────────────────────────────

#[test]
fn clone_shares_key_material() {
    let kp = fx().ed25519("clone-test", Ed25519Spec::new());
    let cloned = kp.clone();
    assert_eq!(kp.private_key_pkcs8_der(), cloned.private_key_pkcs8_der());
    assert_eq!(kp.public_key_spki_der(), cloned.public_key_spki_der());
}

// ── Spec trait coverage ─────────────────────────────────────────────

#[test]
fn spec_new_and_default_match() {
    let s1 = Ed25519Spec::new();
    let s2 = Ed25519Spec::default();
    assert_eq!(s1, s2);
}

#[test]
fn spec_clone_copy_eq() {
    let s1 = Ed25519Spec::new();
    let s2 = s1;
    assert_eq!(s1, s2);
}

#[test]
fn spec_hash_in_set() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(Ed25519Spec::new());
    set.insert(Ed25519Spec::new()); // duplicate
    assert_eq!(set.len(), 1);
}

#[test]
fn spec_stable_bytes_are_fixed() {
    let b1 = Ed25519Spec::new().stable_bytes();
    let b2 = Ed25519Spec::new().stable_bytes();
    assert_eq!(b1, b2);
}

// ── PEM format validation ───────────────────────────────────────────

#[test]
fn private_key_pem_headers() {
    let kp = fx().ed25519("pem-test", Ed25519Spec::new());
    let pem = kp.private_key_pkcs8_pem();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(pem.trim_end().ends_with("-----END PRIVATE KEY-----"));
}

#[test]
fn public_key_pem_headers() {
    let kp = fx().ed25519("pem-pub", Ed25519Spec::new());
    let pem = kp.public_key_spki_pem();
    assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    assert!(pem.trim_end().ends_with("-----END PUBLIC KEY-----"));
}

// ── Negative fixtures ───────────────────────────────────────────────

#[test]
fn corrupt_deterministic_empty_variant() {
    let kp = fx().ed25519("corrupt-empty", Ed25519Spec::new());
    let corrupted = kp.private_key_pkcs8_pem_corrupt_deterministic("");
    assert_ne!(corrupted, kp.private_key_pkcs8_pem());
}

#[test]
fn der_truncated_zero() {
    let kp = fx().ed25519("truncate-zero", Ed25519Spec::new());
    let truncated = kp.private_key_pkcs8_der_truncated(0);
    assert!(truncated.is_empty());
}

#[test]
fn der_truncated_to_one() {
    let kp = fx().ed25519("truncate-one", Ed25519Spec::new());
    let truncated = kp.private_key_pkcs8_der_truncated(1);
    assert_eq!(truncated.len(), 1);
}

#[test]
fn der_truncated_beyond_length() {
    let kp = fx().ed25519("truncate-beyond", Ed25519Spec::new());
    let der = kp.private_key_pkcs8_der();
    let truncated = kp.private_key_pkcs8_der_truncated(der.len() + 100);
    assert_eq!(truncated.len(), der.len());
}

#[test]
fn der_corrupt_deterministic_differs() {
    let kp = fx().ed25519("der-corrupt", Ed25519Spec::new());
    let corrupted = kp.private_key_pkcs8_der_corrupt_deterministic("variant-a");
    assert_ne!(corrupted, kp.private_key_pkcs8_der());
}

#[test]
fn mismatched_public_key_differs() {
    let kp = fx().ed25519("mismatch", Ed25519Spec::new());
    let mm = kp.mismatched_public_key_spki_der();
    assert_ne!(mm, kp.public_key_spki_der());
    assert!(!mm.is_empty());
}

// ── Tempfile writes ─────────────────────────────────────────────────

#[test]
fn write_private_key_pem_roundtrip() {
    let kp = fx().ed25519("tmpfile-priv", Ed25519Spec::new());
    let tmp = kp.write_private_key_pkcs8_pem().unwrap();
    assert_eq!(tmp.read_to_string().unwrap(), kp.private_key_pkcs8_pem());
}

#[test]
fn write_public_key_pem_roundtrip() {
    let kp = fx().ed25519("tmpfile-pub", Ed25519Spec::new());
    let tmp = kp.write_public_key_spki_pem().unwrap();
    assert_eq!(tmp.read_to_string().unwrap(), kp.public_key_spki_pem());
}

// ── Determinism with different labels ───────────────────────────────

#[test]
fn different_labels_produce_different_keys() {
    let kp1 = fx().ed25519("label-a", Ed25519Spec::new());
    let kp2 = fx().ed25519("label-b", Ed25519Spec::new());
    assert_ne!(kp1.private_key_pkcs8_der(), kp2.private_key_pkcs8_der());
}

// ── Concurrent access ───────────────────────────────────────────────

#[test]
fn concurrent_ed25519_same_label() {
    use std::thread;

    let fx = fx();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let fx = fx.clone();
            thread::spawn(move || {
                let kp = fx.ed25519("concurrent-ed", Ed25519Spec::new());
                kp.private_key_pkcs8_der().to_vec()
            })
        })
        .collect();

    let results: Vec<Vec<u8>> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for pair in results.windows(2) {
        assert_eq!(pair[0], pair[1]);
    }
}
