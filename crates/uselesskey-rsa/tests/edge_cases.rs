//! Edge-case and boundary tests for RSA key fixtures.

mod testutil;
use testutil::fx;

use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

// ── Empty and unusual labels ────────────────────────────────────────

#[test]
fn empty_label_produces_valid_keypair() {
    let kp = fx().rsa("", RsaSpec::rs256());
    assert!(!kp.private_key_pkcs8_pem().is_empty());
    assert!(!kp.public_key_spki_pem().is_empty());
}

#[test]
fn unicode_label_produces_valid_keypair() {
    let kp = fx().rsa("日本語🔑キー", RsaSpec::rs256());
    assert!(!kp.private_key_pkcs8_der().is_empty());
}

#[test]
fn very_long_label_works() {
    let label = "x".repeat(10_000);
    let kp = fx().rsa(&label, RsaSpec::rs256());
    assert!(!kp.private_key_pkcs8_pem().is_empty());
}

#[test]
fn special_chars_label() {
    let kp = fx().rsa("label/with\\special<chars>&\"'", RsaSpec::rs256());
    assert!(!kp.private_key_pkcs8_pem().is_empty());
}

#[test]
fn null_byte_in_label() {
    let kp = fx().rsa("label\0null", RsaSpec::rs256());
    assert!(!kp.private_key_pkcs8_pem().is_empty());
}

// ── Debug does not leak key material ────────────────────────────────

#[test]
fn debug_does_not_leak_private_key() {
    let kp = fx().rsa("debug-test", RsaSpec::rs256());
    let dbg = format!("{kp:?}");
    let pem = kp.private_key_pkcs8_pem();

    assert!(dbg.contains("RsaKeyPair"), "Debug should name the type");
    assert!(dbg.contains("debug-test"), "Debug should show label");
    // PEM second line contains base64 key material
    for line in pem.lines().skip(1) {
        if line.starts_with("-----") {
            continue;
        }
        assert!(!dbg.contains(line), "Debug leaked PEM content: {line}");
    }
}

#[test]
fn debug_format_uses_non_exhaustive() {
    let kp = fx().rsa("ne-test", RsaSpec::rs256());
    let dbg = format!("{kp:?}");
    assert!(dbg.contains(".."), "Debug should use finish_non_exhaustive");
}

// ── Clone ───────────────────────────────────────────────────────────

#[test]
fn clone_shares_key_material() {
    let kp = fx().rsa("clone-test", RsaSpec::rs256());
    let cloned = kp.clone();
    assert_eq!(kp.private_key_pkcs8_der(), cloned.private_key_pkcs8_der());
    assert_eq!(kp.public_key_spki_der(), cloned.public_key_spki_der());
}

// ── PEM format validation ───────────────────────────────────────────

#[test]
fn private_key_pem_has_correct_headers() {
    let kp = fx().rsa("pem-header", RsaSpec::rs256());
    let pem = kp.private_key_pkcs8_pem();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(pem.trim_end().ends_with("-----END PRIVATE KEY-----"));
}

#[test]
fn public_key_pem_has_correct_headers() {
    let kp = fx().rsa("pem-header-pub", RsaSpec::rs256());
    let pem = kp.public_key_spki_pem();
    assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    assert!(pem.trim_end().ends_with("-----END PUBLIC KEY-----"));
}

// ── Negative fixture edge cases ─────────────────────────────────────

#[test]
fn corrupt_deterministic_with_empty_variant() {
    let kp = fx().rsa("corrupt-empty", RsaSpec::rs256());
    let corrupted = kp.private_key_pkcs8_pem_corrupt_deterministic("");
    assert_ne!(corrupted, kp.private_key_pkcs8_pem());
}

#[test]
fn corrupt_deterministic_with_unicode_variant() {
    let kp = fx().rsa("corrupt-unicode", RsaSpec::rs256());
    let corrupted = kp.private_key_pkcs8_pem_corrupt_deterministic("日本語");
    assert_ne!(corrupted, kp.private_key_pkcs8_pem());
}

#[test]
fn der_truncated_to_zero() {
    let kp = fx().rsa("truncate-zero", RsaSpec::rs256());
    let truncated = kp.private_key_pkcs8_der_truncated(0);
    assert!(truncated.is_empty());
}

#[test]
fn der_truncated_to_one() {
    let kp = fx().rsa("truncate-one", RsaSpec::rs256());
    let truncated = kp.private_key_pkcs8_der_truncated(1);
    assert_eq!(truncated.len(), 1);
    assert_eq!(truncated[0], kp.private_key_pkcs8_der()[0]);
}

#[test]
fn der_truncated_beyond_length_returns_full() {
    let kp = fx().rsa("truncate-beyond", RsaSpec::rs256());
    let der = kp.private_key_pkcs8_der();
    let truncated = kp.private_key_pkcs8_der_truncated(der.len() + 100);
    assert_eq!(truncated.len(), der.len());
}

#[test]
fn der_corrupt_deterministic_differs_from_original() {
    let kp = fx().rsa("der-corrupt", RsaSpec::rs256());
    let corrupted = kp.private_key_pkcs8_der_corrupt_deterministic("variant-a");
    assert_ne!(corrupted, kp.private_key_pkcs8_der());
}

#[test]
fn mismatched_public_key_is_valid_but_different() {
    let kp = fx().rsa("mismatch-test", RsaSpec::rs256());
    let mismatched = kp.mismatched_public_key_spki_der();
    assert_ne!(mismatched, kp.public_key_spki_der());
    // Should still be a valid DER blob (non-empty)
    assert!(!mismatched.is_empty());
}

// ── Tempfile writes ─────────────────────────────────────────────────

#[test]
fn write_private_key_pem_creates_readable_tempfile() {
    let kp = fx().rsa("tempfile-priv", RsaSpec::rs256());
    let tmp = kp.write_private_key_pkcs8_pem().unwrap();
    let content = tmp.read_to_string().unwrap();
    assert_eq!(content, kp.private_key_pkcs8_pem());
}

#[test]
fn write_public_key_pem_creates_readable_tempfile() {
    let kp = fx().rsa("tempfile-pub", RsaSpec::rs256());
    let tmp = kp.write_public_key_spki_pem().unwrap();
    let content = tmp.read_to_string().unwrap();
    assert_eq!(content, kp.public_key_spki_pem());
}

// ── Spec edge cases ─────────────────────────────────────────────────

#[test]
fn same_label_different_spec_produces_different_keys() {
    let kp1 = fx().rsa("spec-diff", RsaSpec::rs256());
    let kp2 = fx().rsa("spec-diff", RsaSpec::new(4096));
    assert_ne!(kp1.private_key_pkcs8_der(), kp2.private_key_pkcs8_der());
}

#[test]
fn rsa_spec_stable_bytes_differ_for_different_sizes() {
    let s1 = RsaSpec::rs256();
    let s2 = RsaSpec::new(4096);
    assert_ne!(s1.stable_bytes(), s2.stable_bytes());
}

// ── Concurrent access ───────────────────────────────────────────────

#[test]
fn concurrent_rsa_generation_same_label() {
    use std::thread;

    let fx = fx();
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let fx = fx.clone();
            thread::spawn(move || {
                let kp = fx.rsa("concurrent-rsa", RsaSpec::rs256());
                kp.private_key_pkcs8_der().to_vec()
            })
        })
        .collect();

    let results: Vec<Vec<u8>> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    // All threads should get the same key
    for pair in results.windows(2) {
        assert_eq!(pair[0], pair[1]);
    }
}
