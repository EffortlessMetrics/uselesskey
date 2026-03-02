//! Edge-case and boundary tests for HMAC secret fixtures.

mod testutil;
use testutil::fx;

use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

// ── Empty and unusual labels ────────────────────────────────────────

#[test]
fn empty_label_produces_valid_secret() {
    let secret = fx().hmac("", HmacSpec::hs256());
    assert_eq!(secret.secret_bytes().len(), 32);
}

#[test]
fn unicode_label_produces_valid_secret() {
    let secret = fx().hmac("日本語🔑", HmacSpec::hs256());
    assert_eq!(secret.secret_bytes().len(), 32);
}

#[test]
fn very_long_label_works() {
    let label = "x".repeat(10_000);
    let secret = fx().hmac(&label, HmacSpec::hs256());
    assert_eq!(secret.secret_bytes().len(), 32);
}

#[test]
fn null_byte_label() {
    let secret = fx().hmac("label\0null", HmacSpec::hs256());
    assert_eq!(secret.secret_bytes().len(), 32);
}

// ── All specs produce correct length ────────────────────────────────

#[test]
fn hs256_length() {
    let s = fx().hmac("len-256", HmacSpec::hs256());
    assert_eq!(s.secret_bytes().len(), 32);
}

#[test]
fn hs384_length() {
    let s = fx().hmac("len-384", HmacSpec::hs384());
    assert_eq!(s.secret_bytes().len(), 48);
}

#[test]
fn hs512_length() {
    let s = fx().hmac("len-512", HmacSpec::hs512());
    assert_eq!(s.secret_bytes().len(), 64);
}

// ── Debug does not leak secret material ─────────────────────────────

#[test]
fn debug_does_not_leak_secret() {
    let s = fx().hmac("debug-test", HmacSpec::hs256());
    let dbg = format!("{s:?}");
    let hex: String = s
        .secret_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    assert!(dbg.contains("HmacSecret"), "Debug should name the type");
    assert!(dbg.contains("debug-test"), "Debug should show label");
    // Secret bytes should not appear in debug output
    assert!(
        !dbg.contains(&hex[..16]),
        "Debug must not leak hex of secret"
    );
}

#[test]
fn debug_uses_non_exhaustive() {
    let s = fx().hmac("ne-test", HmacSpec::hs256());
    let dbg = format!("{s:?}");
    assert!(dbg.contains(".."), "Debug should use finish_non_exhaustive");
}

// ── Clone ───────────────────────────────────────────────────────────

#[test]
fn clone_shares_secret() {
    let s = fx().hmac("clone-test", HmacSpec::hs256());
    let cloned = s.clone();
    assert_eq!(s.secret_bytes(), cloned.secret_bytes());
}

// ── Spec trait coverage ─────────────────────────────────────────────

#[test]
fn spec_clone_copy_eq() {
    let s1 = HmacSpec::hs256();
    let s2 = s1;
    assert_eq!(s1, s2);

    let s3 = HmacSpec::hs384();
    assert_ne!(s1, s3);
}

#[test]
fn spec_hash_in_set() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(HmacSpec::hs256());
    set.insert(HmacSpec::hs384());
    set.insert(HmacSpec::hs512());
    set.insert(HmacSpec::hs256()); // duplicate
    assert_eq!(set.len(), 3);
}

#[test]
fn spec_alg_names() {
    assert_eq!(HmacSpec::hs256().alg_name(), "HS256");
    assert_eq!(HmacSpec::hs384().alg_name(), "HS384");
    assert_eq!(HmacSpec::hs512().alg_name(), "HS512");
}

#[test]
fn spec_byte_lens() {
    assert_eq!(HmacSpec::hs256().byte_len(), 32);
    assert_eq!(HmacSpec::hs384().byte_len(), 48);
    assert_eq!(HmacSpec::hs512().byte_len(), 64);
}

#[test]
fn spec_stable_bytes_all_different() {
    let b1 = HmacSpec::hs256().stable_bytes();
    let b2 = HmacSpec::hs384().stable_bytes();
    let b3 = HmacSpec::hs512().stable_bytes();
    assert_ne!(b1, b2);
    assert_ne!(b2, b3);
    assert_ne!(b1, b3);
}

// ── Same label different spec → different secrets ───────────────────

#[test]
fn same_label_different_spec_produces_different_secrets() {
    let s256 = fx().hmac("spec-diff", HmacSpec::hs256());
    let s384 = fx().hmac("spec-diff", HmacSpec::hs384());
    let s512 = fx().hmac("spec-diff", HmacSpec::hs512());

    assert_ne!(s256.secret_bytes(), &s384.secret_bytes()[..32]);
    assert_ne!(s384.secret_bytes(), &s512.secret_bytes()[..48]);
}

// ── Concurrent access ───────────────────────────────────────────────

#[test]
fn concurrent_hmac_same_label() {
    use std::thread;

    let fx = fx();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let fx = fx.clone();
            thread::spawn(move || {
                let s = fx.hmac("concurrent-hmac", HmacSpec::hs256());
                s.secret_bytes().to_vec()
            })
        })
        .collect();

    let results: Vec<Vec<u8>> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for pair in results.windows(2) {
        assert_eq!(pair[0], pair[1]);
    }
}
