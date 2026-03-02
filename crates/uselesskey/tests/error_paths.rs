//! Error-path and edge-case tests for the uselesskey facade crate.
//!
//! Exercises boundary inputs (empty labels, very long labels, extreme seeds),
//! negative fixture variants (mismatch, corrupt:*), and factory isolation.
//! No key material appears in assertions — only shapes, lengths, and non-empty
//! checks.

mod testutil;

use uselesskey::prelude::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fx() -> Factory {
    testutil::fx()
}

fn fx_with_seed(seed_bytes: [u8; 32]) -> Factory {
    Factory::deterministic(Seed::new(seed_bytes))
}

// ===========================================================================
// 1. Empty labels — factory should accept "" without panicking
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_empty_label_produces_valid_key() {
    let kp = fx().rsa("", RsaSpec::rs256());
    assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    assert!(!kp.private_key_pkcs8_der().is_empty());
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_empty_label_produces_valid_key() {
    let kp = fx().ecdsa("", EcdsaSpec::es256());
    assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    assert!(!kp.private_key_pkcs8_der().is_empty());
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_empty_label_produces_valid_key() {
    let kp = fx().ed25519("", Ed25519Spec::new());
    assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    assert!(!kp.private_key_pkcs8_der().is_empty());
}

#[test]
#[cfg(feature = "hmac")]
fn hmac_empty_label_produces_valid_secret() {
    let secret = fx().hmac("", HmacSpec::hs256());
    assert_eq!(secret.secret_bytes().len(), 32);
}

// ===========================================================================
// 2. Very long labels — 1000+ chars should work without panic
// ===========================================================================

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_very_long_label_does_not_panic() {
    let long_label = "x".repeat(2000);
    let kp = fx().ecdsa(&long_label, EcdsaSpec::es256());
    assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_very_long_label_does_not_panic() {
    let long_label = "y".repeat(2000);
    let kp = fx().ed25519(&long_label, Ed25519Spec::new());
    assert!(!kp.public_key_spki_der().is_empty());
}

#[test]
#[cfg(feature = "hmac")]
fn hmac_very_long_label_does_not_panic() {
    let long_label = "z".repeat(2000);
    let secret = fx().hmac(&long_label, HmacSpec::hs512());
    assert_eq!(secret.secret_bytes().len(), 64);
}

// ===========================================================================
// 3. Extreme seed values — zero seed and max seed
// ===========================================================================

#[test]
#[cfg(feature = "ecdsa")]
fn deterministic_zero_seed_produces_valid_ecdsa_key() {
    let fx = fx_with_seed([0x00; 32]);
    let kp = fx.ecdsa("zero-seed", EcdsaSpec::es256());
    assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    assert!(!kp.public_key_spki_der().is_empty());
}

#[test]
#[cfg(feature = "ecdsa")]
fn deterministic_max_seed_produces_valid_ecdsa_key() {
    let fx = fx_with_seed([0xFF; 32]);
    let kp = fx.ecdsa("max-seed", EcdsaSpec::es384());
    assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    assert!(!kp.public_key_spki_der().is_empty());
}

#[test]
#[cfg(feature = "ed25519")]
fn deterministic_zero_seed_produces_valid_ed25519_key() {
    let fx = fx_with_seed([0x00; 32]);
    let kp = fx.ed25519("zero-seed", Ed25519Spec::new());
    assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
}

#[test]
#[cfg(feature = "ed25519")]
fn deterministic_max_seed_produces_valid_ed25519_key() {
    let fx = fx_with_seed([0xFF; 32]);
    let kp = fx.ed25519("max-seed", Ed25519Spec::new());
    assert!(!kp.public_key_spki_pem().is_empty());
}

#[test]
#[cfg(feature = "hmac")]
fn deterministic_zero_seed_produces_valid_hmac_secret() {
    let fx = fx_with_seed([0x00; 32]);
    let s = fx.hmac("zero-seed", HmacSpec::hs256());
    assert_eq!(s.secret_bytes().len(), 32);
}

#[test]
#[cfg(feature = "hmac")]
fn deterministic_max_seed_produces_valid_hmac_secret() {
    let fx = fx_with_seed([0xFF; 32]);
    let s = fx.hmac("max-seed", HmacSpec::hs512());
    assert_eq!(s.secret_bytes().len(), 64);
}

#[test]
#[cfg(feature = "ecdsa")]
fn zero_seed_and_max_seed_produce_different_ecdsa_keys() {
    let fx_zero = fx_with_seed([0x00; 32]);
    let fx_max = fx_with_seed([0xFF; 32]);

    let kp_zero = fx_zero.ecdsa("seed-cmp", EcdsaSpec::es256());
    let kp_max = fx_max.ecdsa("seed-cmp", EcdsaSpec::es256());
    assert_ne!(
        kp_zero.private_key_pkcs8_der(),
        kp_max.private_key_pkcs8_der()
    );
}

// ===========================================================================
// 4. Mismatch variant for all asymmetric key types
// ===========================================================================

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_es256_mismatch_differs_from_original() {
    let kp = fx().ecdsa("mismatch-es256", EcdsaSpec::es256());
    let original = kp.public_key_spki_der();
    let mismatched = kp.mismatched_public_key_spki_der();
    assert_ne!(original, mismatched.as_slice());
    assert!(!mismatched.is_empty());
    assert_eq!(mismatched[0], 0x30); // DER SEQUENCE tag
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_es384_mismatch_differs_from_original() {
    let kp = fx().ecdsa("mismatch-es384", EcdsaSpec::es384());
    let original = kp.public_key_spki_der();
    let mismatched = kp.mismatched_public_key_spki_der();
    assert_ne!(original, mismatched.as_slice());
    assert!(!mismatched.is_empty());
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_mismatch_differs_from_original() {
    let kp = fx().ed25519("mismatch-ed25519", Ed25519Spec::new());
    let original = kp.public_key_spki_der();
    let mismatched = kp.mismatched_public_key_spki_der();
    assert_ne!(original, mismatched.as_slice());
    assert!(!mismatched.is_empty());
    assert_eq!(mismatched[0], 0x30);
}

// ===========================================================================
// 5. Corrupt:* variants — deterministic corruption for all key types
// ===========================================================================

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_corrupt_pem_all_variants_differ_from_original() {
    let kp = fx().ecdsa("corrupt-all", EcdsaSpec::es256());
    let original = kp.private_key_pkcs8_pem();
    let variants = [
        kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader),
        kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter),
        kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64),
        kp.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 20 }),
        kp.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine),
    ];
    for (i, v) in variants.iter().enumerate() {
        assert_ne!(v, original, "ecdsa corrupt variant {i} should differ");
    }
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_corrupt_pem_all_variants_differ_from_original() {
    let kp = fx().ed25519("corrupt-all", Ed25519Spec::new());
    let original = kp.private_key_pkcs8_pem();
    let variants = [
        kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader),
        kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter),
        kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64),
        kp.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 10 }),
        kp.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine),
    ];
    for (i, v) in variants.iter().enumerate() {
        assert_ne!(v, original, "ed25519 corrupt variant {i} should differ");
    }
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_deterministic_pem_corruption_is_stable() {
    let kp = fx().ecdsa("corrupt-stable-ecdsa", EcdsaSpec::es256());
    let a = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:edge-v1");
    let b = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:edge-v1");
    assert_eq!(a, b);
    assert_ne!(a, kp.private_key_pkcs8_pem());
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_deterministic_pem_corruption_is_stable() {
    let kp = fx().ed25519("corrupt-stable-ed25519", Ed25519Spec::new());
    let a = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:edge-v1");
    let b = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:edge-v1");
    assert_eq!(a, b);
    assert_ne!(a, kp.private_key_pkcs8_pem());
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_deterministic_der_corruption_is_stable() {
    let kp = fx().ecdsa("der-corrupt-ecdsa", EcdsaSpec::es256());
    let a = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:der-edge-v1");
    let b = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:der-edge-v1");
    assert_eq!(a, b);
    assert_ne!(a, kp.private_key_pkcs8_der());
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_deterministic_der_corruption_is_stable() {
    let kp = fx().ed25519("der-corrupt-ed25519", Ed25519Spec::new());
    let a = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:der-edge-v1");
    let b = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:der-edge-v1");
    assert_eq!(a, b);
    assert_ne!(a, kp.private_key_pkcs8_der());
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_truncated_der_at_zero_is_empty() {
    let kp = fx().ecdsa("trunc-zero-ecdsa", EcdsaSpec::es256());
    let truncated = kp.private_key_pkcs8_der_truncated(0);
    assert!(truncated.is_empty());
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_truncated_der_at_zero_is_empty() {
    let kp = fx().ed25519("trunc-zero-ed25519", Ed25519Spec::new());
    let truncated = kp.private_key_pkcs8_der_truncated(0);
    assert!(truncated.is_empty());
}

// ===========================================================================
// 6. Multiple factories with same seed don't interfere
// ===========================================================================

#[test]
#[cfg(feature = "ecdsa")]
fn two_factories_same_seed_produce_identical_ecdsa_keys() {
    let seed_bytes = [0x42; 32];
    let fx1 = fx_with_seed(seed_bytes);
    let fx2 = fx_with_seed(seed_bytes);

    let kp1 = fx1.ecdsa("shared-label", EcdsaSpec::es256());
    let kp2 = fx2.ecdsa("shared-label", EcdsaSpec::es256());
    assert_eq!(kp1.private_key_pkcs8_pem(), kp2.private_key_pkcs8_pem());
}

#[test]
#[cfg(feature = "ed25519")]
fn two_factories_same_seed_produce_identical_ed25519_keys() {
    let seed_bytes = [0x42; 32];
    let fx1 = fx_with_seed(seed_bytes);
    let fx2 = fx_with_seed(seed_bytes);

    let kp1 = fx1.ed25519("shared-label", Ed25519Spec::new());
    let kp2 = fx2.ed25519("shared-label", Ed25519Spec::new());
    assert_eq!(kp1.private_key_pkcs8_pem(), kp2.private_key_pkcs8_pem());
}

#[test]
#[cfg(feature = "hmac")]
fn two_factories_same_seed_produce_identical_hmac_secrets() {
    let seed_bytes = [0x42; 32];
    let fx1 = fx_with_seed(seed_bytes);
    let fx2 = fx_with_seed(seed_bytes);

    let s1 = fx1.hmac("shared-label", HmacSpec::hs256());
    let s2 = fx2.hmac("shared-label", HmacSpec::hs256());
    assert_eq!(s1.secret_bytes(), s2.secret_bytes());
}

#[test]
#[cfg(feature = "ed25519")]
fn two_factories_same_seed_have_independent_caches() {
    let seed_bytes = [0x42; 32];
    let fx1 = fx_with_seed(seed_bytes);
    let fx2 = fx_with_seed(seed_bytes);

    // Both factories produce identical keys from same seed
    let kp1 = fx1.ed25519("iso-test", Ed25519Spec::new());
    fx1.clear_cache();

    // fx2's cache should be unaffected by fx1.clear_cache()
    let kp2 = fx2.ed25519("iso-test", Ed25519Spec::new());
    assert_eq!(kp1.private_key_pkcs8_pem(), kp2.private_key_pkcs8_pem());
}

// ===========================================================================
// 7. Factory clones share cache
// ===========================================================================

#[test]
#[cfg(feature = "ed25519")]
fn cloned_factory_shares_cache() {
    let fx1 = fx_with_seed([0x10; 32]);
    let fx2 = fx1.clone();

    let kp1 = fx1.ed25519("clone-test", Ed25519Spec::new());
    let kp2 = fx2.ed25519("clone-test", Ed25519Spec::new());
    assert_eq!(kp1.private_key_pkcs8_pem(), kp2.private_key_pkcs8_pem());
}

// ===========================================================================
// 8. Random mode produces non-empty outputs
// ===========================================================================

#[test]
#[cfg(feature = "ecdsa")]
fn random_mode_ecdsa_produces_valid_key() {
    let fx = Factory::random();
    let kp = fx.ecdsa("random-test", EcdsaSpec::es256());
    assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    assert!(!kp.public_key_spki_der().is_empty());
}

#[test]
#[cfg(feature = "ed25519")]
fn random_mode_ed25519_produces_valid_key() {
    let fx = Factory::random();
    let kp = fx.ed25519("random-test", Ed25519Spec::new());
    assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
}

#[test]
#[cfg(feature = "hmac")]
fn random_mode_hmac_produces_valid_secret() {
    let fx = Factory::random();
    let s = fx.hmac("random-test", HmacSpec::hs256());
    assert_eq!(s.secret_bytes().len(), 32);
}

// ===========================================================================
// 9. Error::deterministic_from_env with missing var
// ===========================================================================

#[test]
fn deterministic_from_env_missing_var_returns_error() {
    let result = Factory::deterministic_from_env("USELESSKEY_NONEXISTENT_VAR_12345");
    assert!(result.is_err());
    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("USELESSKEY_NONEXISTENT_VAR_12345"));
}

// ===========================================================================
// 10. Seed::from_env_value edge cases
// ===========================================================================

#[test]
fn seed_from_empty_string_is_ok() {
    let result = Seed::from_env_value("");
    assert!(result.is_ok());
}

#[test]
fn seed_from_whitespace_only_is_ok() {
    let result = Seed::from_env_value("   ");
    assert!(result.is_ok());
}

#[test]
fn seed_from_unicode_is_ok() {
    let result = Seed::from_env_value("🔑🔒🗝️");
    assert!(result.is_ok());
}

// ===========================================================================
// 11. Debug output never leaks key material
// ===========================================================================

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_debug_does_not_contain_begin_private() {
    let kp = fx().ecdsa("debug-check", EcdsaSpec::es256());
    let dbg = format!("{:?}", kp);
    assert!(!dbg.contains("BEGIN PRIVATE KEY"));
    assert!(!dbg.contains("BEGIN PUBLIC KEY"));
    assert!(dbg.contains("EcdsaKeyPair"));
}

#[test]
#[cfg(feature = "hmac")]
fn hmac_debug_does_not_contain_secret_bytes() {
    let s = fx().hmac("debug-check", HmacSpec::hs256());
    let dbg = format!("{:?}", s);
    assert!(!dbg.contains("secret_bytes"));
    assert!(dbg.contains("HmacSecret"));
}

#[test]
fn seed_debug_is_redacted() {
    let seed = Seed::new([0xAB; 32]);
    let dbg = format!("{:?}", seed);
    assert!(dbg.contains("redacted"));
    assert!(!dbg.contains("ab"));
}

// ===========================================================================
// 12. Multiple HMAC specs produce different lengths
// ===========================================================================

#[test]
#[cfg(feature = "hmac")]
fn hmac_all_specs_produce_correct_lengths() {
    let fx = fx();
    let hs256 = fx.hmac("spec-len-256", HmacSpec::hs256());
    let hs384 = fx.hmac("spec-len-384", HmacSpec::hs384());
    let hs512 = fx.hmac("spec-len-512", HmacSpec::hs512());
    assert_eq!(hs256.secret_bytes().len(), 32);
    assert_eq!(hs384.secret_bytes().len(), 48);
    assert_eq!(hs512.secret_bytes().len(), 64);
}

// ===========================================================================
// 13. ECDSA both curves produce valid distinct keys
// ===========================================================================

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_es256_and_es384_produce_different_keys() {
    let fx = fx();
    let es256 = fx.ecdsa("curve-cmp", EcdsaSpec::es256());
    let es384 = fx.ecdsa("curve-cmp", EcdsaSpec::es384());
    assert_ne!(es256.private_key_pkcs8_der(), es384.private_key_pkcs8_der());
}

// ===========================================================================
// 14. Truncation larger than DER returns full DER
// ===========================================================================

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_truncated_der_larger_than_original_returns_full() {
    let kp = fx().ecdsa("trunc-full", EcdsaSpec::es256());
    let full = kp.private_key_pkcs8_der();
    let truncated = kp.private_key_pkcs8_der_truncated(full.len() + 100);
    assert_eq!(truncated, full);
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_truncated_der_larger_than_original_returns_full() {
    let kp = fx().ed25519("trunc-full", Ed25519Spec::new());
    let full = kp.private_key_pkcs8_der();
    let truncated = kp.private_key_pkcs8_der_truncated(full.len() + 100);
    assert_eq!(truncated, full);
}
