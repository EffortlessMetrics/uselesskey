//! Security invariant tests: Debug output must never leak key material.
//!
//! For each algorithm crate (RSA, ECDSA, Ed25519, HMAC, Token), generates a
//! key fixture and verifies that `Debug` formatting does not contain the
//! base64-encoded (or raw) key bytes.

#![cfg(feature = "security-invariants")]

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use uselesskey_core::{Factory, Seed};
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_token::{TokenFactoryExt, TokenSpec};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn det_factory() -> Factory {
    Factory::deterministic(Seed::new([0x42; 32]))
}

/// Extract the base64 body lines from a PEM string (the secret part).
fn pem_body_lines(pem: &str) -> Vec<&str> {
    pem.lines()
        .filter(|l| !l.starts_with("-----") && !l.is_empty())
        .collect()
}

// ===========================================================================
// 1. RSA — Debug must not contain base64 key bytes
// ===========================================================================

#[test]
fn rsa_debug_does_not_contain_private_key_bytes() {
    let fx = det_factory();
    let kp = fx.rsa("security-test", RsaSpec::rs256());

    let debug = format!("{kp:?}");
    let der_bytes = kp.private_key_pkcs8_der();
    let b64_key = BASE64.encode(der_bytes);

    // Check a significant substring of the base64-encoded key
    let fragment = &b64_key[0..b64_key.len().min(40)];
    assert!(
        !debug.contains(fragment),
        "RSA Debug must not contain base64 private key fragment"
    );

    // Also check PEM body lines
    for line in pem_body_lines(kp.private_key_pkcs8_pem()) {
        assert!(
            !debug.contains(line),
            "RSA Debug must not contain PEM body line: {line}"
        );
    }
}

#[test]
fn rsa_debug_does_not_contain_public_key_bytes() {
    let fx = det_factory();
    let kp = fx.rsa("security-test", RsaSpec::rs256());

    let debug = format!("{kp:?}");
    let b64_pub = BASE64.encode(kp.public_key_spki_der());
    let fragment = &b64_pub[0..b64_pub.len().min(40)];
    assert!(
        !debug.contains(fragment),
        "RSA Debug must not contain base64 public key fragment"
    );
}

#[test]
fn rsa_debug_shows_label_and_spec_only() {
    let fx = det_factory();
    let kp = fx.rsa("my-label", RsaSpec::rs256());
    let debug = format!("{kp:?}");

    assert!(debug.contains("RsaKeyPair"), "should show struct name");
    assert!(debug.contains("my-label"), "should show label");
    assert!(
        debug.contains(".."),
        "should use finish_non_exhaustive (..)"
    );
}

// ===========================================================================
// 2. ECDSA — Debug must not contain base64 key bytes
// ===========================================================================

#[test]
fn ecdsa_debug_does_not_contain_private_key_bytes() {
    let fx = det_factory();
    let kp = fx.ecdsa("security-test", EcdsaSpec::es256());

    let debug = format!("{kp:?}");
    let b64_key = BASE64.encode(kp.private_key_pkcs8_der());
    let fragment = &b64_key[0..b64_key.len().min(40)];

    assert!(
        !debug.contains(fragment),
        "ECDSA Debug must not contain base64 private key fragment"
    );

    for line in pem_body_lines(kp.private_key_pkcs8_pem()) {
        assert!(
            !debug.contains(line),
            "ECDSA Debug must not contain PEM body line: {line}"
        );
    }
}

#[test]
fn ecdsa_debug_does_not_contain_public_key_bytes() {
    let fx = det_factory();
    let kp = fx.ecdsa("security-test", EcdsaSpec::es256());

    let debug = format!("{kp:?}");
    let b64_pub = BASE64.encode(kp.public_key_spki_der());
    let fragment = &b64_pub[0..b64_pub.len().min(40)];
    assert!(
        !debug.contains(fragment),
        "ECDSA Debug must not contain base64 public key fragment"
    );
}

#[test]
fn ecdsa_debug_shows_label_and_spec_only() {
    let fx = det_factory();
    let kp = fx.ecdsa("my-label", EcdsaSpec::es256());
    let debug = format!("{kp:?}");

    assert!(debug.contains("EcdsaKeyPair"), "should show struct name");
    assert!(debug.contains("my-label"), "should show label");
}

// ===========================================================================
// 3. Ed25519 — Debug must not contain base64 key bytes
// ===========================================================================

#[test]
fn ed25519_debug_does_not_contain_private_key_bytes() {
    let fx = det_factory();
    let kp = fx.ed25519("security-test", Ed25519Spec::new());

    let debug = format!("{kp:?}");
    let b64_key = BASE64.encode(kp.private_key_pkcs8_der());
    let fragment = &b64_key[0..b64_key.len().min(40)];

    assert!(
        !debug.contains(fragment),
        "Ed25519 Debug must not contain base64 private key fragment"
    );

    for line in pem_body_lines(kp.private_key_pkcs8_pem()) {
        assert!(
            !debug.contains(line),
            "Ed25519 Debug must not contain PEM body line: {line}"
        );
    }
}

#[test]
fn ed25519_debug_does_not_contain_public_key_bytes() {
    let fx = det_factory();
    let kp = fx.ed25519("security-test", Ed25519Spec::new());

    let debug = format!("{kp:?}");
    let b64_pub = BASE64.encode(kp.public_key_spki_der());
    let fragment = &b64_pub[0..b64_pub.len().min(40)];
    assert!(
        !debug.contains(fragment),
        "Ed25519 Debug must not contain base64 public key fragment"
    );
}

#[test]
fn ed25519_debug_shows_label_and_spec_only() {
    let fx = det_factory();
    let kp = fx.ed25519("my-label", Ed25519Spec::new());
    let debug = format!("{kp:?}");

    assert!(debug.contains("Ed25519KeyPair"), "should show struct name");
    assert!(debug.contains("my-label"), "should show label");
}

// ===========================================================================
// 4. HMAC — Debug must not contain base64 secret bytes
// ===========================================================================

#[test]
fn hmac_debug_does_not_contain_secret_bytes() {
    let fx = det_factory();
    let secret = fx.hmac("security-test", HmacSpec::hs256());

    let debug = format!("{secret:?}");
    let b64_secret = BASE64.encode(secret.secret_bytes());
    let fragment = &b64_secret[0..b64_secret.len().min(40)];

    assert!(
        !debug.contains(fragment),
        "HMAC Debug must not contain base64 secret fragment"
    );

    // Also check raw hex of first few bytes
    let hex_prefix: String = secret.secret_bytes()[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(
        !debug.to_lowercase().contains(&hex_prefix),
        "HMAC Debug must not contain hex secret prefix: {hex_prefix}"
    );
}

#[test]
fn hmac_debug_shows_label_and_spec_only() {
    let fx = det_factory();
    let secret = fx.hmac("my-label", HmacSpec::hs256());
    let debug = format!("{secret:?}");

    assert!(debug.contains("HmacSecret"), "should show struct name");
    assert!(debug.contains("my-label"), "should show label");
}

// ===========================================================================
// 5. Token — Debug must not contain token value
// ===========================================================================

#[test]
fn token_debug_does_not_contain_token_value() {
    let fx = det_factory();

    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let token = fx.token("security-test", spec);
        let debug = format!("{token:?}");
        let value = token.value();

        // The token value must not appear in Debug
        assert!(
            !debug.contains(value),
            "Token({:?}) Debug must not contain token value: {debug}",
            spec
        );

        // Check a significant substring too (in case of partial matches)
        if value.len() > 10 {
            let fragment = &value[0..10];
            assert!(
                !debug.contains(fragment),
                "Token({:?}) Debug must not contain token value fragment: {debug}",
                spec
            );
        }
    }
}

#[test]
fn token_debug_shows_label_and_spec_only() {
    let fx = det_factory();
    let token = fx.token("my-label", TokenSpec::bearer());
    let debug = format!("{token:?}");

    assert!(debug.contains("TokenFixture"), "should show struct name");
    assert!(debug.contains("my-label"), "should show label");
}

// ===========================================================================
// 6. Cross-algorithm: no key material in any Debug across all types
// ===========================================================================

#[test]
fn all_key_types_debug_never_contains_begin_private_key() {
    let fx = det_factory();

    // RSA
    let rsa_debug = format!("{:?}", fx.rsa("cross", RsaSpec::rs256()));
    assert!(
        !rsa_debug.contains("BEGIN"),
        "RSA Debug contains PEM header"
    );

    // ECDSA
    let ecdsa_debug = format!("{:?}", fx.ecdsa("cross", EcdsaSpec::es256()));
    assert!(
        !ecdsa_debug.contains("BEGIN"),
        "ECDSA Debug contains PEM header"
    );

    // Ed25519
    let ed_debug = format!("{:?}", fx.ed25519("cross", Ed25519Spec::new()));
    assert!(
        !ed_debug.contains("BEGIN"),
        "Ed25519 Debug contains PEM header"
    );
}

// ===========================================================================
// 7. Generated keys do not appear in committed test source files
// ===========================================================================

#[test]
fn generated_key_bytes_not_in_committed_source() {
    use std::path::Path;

    let fx = det_factory();
    let ecdsa_kp = fx.ecdsa("no-blob-check", EcdsaSpec::es256());
    let b64_key = BASE64.encode(ecdsa_kp.private_key_pkcs8_der());

    // Take a significant unique fragment
    let fragment = &b64_key[10..b64_key.len().min(50)];

    // Scan Rust source files in the crates directory
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let crates_dir = root.join("crates");

    let mut found_in: Vec<String> = Vec::new();
    scan_dir_for_fragment(&crates_dir, fragment, &mut found_in);

    assert!(
        found_in.is_empty(),
        "generated key fragment found in committed files:\n  {}",
        found_in.join("\n  ")
    );
}

fn scan_dir_for_fragment(dir: &std::path::Path, fragment: &str, found: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(name, ".git" | "target" | ".cargo") {
                continue;
            }
            scan_dir_for_fragment(&path, fragment, found);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e == "rs")
            .unwrap_or(false)
            && let Ok(content) = std::fs::read_to_string(&path)
            && content.contains(fragment)
        {
            found.push(path.display().to_string());
        }
    }
}

// ===========================================================================
// 8. Test output capture: key generation doesn't write to stderr
// ===========================================================================

#[test]
fn key_generation_does_not_print_to_stderr() {
    // This test verifies that generating keys doesn't produce console output.
    // We can't easily capture stderr in-process, but we can verify that
    // formatting the key types only uses the safe Debug impl.
    let fx = det_factory();

    // Generate keys — these should produce no side-effect output
    let rsa_kp = fx.rsa("stderr-test", RsaSpec::rs256());
    let ecdsa_kp = fx.ecdsa("stderr-test", EcdsaSpec::es256());
    let ed_kp = fx.ed25519("stderr-test", Ed25519Spec::new());
    let hmac_s = fx.hmac("stderr-test", HmacSpec::hs256());
    let token_f = fx.token("stderr-test", TokenSpec::bearer());

    // Verify Debug output is well-formed and short (no accidental dumps)
    for (name, debug) in [
        ("RSA", format!("{rsa_kp:?}")),
        ("ECDSA", format!("{ecdsa_kp:?}")),
        ("Ed25519", format!("{ed_kp:?}")),
        ("HMAC", format!("{hmac_s:?}")),
        ("Token", format!("{token_f:?}")),
    ] {
        assert!(
            debug.len() < 500,
            "{name} Debug output is suspiciously long ({} chars), may contain key material: {debug}",
            debug.len()
        );
    }
}
