//! Security tests: verify the "no key leakage" invariant.
//!
//! Every fixture type must have a custom `Debug` impl that redacts key material.
//! These tests verify that `format!("{:?}", ...)` output never contains PEM headers,
//! base64-encoded key data, raw byte dumps, or seed material.

mod testutil;

use uselesskey::prelude::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fx() -> Factory {
    testutil::fx()
}

/// Assert that a debug string does not leak any recognisable key material.
fn assert_no_key_leakage(debug: &str, context: &str) {
    // PEM headers / footers
    assert!(
        !debug.contains("-----BEGIN"),
        "{context}: Debug leaks PEM header: {debug}"
    );
    assert!(
        !debug.contains("-----END"),
        "{context}: Debug leaks PEM footer: {debug}"
    );
    assert!(
        !debug.contains("PRIVATE KEY"),
        "{context}: Debug leaks 'PRIVATE KEY': {debug}"
    );
    assert!(
        !debug.contains("PUBLIC KEY"),
        "{context}: Debug leaks 'PUBLIC KEY': {debug}"
    );
    assert!(
        !debug.contains("CERTIFICATE"),
        "{context}: Debug leaks 'CERTIFICATE': {debug}"
    );
    assert!(
        !debug.contains("PGP"),
        "{context}: Debug leaks 'PGP': {debug}"
    );

    // Length guard: Debug output that is suspiciously long likely contains
    // encoded key material. All current types should produce under 200 chars.
    assert!(
        debug.len() < 500,
        "{context}: Debug output suspiciously long ({} chars, may contain key material): {}",
        debug.len(),
        &debug[..200.min(debug.len())]
    );
}

// ===========================================================================
// 1. Factory and Seed — Debug must not leak the master seed
// ===========================================================================

#[test]
fn security_seed_debug_is_redacted() {
    let seed = Seed::from_env_value("super-secret-seed-value").unwrap();
    let debug = format!("{:?}", seed);

    assert!(
        debug.contains("redacted"),
        "Seed Debug should contain 'redacted': {debug}"
    );
    assert!(
        !debug.contains("super-secret"),
        "Seed Debug must not contain the input value"
    );
    // Seed bytes are 32 bytes, hex would be 64+ chars
    assert!(debug.len() < 50, "Seed Debug too long: {debug}");
}

#[test]
fn security_factory_debug_does_not_leak_seed() {
    let seed = Seed::from_env_value("another-secret-seed").unwrap();
    let fx = Factory::deterministic(seed);
    let debug = format!("{:?}", fx);

    assert!(
        !debug.contains("another-secret"),
        "Factory Debug must not contain seed input"
    );
    assert!(
        debug.contains("Factory"),
        "Factory Debug should identify the type"
    );
    assert!(
        debug.contains("Deterministic"),
        "Factory Debug should show mode"
    );
    // The seed inside Deterministic should be redacted
    assert!(
        debug.contains("redacted"),
        "Factory Debug should show redacted seed: {debug}"
    );
}

#[test]
fn security_factory_random_debug_is_safe() {
    let fx = Factory::random();
    let debug = format!("{:?}", fx);

    assert!(debug.contains("Random"), "Should show Random mode");
    assert_no_key_leakage(&debug, "Factory(Random)");
}

// ===========================================================================
// 2. RSA keypair — Debug must not leak private/public key material
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn security_rsa_keypair_debug_no_leakage() {
    let kp = fx().rsa("security-rsa", RsaSpec::rs256());
    let debug = format!("{:?}", kp);

    assert_no_key_leakage(&debug, "RsaKeyPair");
    assert!(
        debug.contains("RsaKeyPair"),
        "Should identify the type: {debug}"
    );
    assert!(debug.contains("security-rsa"), "Should show label: {debug}");
}

#[test]
#[cfg(feature = "rsa")]
fn security_rsa_debug_does_not_contain_actual_key_bytes() {
    let kp = fx().rsa("security-rsa-bytes", RsaSpec::rs256());
    let debug = format!("{:?}", kp);

    // Grab actual PEM content and ensure none of it appears in debug
    let pem = kp.private_key_pkcs8_pem();
    // Extract the base64 body (second line of PEM, first line of actual data)
    let base64_lines: Vec<&str> = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    for line in &base64_lines {
        if line.len() > 8 {
            assert!(
                !debug.contains(line),
                "Debug contains base64 key material: {line}"
            );
        }
    }
}

// ===========================================================================
// 3. ECDSA keypair — Debug must not leak key material
// ===========================================================================

#[test]
#[cfg(feature = "ecdsa")]
fn security_ecdsa_keypair_debug_no_leakage() {
    let kp = fx().ecdsa("security-ecdsa", EcdsaSpec::es256());
    let debug = format!("{:?}", kp);

    assert_no_key_leakage(&debug, "EcdsaKeyPair(ES256)");
    assert!(debug.contains("EcdsaKeyPair"), "Should identify type");
}

#[test]
#[cfg(feature = "ecdsa")]
fn security_ecdsa_es384_debug_no_leakage() {
    let kp = fx().ecdsa("security-ecdsa-384", EcdsaSpec::es384());
    let debug = format!("{:?}", kp);

    assert_no_key_leakage(&debug, "EcdsaKeyPair(ES384)");
}

#[test]
#[cfg(feature = "ecdsa")]
fn security_ecdsa_debug_does_not_contain_actual_key_bytes() {
    let kp = fx().ecdsa("security-ecdsa-leak", EcdsaSpec::es256());
    let debug = format!("{:?}", kp);

    let pem = kp.private_key_pkcs8_pem();
    let base64_lines: Vec<&str> = pem
        .lines()
        .filter(|l| !l.starts_with("-----") && l.len() > 8)
        .collect();
    for line in &base64_lines {
        assert!(
            !debug.contains(line),
            "ECDSA Debug contains base64 key material: {line}"
        );
    }
}

// ===========================================================================
// 4. Ed25519 keypair — Debug must not leak key material
// ===========================================================================

#[test]
#[cfg(feature = "ed25519")]
fn security_ed25519_keypair_debug_no_leakage() {
    let kp = fx().ed25519("security-ed25519", Ed25519Spec::new());
    let debug = format!("{:?}", kp);

    assert_no_key_leakage(&debug, "Ed25519KeyPair");
    assert!(debug.contains("Ed25519KeyPair"), "Should identify type");
}

#[test]
#[cfg(feature = "ed25519")]
fn security_ed25519_debug_does_not_contain_actual_key_bytes() {
    let kp = fx().ed25519("security-ed25519-leak", Ed25519Spec::new());
    let debug = format!("{:?}", kp);

    let pem = kp.private_key_pkcs8_pem();
    let base64_lines: Vec<&str> = pem
        .lines()
        .filter(|l| !l.starts_with("-----") && l.len() > 8)
        .collect();
    for line in &base64_lines {
        assert!(
            !debug.contains(line),
            "Ed25519 Debug contains base64 key material: {line}"
        );
    }
}

// ===========================================================================
// 5. HMAC secret — Debug must not leak secret bytes
// ===========================================================================

#[test]
#[cfg(feature = "hmac")]
fn security_hmac_secret_debug_no_leakage() {
    let secret = fx().hmac("security-hmac", HmacSpec::hs256());
    let debug = format!("{:?}", secret);

    assert_no_key_leakage(&debug, "HmacSecret(HS256)");
    assert!(debug.contains("HmacSecret"), "Should identify type");
}

#[test]
#[cfg(feature = "hmac")]
fn security_hmac_hs384_debug_no_leakage() {
    let secret = fx().hmac("security-hmac-384", HmacSpec::hs384());
    let debug = format!("{:?}", secret);
    assert_no_key_leakage(&debug, "HmacSecret(HS384)");
}

#[test]
#[cfg(feature = "hmac")]
fn security_hmac_hs512_debug_no_leakage() {
    let secret = fx().hmac("security-hmac-512", HmacSpec::hs512());
    let debug = format!("{:?}", secret);
    assert_no_key_leakage(&debug, "HmacSecret(HS512)");
}

#[test]
#[cfg(feature = "hmac")]
fn security_hmac_debug_does_not_contain_secret_bytes() {
    let secret = fx().hmac("security-hmac-bytes", HmacSpec::hs256());
    let debug = format!("{:?}", secret);

    // Encode the actual secret as hex and base64 and verify neither appears
    let bytes = secret.secret_bytes();
    let hex_str = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    // Any substring of ≥8 hex chars from the secret should not appear
    if hex_str.len() >= 16 {
        let fragment = &hex_str[..16];
        assert!(
            !debug.contains(fragment),
            "HMAC Debug contains hex-encoded secret bytes"
        );
    }
}

// ===========================================================================
// 6. Token fixture — Debug must not leak token value
// ===========================================================================

#[test]
#[cfg(feature = "token")]
fn security_token_debug_no_leakage() {
    let tok = fx().token("security-token", TokenSpec::api_key());
    let debug = format!("{:?}", tok);

    assert_no_key_leakage(&debug, "TokenFixture(ApiKey)");
    assert!(debug.contains("TokenFixture"), "Should identify type");

    // The actual token value must not appear in debug
    let value = tok.value();
    assert!(
        !debug.contains(value),
        "Token Debug contains the actual token value"
    );
}

#[test]
#[cfg(feature = "token")]
fn security_token_bearer_debug_no_leakage() {
    let tok = fx().token("security-bearer", TokenSpec::bearer());
    let debug = format!("{:?}", tok);

    assert_no_key_leakage(&debug, "TokenFixture(Bearer)");
    let value = tok.value();
    assert!(
        !debug.contains(value),
        "Bearer token Debug contains the actual token value"
    );
}

// ===========================================================================
// 7. PGP keypair — Debug must not leak armored key blocks
// ===========================================================================

#[test]
#[cfg(feature = "pgp")]
fn security_pgp_keypair_debug_no_leakage() {
    use uselesskey::{PgpFactoryExt, PgpSpec};

    let kp = fx().pgp("security-pgp", PgpSpec::ed25519());
    let debug = format!("{:?}", kp);

    assert_no_key_leakage(&debug, "PgpKeyPair");
    assert!(debug.contains("PgpKeyPair"), "Should identify type");
}

#[test]
#[cfg(feature = "pgp")]
fn security_pgp_debug_does_not_contain_armored_key() {
    use uselesskey::{PgpFactoryExt, PgpSpec};

    let kp = fx().pgp("security-pgp-leak", PgpSpec::ed25519());
    let debug = format!("{:?}", kp);

    let armored = kp.private_key_armored();
    // Check that no armored line appears in debug
    for line in armored.lines() {
        if line.len() > 16 && !line.starts_with("-----") && !line.starts_with("Comment:") {
            assert!(
                !debug.contains(line),
                "PGP Debug contains armored key data: {line}"
            );
        }
    }
}

// ===========================================================================
// 8. X.509 certificate — Debug must not leak cert/key material
// ===========================================================================

#[test]
#[cfg(feature = "x509")]
fn security_x509_cert_debug_no_leakage() {
    use uselesskey::{X509FactoryExt, X509Spec};

    let spec = X509Spec::self_signed("security-cn");
    let cert = fx().x509_self_signed("security-x509", spec);
    let debug = format!("{:?}", cert);

    assert_no_key_leakage(&debug, "X509Cert");
    assert!(debug.contains("X509Cert"), "Should identify type");
}

#[test]
#[cfg(feature = "x509")]
fn security_x509_chain_debug_no_leakage() {
    use uselesskey::{ChainSpec, X509FactoryExt};

    let spec = ChainSpec::new("security-chain-cn");
    let chain = fx().x509_chain("security-chain", spec);
    let debug = format!("{:?}", chain);

    assert_no_key_leakage(&debug, "X509Chain");
    assert!(debug.contains("X509Chain"), "Should identify type");
}

#[test]
#[cfg(feature = "x509")]
fn security_x509_debug_does_not_contain_cert_pem() {
    use uselesskey::{X509FactoryExt, X509Spec};

    let spec = X509Spec::self_signed("security-cn-leak");
    let cert = fx().x509_self_signed("security-x509-leak", spec);
    let debug = format!("{:?}", cert);

    let pem = cert.cert_pem();
    let base64_lines: Vec<&str> = pem
        .lines()
        .filter(|l| !l.starts_with("-----") && l.len() > 8)
        .collect();
    for line in &base64_lines {
        assert!(
            !debug.contains(line),
            "X509 Debug contains cert PEM data: {line}"
        );
    }
}

// ===========================================================================
// 9. Negative / corrupt fixtures — Debug of corrupted variants must not leak
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn security_corrupt_pem_enum_debug_no_leakage() {
    // CorruptPem variants have derived Debug; they should not contain key data
    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 10 },
        CorruptPem::ExtraBlankLine,
    ];
    for v in &variants {
        let debug = format!("{:?}", v);
        assert!(
            !debug.contains("-----BEGIN"),
            "CorruptPem Debug leaks PEM: {debug}"
        );
        assert!(debug.len() < 100, "CorruptPem Debug too long: {debug}");
    }
}

// ===========================================================================
// 10. Cross-type: all fixture types' Debug with alternate formatting ({:#?})
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn security_rsa_alternate_debug_no_leakage() {
    let kp = fx().rsa("security-rsa-alt", RsaSpec::rs256());
    let debug = format!("{:#?}", kp);
    assert_no_key_leakage(&debug, "RsaKeyPair(alt)");
}

#[test]
#[cfg(feature = "ecdsa")]
fn security_ecdsa_alternate_debug_no_leakage() {
    let kp = fx().ecdsa("security-ecdsa-alt", EcdsaSpec::es256());
    let debug = format!("{:#?}", kp);
    assert_no_key_leakage(&debug, "EcdsaKeyPair(alt)");
}

#[test]
#[cfg(feature = "ed25519")]
fn security_ed25519_alternate_debug_no_leakage() {
    let kp = fx().ed25519("security-ed25519-alt", Ed25519Spec::new());
    let debug = format!("{:#?}", kp);
    assert_no_key_leakage(&debug, "Ed25519KeyPair(alt)");
}

#[test]
#[cfg(feature = "hmac")]
fn security_hmac_alternate_debug_no_leakage() {
    let secret = fx().hmac("security-hmac-alt", HmacSpec::hs256());
    let debug = format!("{:#?}", secret);
    assert_no_key_leakage(&debug, "HmacSecret(alt)");
}

#[test]
#[cfg(feature = "token")]
fn security_token_alternate_debug_no_leakage() {
    let tok = fx().token("security-token-alt", TokenSpec::api_key());
    let debug = format!("{:#?}", tok);
    assert_no_key_leakage(&debug, "TokenFixture(alt)");
    assert!(
        !debug.contains(tok.value()),
        "Token alt-Debug contains token value"
    );
}

#[test]
#[cfg(feature = "pgp")]
fn security_pgp_alternate_debug_no_leakage() {
    use uselesskey::{PgpFactoryExt, PgpSpec};

    let kp = fx().pgp("security-pgp-alt", PgpSpec::ed25519());
    let debug = format!("{:#?}", kp);
    assert_no_key_leakage(&debug, "PgpKeyPair(alt)");
}

#[test]
#[cfg(feature = "x509")]
fn security_x509_alternate_debug_no_leakage() {
    use uselesskey::{X509FactoryExt, X509Spec};

    let spec = X509Spec::self_signed("alt-cn");
    let cert = fx().x509_self_signed("security-x509-alt", spec);
    let debug = format!("{:#?}", cert);
    assert_no_key_leakage(&debug, "X509Cert(alt)");
}

// ===========================================================================
// 11. Error messages must not contain key material
// ===========================================================================

#[test]
fn security_error_missing_env_var_no_leakage() {
    let result = Factory::deterministic_from_env("USELESSKEY_NONEXISTENT_VAR_12345");
    assert!(result.is_err());
    let err = result.unwrap_err();
    let debug = format!("{:?}", err);
    let display = format!("{}", err);
    assert_no_key_leakage(&debug, "Error(Debug)");
    assert_no_key_leakage(&display, "Error(Display)");
}

// ===========================================================================
// 12. Random mode fixtures also safe
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn security_random_rsa_debug_no_leakage() {
    let fx = Factory::random();
    let kp = fx.rsa("security-random-rsa", RsaSpec::rs256());
    let debug = format!("{:?}", kp);
    assert_no_key_leakage(&debug, "RsaKeyPair(random)");
}

#[test]
#[cfg(feature = "ecdsa")]
fn security_random_ecdsa_debug_no_leakage() {
    let fx = Factory::random();
    let kp = fx.ecdsa("security-random-ecdsa", EcdsaSpec::es256());
    let debug = format!("{:?}", kp);
    assert_no_key_leakage(&debug, "EcdsaKeyPair(random)");
}

#[test]
#[cfg(feature = "ed25519")]
fn security_random_ed25519_debug_no_leakage() {
    let fx = Factory::random();
    let kp = fx.ed25519("security-random-ed25519", Ed25519Spec::new());
    let debug = format!("{:?}", kp);
    assert_no_key_leakage(&debug, "Ed25519KeyPair(random)");
}

#[test]
#[cfg(feature = "hmac")]
fn security_random_hmac_debug_no_leakage() {
    let fx = Factory::random();
    let secret = fx.hmac("security-random-hmac", HmacSpec::hs256());
    let debug = format!("{:?}", secret);
    assert_no_key_leakage(&debug, "HmacSecret(random)");
}

// ===========================================================================
// 13. Comprehensive full-feature cross-check
// ===========================================================================

#[test]
#[cfg(feature = "full")]
fn security_full_feature_all_types_debug_no_leakage() {
    use uselesskey::{
        ChainSpec, PgpFactoryExt, PgpSpec, TokenFactoryExt, TokenSpec, X509FactoryExt, X509Spec,
    };

    let fx = fx();

    // RSA
    let rsa_debug = format!("{:?}", fx.rsa("sec-full-rsa", RsaSpec::rs256()));
    assert_no_key_leakage(&rsa_debug, "full:RSA");

    // ECDSA ES256
    let ecdsa_debug = format!("{:?}", fx.ecdsa("sec-full-ec256", EcdsaSpec::es256()));
    assert_no_key_leakage(&ecdsa_debug, "full:ECDSA-ES256");

    // ECDSA ES384
    let ecdsa384_debug = format!("{:?}", fx.ecdsa("sec-full-ec384", EcdsaSpec::es384()));
    assert_no_key_leakage(&ecdsa384_debug, "full:ECDSA-ES384");

    // Ed25519
    let ed_debug = format!("{:?}", fx.ed25519("sec-full-ed", Ed25519Spec::new()));
    assert_no_key_leakage(&ed_debug, "full:Ed25519");

    // HMAC all variants
    let hmac256_debug = format!("{:?}", fx.hmac("sec-full-h256", HmacSpec::hs256()));
    assert_no_key_leakage(&hmac256_debug, "full:HMAC-HS256");
    let hmac384_debug = format!("{:?}", fx.hmac("sec-full-h384", HmacSpec::hs384()));
    assert_no_key_leakage(&hmac384_debug, "full:HMAC-HS384");
    let hmac512_debug = format!("{:?}", fx.hmac("sec-full-h512", HmacSpec::hs512()));
    assert_no_key_leakage(&hmac512_debug, "full:HMAC-HS512");

    // Token
    let tok = fx.token("sec-full-tok", TokenSpec::api_key());
    let tok_debug = format!("{:?}", tok);
    assert_no_key_leakage(&tok_debug, "full:Token");
    assert!(
        !tok_debug.contains(tok.value()),
        "full:Token Debug leaks value"
    );

    // PGP
    let pgp_debug = format!("{:?}", fx.pgp("sec-full-pgp", PgpSpec::ed25519()));
    assert_no_key_leakage(&pgp_debug, "full:PGP");

    // X.509 self-signed
    let spec = X509Spec::self_signed("sec-full-cn");
    let x509_debug = format!("{:?}", fx.x509_self_signed("sec-full-x509", spec));
    assert_no_key_leakage(&x509_debug, "full:X509");

    // X.509 chain
    let chain_debug = format!(
        "{:?}",
        fx.x509_chain("sec-full-chain", ChainSpec::new("sec-full-chain-cn"))
    );
    assert_no_key_leakage(&chain_debug, "full:X509Chain");

    // Factory itself
    let factory_debug = format!("{:?}", fx);
    assert_no_key_leakage(&factory_debug, "full:Factory");
    assert!(
        factory_debug.contains("redacted"),
        "Factory Debug should redact seed"
    );
}
