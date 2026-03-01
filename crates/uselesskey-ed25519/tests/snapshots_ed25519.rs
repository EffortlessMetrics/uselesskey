//! Insta snapshot tests for uselesskey-ed25519.
//!
//! These tests snapshot key shapes produced by deterministic keys
//! to detect unintended changes in PEM format, DER length, JWK structure,
//! and negative-fixture behaviour. Actual key bytes are never snapshotted.

mod testutil;

use serde::Serialize;
use testutil::fx;
use uselesskey_core::negative::CorruptPem;
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

// =========================================================================
// Snapshot structs
// =========================================================================

#[derive(Serialize)]
struct PrivatePemShape {
    header: String,
    trailer: String,
    line_count: usize,
    pem_len: usize,
}

#[derive(Serialize)]
struct PublicPemShape {
    header: String,
    trailer: String,
    line_count: usize,
    pem_len: usize,
}

#[derive(Serialize)]
struct DerShape {
    private_der_len: usize,
    public_der_len: usize,
}

#[cfg(feature = "jwk")]
#[derive(Serialize)]
struct PublicJwkShape {
    kty: String,
    crv: String,
    alg: String,
    use_: String,
    kid_len: usize,
    x_len: usize,
    has_d: bool,
}

#[cfg(feature = "jwk")]
#[derive(Serialize)]
struct PrivateJwkShape {
    kty: String,
    crv: String,
    alg: String,
    use_: String,
    kid_len: usize,
    x_len: usize,
    d_len: usize,
}

#[cfg(feature = "jwk")]
#[derive(Serialize)]
struct JwksShape {
    keys_count: usize,
    first_key_kty: String,
    first_key_crv: String,
}

#[derive(Serialize)]
struct LabelDivergence {
    private_pem_differs: bool,
    public_pem_differs: bool,
    private_der_differs: bool,
    public_der_differs: bool,
}

#[derive(Serialize)]
struct MismatchShape {
    good_public_der_len: usize,
    mismatched_public_der_len: usize,
    keys_differ: bool,
}

#[derive(Serialize)]
struct CorruptPemShape {
    variant: &'static str,
    has_begin_line: bool,
    has_end_line: bool,
    differs_from_original: bool,
}

#[derive(Serialize)]
struct TruncatedDerShape {
    requested_len: usize,
    actual_len: usize,
    shorter_than_original: bool,
}

#[derive(Serialize)]
struct DeterministicCorruptionShape {
    pem_differs_from_good: bool,
    pem_starts_with_dash: bool,
    pem_stable: bool,
    der_differs_from_good: bool,
    der_same_len_as_good: bool,
    der_stable: bool,
}

#[derive(Serialize)]
struct DebugSafety {
    contains_struct_name: bool,
    contains_label: bool,
    contains_private_pem_material: bool,
    uses_non_exhaustive: bool,
}

#[derive(Serialize)]
struct TempfileShape {
    private_tempfile_matches_pem: bool,
    public_tempfile_matches_pem: bool,
}

// =========================================================================
// Private PEM shape
// =========================================================================

#[test]
fn snapshot_private_pem_shape() {
    let fx = fx();
    let key = fx.ed25519("snap-priv-pem", Ed25519Spec::new());
    let pem = key.private_key_pkcs8_pem();
    let lines: Vec<&str> = pem.lines().collect();

    let result = PrivatePemShape {
        header: lines.first().unwrap_or(&"").to_string(),
        trailer: lines.last().unwrap_or(&"").to_string(),
        line_count: lines.len(),
        pem_len: pem.len(),
    };

    insta::assert_yaml_snapshot!("private_pem_shape", result);
}

// =========================================================================
// Public PEM shape
// =========================================================================

#[test]
fn snapshot_public_pem_shape() {
    let fx = fx();
    let key = fx.ed25519("snap-pub-pem", Ed25519Spec::new());
    let pem = key.public_key_spki_pem();
    let lines: Vec<&str> = pem.lines().collect();

    let result = PublicPemShape {
        header: lines.first().unwrap_or(&"").to_string(),
        trailer: lines.last().unwrap_or(&"").to_string(),
        line_count: lines.len(),
        pem_len: pem.len(),
    };

    insta::assert_yaml_snapshot!("public_pem_shape", result);
}

// =========================================================================
// DER lengths
// =========================================================================

#[test]
fn snapshot_der_lengths() {
    let fx = fx();
    let key = fx.ed25519("snap-der", Ed25519Spec::new());

    let result = DerShape {
        private_der_len: key.private_key_pkcs8_der().len(),
        public_der_len: key.public_key_spki_der().len(),
    };

    insta::assert_yaml_snapshot!("der_lengths", result);
}

// =========================================================================
// Public JWK shape
// =========================================================================

#[cfg(feature = "jwk")]
#[test]
fn snapshot_public_jwk_shape() {
    let fx = fx();
    let key = fx.ed25519("snap-pub-jwk", Ed25519Spec::new());
    let jwk = key.public_jwk().to_value();

    let result = PublicJwkShape {
        kty: jwk["kty"].as_str().unwrap_or("").to_string(),
        crv: jwk["crv"].as_str().unwrap_or("").to_string(),
        alg: jwk["alg"].as_str().unwrap_or("").to_string(),
        use_: jwk["use"].as_str().unwrap_or("").to_string(),
        kid_len: jwk["kid"].as_str().unwrap_or("").len(),
        x_len: jwk["x"].as_str().unwrap_or("").len(),
        has_d: jwk.get("d").is_some(),
    };

    insta::assert_yaml_snapshot!("public_jwk_shape", result);
}

// =========================================================================
// Private JWK shape
// =========================================================================

#[cfg(feature = "jwk")]
#[test]
fn snapshot_private_jwk_shape() {
    let fx = fx();
    let key = fx.ed25519("snap-priv-jwk", Ed25519Spec::new());
    let jwk = key.private_key_jwk().to_value();

    let result = PrivateJwkShape {
        kty: jwk["kty"].as_str().unwrap_or("").to_string(),
        crv: jwk["crv"].as_str().unwrap_or("").to_string(),
        alg: jwk["alg"].as_str().unwrap_or("").to_string(),
        use_: jwk["use"].as_str().unwrap_or("").to_string(),
        kid_len: jwk["kid"].as_str().unwrap_or("").len(),
        x_len: jwk["x"].as_str().unwrap_or("").len(),
        d_len: jwk["d"].as_str().unwrap_or("").len(),
    };

    insta::assert_yaml_snapshot!("private_jwk_shape", result);
}

// =========================================================================
// JWKS shape
// =========================================================================

#[cfg(feature = "jwk")]
#[test]
fn snapshot_jwks_shape() {
    let fx = fx();
    let key = fx.ed25519("snap-jwks", Ed25519Spec::new());
    let jwks = key.public_jwks().to_value();
    let keys = jwks["keys"].as_array().expect("keys array");

    let result = JwksShape {
        keys_count: keys.len(),
        first_key_kty: keys[0]["kty"].as_str().unwrap_or("").to_string(),
        first_key_crv: keys[0]["crv"].as_str().unwrap_or("").to_string(),
    };

    insta::assert_yaml_snapshot!("jwks_shape", result);
}

// =========================================================================
// Label divergence
// =========================================================================

#[test]
fn snapshot_label_divergence() {
    let fx = fx();
    let a = fx.ed25519("label-a", Ed25519Spec::new());
    let b = fx.ed25519("label-b", Ed25519Spec::new());

    let result = LabelDivergence {
        private_pem_differs: a.private_key_pkcs8_pem() != b.private_key_pkcs8_pem(),
        public_pem_differs: a.public_key_spki_pem() != b.public_key_spki_pem(),
        private_der_differs: a.private_key_pkcs8_der() != b.private_key_pkcs8_der(),
        public_der_differs: a.public_key_spki_der() != b.public_key_spki_der(),
    };

    insta::assert_yaml_snapshot!("label_divergence", result);
}

// =========================================================================
// Mismatch shape
// =========================================================================

#[test]
fn snapshot_mismatch_shape() {
    let fx = fx();
    let key = fx.ed25519("snap-mismatch", Ed25519Spec::new());
    let good = key.public_key_spki_der();
    let mismatched = key.mismatched_public_key_spki_der();

    let result = MismatchShape {
        good_public_der_len: good.len(),
        mismatched_public_der_len: mismatched.len(),
        keys_differ: good != mismatched.as_slice(),
    };

    insta::assert_yaml_snapshot!("mismatch_shape", result);
}

// =========================================================================
// Corrupt PEM variants
// =========================================================================

#[test]
fn snapshot_corrupt_pem_variants() {
    let fx = fx();
    let key = fx.ed25519("snap-corrupt", Ed25519Spec::new());
    let original = key.private_key_pkcs8_pem();

    let variants: Vec<(&str, CorruptPem)> = vec![
        ("BadHeader", CorruptPem::BadHeader),
        ("BadFooter", CorruptPem::BadFooter),
        ("BadBase64", CorruptPem::BadBase64),
        ("ExtraBlankLine", CorruptPem::ExtraBlankLine),
    ];

    let entries: Vec<CorruptPemShape> = variants
        .into_iter()
        .map(|(name, how)| {
            let corrupt = key.private_key_pkcs8_pem_corrupt(how);
            CorruptPemShape {
                variant: name,
                has_begin_line: corrupt.contains("-----BEGIN"),
                has_end_line: corrupt.contains("-----END"),
                differs_from_original: corrupt != original,
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("corrupt_pem_variants", entries);
}

// =========================================================================
// Truncated DER
// =========================================================================

#[test]
fn snapshot_truncated_der() {
    let fx = fx();
    let key = fx.ed25519("snap-truncated", Ed25519Spec::new());
    let original_len = key.private_key_pkcs8_der().len();

    let lengths: Vec<usize> = vec![0, 1, 10, 16];

    let entries: Vec<TruncatedDerShape> = lengths
        .into_iter()
        .map(|len| {
            let truncated = key.private_key_pkcs8_der_truncated(len);
            TruncatedDerShape {
                requested_len: len,
                actual_len: truncated.len(),
                shorter_than_original: truncated.len() < original_len,
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("truncated_der", entries);
}

// =========================================================================
// Deterministic corruption
// =========================================================================

#[test]
fn snapshot_deterministic_corruption() {
    let fx = fx();
    let key = fx.ed25519("snap-det-corrupt", Ed25519Spec::new());
    let good_pem = key.private_key_pkcs8_pem();
    let good_der = key.private_key_pkcs8_der();

    let pem_a = key.private_key_pkcs8_pem_corrupt_deterministic("corrupt:v1");
    let pem_b = key.private_key_pkcs8_pem_corrupt_deterministic("corrupt:v1");
    let der_a = key.private_key_pkcs8_der_corrupt_deterministic("corrupt:v1");
    let der_b = key.private_key_pkcs8_der_corrupt_deterministic("corrupt:v1");

    let result = DeterministicCorruptionShape {
        pem_differs_from_good: pem_a != good_pem,
        pem_starts_with_dash: pem_a.starts_with('-'),
        pem_stable: pem_a == pem_b,
        der_differs_from_good: der_a != good_der,
        der_same_len_as_good: der_a.len() == good_der.len(),
        der_stable: der_a == der_b,
    };

    insta::assert_yaml_snapshot!("deterministic_corruption", result);
}

// =========================================================================
// Debug safety
// =========================================================================

#[test]
fn snapshot_debug_safety() {
    let fx = fx();
    let key = fx.ed25519("debug-snap", Ed25519Spec::new());
    let dbg = format!("{key:?}");
    let pem = key.private_key_pkcs8_pem();
    // Extract the base64 body (second line of PEM) to check it doesn't leak
    let pem_body = pem
        .lines()
        .find(|l| !l.starts_with("-----"))
        .unwrap_or("");

    let result = DebugSafety {
        contains_struct_name: dbg.contains("Ed25519KeyPair"),
        contains_label: dbg.contains("debug-snap"),
        contains_private_pem_material: dbg.contains(pem_body),
        uses_non_exhaustive: dbg.contains(".."),
    };

    insta::assert_yaml_snapshot!("debug_safety", result);
}

// =========================================================================
// Tempfile shape
// =========================================================================

#[test]
fn snapshot_tempfile_shape() {
    let fx = fx();
    let key = fx.ed25519("snap-tempfile", Ed25519Spec::new());

    let priv_tf = key.write_private_key_pkcs8_pem().expect("private tempfile");
    let pub_tf = key.write_public_key_spki_pem().expect("public tempfile");

    let priv_contents = std::fs::read_to_string(priv_tf.path()).expect("read private");
    let pub_contents = std::fs::read_to_string(pub_tf.path()).expect("read public");

    let result = TempfileShape {
        private_tempfile_matches_pem: priv_contents == key.private_key_pkcs8_pem(),
        public_tempfile_matches_pem: pub_contents == key.public_key_spki_pem(),
    };

    insta::assert_yaml_snapshot!("tempfile_shape", result);
}
