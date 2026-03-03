//! Insta snapshot tests for the `uselesskey` facade crate.
//!
//! These tests exercise the public re-exported API and snapshot metadata
//! (lengths, PEM headers, algorithm names, JWK field shapes) — never
//! actual key material bytes.

mod testutil;

use serde::Serialize;
use testutil::fx;
use uselesskey::negative::CorruptPem;

// ---------------------------------------------------------------------------
// Shared snapshot helpers
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct PemShape {
    first_line: String,
    last_line: String,
    line_count: usize,
}

fn pem_shape(pem: &str) -> PemShape {
    let lines: Vec<&str> = pem.lines().collect();
    PemShape {
        first_line: lines.first().unwrap_or(&"").to_string(),
        last_line: lines.last().unwrap_or(&"").to_string(),
        line_count: lines.len(),
    }
}

#[derive(Serialize)]
struct KeyPairSnapshot {
    label: String,
    algorithm: String,
    private_pem: PemShape,
    public_pem: PemShape,
    private_der_len: usize,
    public_der_len: usize,
}

// ---------------------------------------------------------------------------
// RSA
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "rsa")]
fn snapshot_facade_rsa_2048_metadata() {
    use uselesskey::{RsaFactoryExt, RsaSpec};

    let fx = fx();
    let kp = fx.rsa("facade-rsa-2048", RsaSpec::rs256());

    let result = KeyPairSnapshot {
        label: "facade-rsa-2048".into(),
        algorithm: "RS256".into(),
        private_pem: pem_shape(kp.private_key_pkcs8_pem()),
        public_pem: pem_shape(kp.public_key_spki_pem()),
        private_der_len: kp.private_key_pkcs8_der().len(),
        public_der_len: kp.public_key_spki_der().len(),
    };

    insta::assert_yaml_snapshot!("facade_rsa_2048_metadata", result);
}

#[test]
#[cfg(feature = "rsa")]
fn snapshot_facade_rsa_4096_metadata() {
    use uselesskey::{RsaFactoryExt, RsaSpec};

    let fx = fx();
    let kp = fx.rsa("facade-rsa-4096", RsaSpec::new(4096));

    let result = KeyPairSnapshot {
        label: "facade-rsa-4096".into(),
        algorithm: "RS256-4096".into(),
        private_pem: pem_shape(kp.private_key_pkcs8_pem()),
        public_pem: pem_shape(kp.public_key_spki_pem()),
        private_der_len: kp.private_key_pkcs8_der().len(),
        public_der_len: kp.public_key_spki_der().len(),
    };

    insta::assert_yaml_snapshot!("facade_rsa_4096_metadata", result);
}

// ---------------------------------------------------------------------------
// ECDSA
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "ecdsa")]
fn snapshot_facade_ecdsa_p256_metadata() {
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec};

    let fx = fx();
    let kp = fx.ecdsa("facade-ecdsa-p256", EcdsaSpec::es256());

    let result = KeyPairSnapshot {
        label: "facade-ecdsa-p256".into(),
        algorithm: "ES256".into(),
        private_pem: pem_shape(kp.private_key_pkcs8_pem()),
        public_pem: pem_shape(kp.public_key_spki_pem()),
        private_der_len: kp.private_key_pkcs8_der().len(),
        public_der_len: kp.public_key_spki_der().len(),
    };

    insta::assert_yaml_snapshot!("facade_ecdsa_p256_metadata", result);
}

#[test]
#[cfg(feature = "ecdsa")]
fn snapshot_facade_ecdsa_p384_metadata() {
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec};

    let fx = fx();
    let kp = fx.ecdsa("facade-ecdsa-p384", EcdsaSpec::es384());

    let result = KeyPairSnapshot {
        label: "facade-ecdsa-p384".into(),
        algorithm: "ES384".into(),
        private_pem: pem_shape(kp.private_key_pkcs8_pem()),
        public_pem: pem_shape(kp.public_key_spki_pem()),
        private_der_len: kp.private_key_pkcs8_der().len(),
        public_der_len: kp.public_key_spki_der().len(),
    };

    insta::assert_yaml_snapshot!("facade_ecdsa_p384_metadata", result);
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "ed25519")]
fn snapshot_facade_ed25519_metadata() {
    use uselesskey::{Ed25519FactoryExt, Ed25519Spec};

    let fx = fx();
    let kp = fx.ed25519("facade-ed25519", Ed25519Spec::new());

    let result = KeyPairSnapshot {
        label: "facade-ed25519".into(),
        algorithm: "EdDSA".into(),
        private_pem: pem_shape(kp.private_key_pkcs8_pem()),
        public_pem: pem_shape(kp.public_key_spki_pem()),
        private_der_len: kp.private_key_pkcs8_der().len(),
        public_der_len: kp.public_key_spki_der().len(),
    };

    insta::assert_yaml_snapshot!("facade_ed25519_metadata", result);
}

// ---------------------------------------------------------------------------
// HMAC
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "hmac")]
fn snapshot_facade_hmac_sizes() {
    use uselesskey::{HmacFactoryExt, HmacSpec};

    #[derive(Serialize)]
    struct HmacSizeSnapshot {
        algorithm: &'static str,
        expected_bytes: usize,
        actual_bytes: usize,
    }

    let fx = fx();
    let sizes: Vec<HmacSizeSnapshot> = vec![
        {
            let k = fx.hmac("facade-hs256", HmacSpec::hs256());
            HmacSizeSnapshot {
                algorithm: "HS256",
                expected_bytes: 32,
                actual_bytes: k.secret_bytes().len(),
            }
        },
        {
            let k = fx.hmac("facade-hs384", HmacSpec::hs384());
            HmacSizeSnapshot {
                algorithm: "HS384",
                expected_bytes: 48,
                actual_bytes: k.secret_bytes().len(),
            }
        },
        {
            let k = fx.hmac("facade-hs512", HmacSpec::hs512());
            HmacSizeSnapshot {
                algorithm: "HS512",
                expected_bytes: 64,
                actual_bytes: k.secret_bytes().len(),
            }
        },
    ];

    insta::assert_yaml_snapshot!("facade_hmac_sizes", sizes);
}

// ---------------------------------------------------------------------------
// Token
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "token")]
fn snapshot_facade_token_api_key() {
    use uselesskey::{TokenFactoryExt, TokenSpec};

    #[derive(Serialize)]
    struct TokenSnapshot {
        kind: &'static str,
        value_len: usize,
        prefix: String,
        auth_header_scheme: String,
    }

    let fx = fx();
    let tok = fx.token("facade-api-key", TokenSpec::api_key());

    let result = TokenSnapshot {
        kind: "api_key",
        value_len: tok.value().len(),
        prefix: tok.value().chars().take(8).collect(),
        auth_header_scheme: tok
            .authorization_header()
            .split(' ')
            .next()
            .unwrap_or("")
            .to_string(),
    };

    insta::assert_yaml_snapshot!("facade_token_api_key", result);
}

#[test]
#[cfg(feature = "token")]
fn snapshot_facade_token_bearer() {
    use uselesskey::{TokenFactoryExt, TokenSpec};

    #[derive(Serialize)]
    struct TokenSnapshot {
        kind: &'static str,
        value_len: usize,
        auth_header_scheme: String,
    }

    let fx = fx();
    let tok = fx.token("facade-bearer", TokenSpec::bearer());

    let result = TokenSnapshot {
        kind: "bearer",
        value_len: tok.value().len(),
        auth_header_scheme: tok
            .authorization_header()
            .split(' ')
            .next()
            .unwrap_or("")
            .to_string(),
    };

    insta::assert_yaml_snapshot!("facade_token_bearer", result);
}

#[test]
#[cfg(feature = "token")]
fn snapshot_facade_token_oauth() {
    use uselesskey::{TokenFactoryExt, TokenSpec};

    #[derive(Serialize)]
    struct OAuthSnapshot {
        kind: &'static str,
        value_len: usize,
        has_three_segments: bool,
        auth_header_scheme: String,
    }

    let fx = fx();
    let tok = fx.token("facade-oauth", TokenSpec::oauth_access_token());
    let segments: Vec<&str> = tok.value().split('.').collect();

    let result = OAuthSnapshot {
        kind: "oauth_access_token",
        value_len: tok.value().len(),
        has_three_segments: segments.len() == 3,
        auth_header_scheme: tok
            .authorization_header()
            .split(' ')
            .next()
            .unwrap_or("")
            .to_string(),
    };

    insta::assert_yaml_snapshot!("facade_token_oauth", result);
}

// ---------------------------------------------------------------------------
// JWK structure
// ---------------------------------------------------------------------------

#[test]
#[cfg(all(feature = "jwk", feature = "rsa"))]
fn snapshot_facade_rsa_jwk_shape() {
    use uselesskey::{RsaFactoryExt, RsaSpec};

    #[derive(Serialize)]
    struct JwkShape {
        kty: String,
        alg: String,
        use_field: String,
        has_kid: bool,
        kid_not_empty: bool,
    }

    let fx = fx();
    let kp = fx.rsa("facade-jwk-rsa", RsaSpec::rs256());
    let jwk = kp.public_jwk();
    let val = jwk.to_value();

    let result = JwkShape {
        kty: val["kty"].as_str().unwrap_or("").to_string(),
        alg: val["alg"].as_str().unwrap_or("").to_string(),
        use_field: val["use"].as_str().unwrap_or("").to_string(),
        has_kid: val.get("kid").is_some(),
        kid_not_empty: !val["kid"].as_str().unwrap_or("").is_empty(),
    };

    insta::assert_yaml_snapshot!("facade_rsa_jwk_shape", result);
}

#[test]
#[cfg(all(feature = "jwk", feature = "ecdsa"))]
fn snapshot_facade_ecdsa_jwk_shape() {
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec};

    #[derive(Serialize)]
    struct EcJwkShape {
        kty: String,
        alg: String,
        crv: String,
        use_field: String,
        has_kid: bool,
    }

    let fx = fx();
    let kp = fx.ecdsa("facade-jwk-ecdsa", EcdsaSpec::es256());
    let jwk = kp.public_jwk();
    let val = jwk.to_value();

    let result = EcJwkShape {
        kty: val["kty"].as_str().unwrap_or("").to_string(),
        alg: val["alg"].as_str().unwrap_or("").to_string(),
        crv: val["crv"].as_str().unwrap_or("").to_string(),
        use_field: val["use"].as_str().unwrap_or("").to_string(),
        has_kid: val.get("kid").is_some(),
    };

    insta::assert_yaml_snapshot!("facade_ecdsa_jwk_shape", result);
}

#[test]
#[cfg(all(feature = "jwk", feature = "ed25519"))]
fn snapshot_facade_ed25519_jwk_shape() {
    use uselesskey::{Ed25519FactoryExt, Ed25519Spec};

    #[derive(Serialize)]
    struct OkpJwkShape {
        kty: String,
        alg: String,
        crv: String,
        use_field: String,
        has_kid: bool,
    }

    let fx = fx();
    let kp = fx.ed25519("facade-jwk-ed25519", Ed25519Spec::new());
    let jwk = kp.public_jwk();
    let val = jwk.to_value();

    let result = OkpJwkShape {
        kty: val["kty"].as_str().unwrap_or("").to_string(),
        alg: val["alg"].as_str().unwrap_or("").to_string(),
        crv: val["crv"].as_str().unwrap_or("").to_string(),
        use_field: val["use"].as_str().unwrap_or("").to_string(),
        has_kid: val.get("kid").is_some(),
    };

    insta::assert_yaml_snapshot!("facade_ed25519_jwk_shape", result);
}

// ---------------------------------------------------------------------------
// JWKS builder
// ---------------------------------------------------------------------------

#[test]
#[cfg(all(feature = "jwk", feature = "rsa", feature = "ecdsa"))]
fn snapshot_facade_jwks_builder() {
    use uselesskey::jwk::JwksBuilder;
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec, RsaFactoryExt, RsaSpec};

    #[derive(Serialize)]
    struct JwksSnapshot {
        key_count: usize,
        kids_sorted: bool,
        key_types: Vec<String>,
    }

    let fx = fx();
    let rsa_kp = fx.rsa("facade-jwks-rsa", RsaSpec::rs256());
    let ec_kp = fx.ecdsa("facade-jwks-ec", EcdsaSpec::es256());

    let jwks = JwksBuilder::new()
        .add_public(rsa_kp.public_jwk())
        .add_public(ec_kp.public_jwk())
        .build();

    let val = jwks.to_value();
    let keys = val["keys"].as_array().expect("keys is array");

    let kids: Vec<&str> = keys.iter().filter_map(|k| k["kid"].as_str()).collect();
    let mut sorted_kids = kids.clone();
    sorted_kids.sort();

    let key_types: Vec<String> = keys
        .iter()
        .filter_map(|k| k["kty"].as_str().map(String::from))
        .collect();

    let result = JwksSnapshot {
        key_count: keys.len(),
        kids_sorted: kids == sorted_kids,
        key_types,
    };

    insta::assert_yaml_snapshot!("facade_jwks_builder", result);
}

// ---------------------------------------------------------------------------
// Negative fixtures — corrupt PEM variants
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "rsa")]
fn snapshot_facade_corrupt_pem_variants() {
    use uselesskey::{RsaFactoryExt, RsaSpec};

    #[derive(Serialize)]
    struct CorruptSnapshot {
        variant: &'static str,
        differs_from_original: bool,
        first_line: String,
    }

    let fx = fx();
    let kp = fx.rsa("facade-corrupt", RsaSpec::rs256());
    let original = kp.private_key_pkcs8_pem();

    let variants = [
        ("BadHeader", CorruptPem::BadHeader),
        ("BadFooter", CorruptPem::BadFooter),
        ("BadBase64", CorruptPem::BadBase64),
        ("ExtraBlankLine", CorruptPem::ExtraBlankLine),
    ];

    let results: Vec<CorruptSnapshot> = variants
        .iter()
        .map(|(name, variant)| {
            let corrupted = kp.private_key_pkcs8_pem_corrupt(variant.clone());
            CorruptSnapshot {
                variant: name,
                differs_from_original: corrupted != original,
                first_line: corrupted.lines().next().unwrap_or("").to_string(),
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("facade_corrupt_pem_variants", results);
}

// ---------------------------------------------------------------------------
// Negative fixtures — truncated DER
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "rsa")]
fn snapshot_facade_truncated_der() {
    use uselesskey::{RsaFactoryExt, RsaSpec};

    #[derive(Serialize)]
    struct TruncatedDerSnapshot {
        original_der_len: usize,
        truncated_len: usize,
        is_shorter: bool,
    }

    let fx = fx();
    let kp = fx.rsa("facade-truncated", RsaSpec::rs256());
    let original_len = kp.private_key_pkcs8_der().len();
    let truncated = kp.private_key_pkcs8_der_truncated(10);

    let result = TruncatedDerSnapshot {
        original_der_len: original_len,
        truncated_len: truncated.len(),
        is_shorter: truncated.len() < original_len,
    };

    insta::assert_yaml_snapshot!("facade_truncated_der", result);
}

// ---------------------------------------------------------------------------
// Negative fixtures — mismatched key
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "rsa")]
fn snapshot_facade_mismatched_key() {
    use uselesskey::{RsaFactoryExt, RsaSpec};

    #[derive(Serialize)]
    struct MismatchSnapshot {
        original_public_der_len: usize,
        mismatched_public_der_len: usize,
        differs: bool,
    }

    let fx = fx();
    let kp = fx.rsa("facade-mismatch", RsaSpec::rs256());
    let original = kp.public_key_spki_der();
    let mismatched = kp.mismatched_public_key_spki_der();

    let result = MismatchSnapshot {
        original_public_der_len: original.len(),
        mismatched_public_der_len: mismatched.len(),
        differs: original != mismatched,
    };

    insta::assert_yaml_snapshot!("facade_mismatched_key", result);
}

// ---------------------------------------------------------------------------
// X.509 certificate metadata
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "x509")]
fn snapshot_facade_x509_cert_shapes() {
    use uselesskey::{X509FactoryExt, X509Spec};

    #[derive(Serialize)]
    struct X509Snapshot {
        cert_pem: PemShape,
        private_key_pem: PemShape,
        cert_der_len: usize,
        private_key_der_len: usize,
    }

    let fx = fx();
    let cert = fx.x509_self_signed("facade-x509", X509Spec::self_signed("facade.example.com"));

    let result = X509Snapshot {
        cert_pem: pem_shape(cert.cert_pem()),
        private_key_pem: pem_shape(cert.private_key_pkcs8_pem()),
        cert_der_len: cert.cert_der().len(),
        private_key_der_len: cert.private_key_pkcs8_der().len(),
    };

    insta::assert_yaml_snapshot!("facade_x509_cert_shapes", result, {
        ".cert_der_len" => "[VOLATILE]",
        ".private_key_der_len" => "[VOLATILE]",
        ".cert_pem.line_count" => "[VOLATILE]",
        ".private_key_pem.line_count" => "[VOLATILE]",
    });
}

#[test]
#[cfg(feature = "x509")]
fn snapshot_facade_x509_parsed_metadata() {
    use uselesskey::{X509FactoryExt, X509Spec};

    let fx = fx();
    let cert = fx.x509_self_signed(
        "facade-x509-parsed",
        X509Spec::self_signed("parsed.example.com"),
    );

    let (_, parsed) =
        x509_parser::parse_x509_certificate(cert.cert_der()).expect("valid DER certificate");

    fn extract_cn(name: &x509_parser::prelude::X509Name<'_>) -> String {
        name.iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or("")
            .to_string()
    }

    #[derive(Serialize)]
    struct ParsedCertSnapshot {
        subject_cn: String,
        issuer_cn: String,
        is_self_signed: bool,
        version: u32,
    }

    let result = ParsedCertSnapshot {
        subject_cn: extract_cn(parsed.subject()),
        issuer_cn: extract_cn(parsed.issuer()),
        is_self_signed: parsed.subject() == parsed.issuer(),
        version: parsed.version().0,
    };

    insta::assert_yaml_snapshot!("facade_x509_parsed_metadata", result);
}

// ---------------------------------------------------------------------------
// X.509 negative fixtures
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "x509")]
fn snapshot_facade_x509_negative_shapes() {
    use uselesskey::{X509FactoryExt, X509Spec};

    #[derive(Serialize)]
    struct X509NegativeSnapshot {
        expired_cert_pem_first_line: String,
        not_yet_valid_cert_pem_first_line: String,
        corrupt_cert_pem_first_line: String,
        truncated_cert_der_len: usize,
    }

    let fx = fx();
    let cert = fx.x509_self_signed("facade-x509-neg", X509Spec::self_signed("neg.example.com"));

    let expired = cert.expired();
    let not_yet = cert.not_yet_valid();
    let corrupt = cert.corrupt_cert_pem(CorruptPem::BadHeader);
    let truncated = cert.truncate_cert_der(10);

    let result = X509NegativeSnapshot {
        expired_cert_pem_first_line: expired.cert_pem().lines().next().unwrap_or("").to_string(),
        not_yet_valid_cert_pem_first_line: not_yet
            .cert_pem()
            .lines()
            .next()
            .unwrap_or("")
            .to_string(),
        corrupt_cert_pem_first_line: corrupt.lines().next().unwrap_or("").to_string(),
        truncated_cert_der_len: truncated.len(),
    };

    insta::assert_yaml_snapshot!("facade_x509_negative_shapes", result);
}
