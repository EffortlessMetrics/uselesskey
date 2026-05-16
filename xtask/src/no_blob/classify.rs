use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};

pub(crate) fn classify_by_content(
    bytes: &[u8],
    allow_secret_markers: bool,
) -> Option<(&'static str, &'static str)> {
    let text = String::from_utf8_lossy(bytes);

    if allow_secret_markers {
        // PEM header detection
        if let Some(pem_start) = text.find("-----BEGIN ") {
            let after = &text[pem_start + 11..];
            if let Some(end) = after.find("-----") {
                let label = after[..end].trim();
                return Some(classify_pem_label(label));
            }
        }

        // SSH public key prefixes (check per-line, not just file start)
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("ssh-rsa ")
                || trimmed.starts_with("ssh-ed25519 ")
                || trimmed.starts_with("ssh-dss ")
                || trimmed.starts_with("ecdsa-sha2-")
            {
                return Some((
                    "SSH public key",
                    "fx.ssh_key(\"key\", SshSpec::ed25519()).authorized_key_line()",
                ));
            }
        }
    }

    if find_jwt_candidate(&text).is_some() {
        return Some((
            "JWT token",
            "fx.token(\"auth\", TokenSpec::oauth_access_token())",
        ));
    }

    None
}

fn find_jwt_candidate(text: &str) -> Option<&str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '=')))
        .find(|candidate| looks_like_jwt(candidate))
}

pub(crate) fn classify_pem_label(label: &str) -> (&'static str, &'static str) {
    match label {
        "RSA PRIVATE KEY" => (
            "RSA private key (PKCS#1)",
            "fx.rsa(\"key\", RsaSpec::rs256()).private_key_pkcs1_pem()",
        ),
        "PRIVATE KEY" => (
            "Private key (PKCS#8)",
            "fx.rsa(\"key\", RsaSpec::rs256()).private_key_pem()  -- or ecdsa/ed25519 variant",
        ),
        "EC PRIVATE KEY" => (
            "EC private key (SEC1)",
            "fx.ecdsa(\"key\", EcdsaSpec::es256()).private_key_sec1_pem()",
        ),
        "PUBLIC KEY" => (
            "Public key (SPKI)",
            "fx.rsa(\"key\", RsaSpec::rs256()).public_key_pem()  -- or ecdsa/ed25519 variant",
        ),
        "RSA PUBLIC KEY" => (
            "RSA public key (PKCS#1)",
            "fx.rsa(\"key\", RsaSpec::rs256()).public_key_pkcs1_pem()",
        ),
        "CERTIFICATE" => (
            "X.509 certificate",
            "fx.x509_self_signed(\"ca\", X509Spec::default()).cert_pem()",
        ),
        "CERTIFICATE REQUEST" => (
            "X.509 CSR",
            "fx.x509_self_signed(\"ca\", X509Spec::default()) -- CSR not yet supported; use cert",
        ),
        "ENCRYPTED PRIVATE KEY" => (
            "Encrypted private key (PKCS#8)",
            "fx.rsa(\"key\", RsaSpec::rs256()).private_key_pem()  -- uselesskey generates unencrypted keys",
        ),
        "OPENSSH PRIVATE KEY" => (
            "OpenSSH private key",
            "fx.ssh_key(\"key\", SshSpec::ed25519()).private_key_openssh()",
        ),
        "PGP PUBLIC KEY BLOCK" | "PGP PRIVATE KEY BLOCK" => {
            ("PGP key block", "fx.pgp(\"key\", PgpSpec::rsa()).armored()")
        }
        "PGP MESSAGE" => (
            "PGP message",
            "fx.pgp(\"key\", PgpSpec::rsa()) -- generate key, then encrypt test data",
        ),
        "PGP SIGNATURE" => (
            "PGP signature",
            "fx.pgp(\"key\", PgpSpec::rsa()) -- generate key, then sign test data",
        ),
        _ => (
            "Unknown PEM type",
            "Delete the file and use the appropriate uselesskey fixture API",
        ),
    }
}

pub(crate) fn looks_like_jwt(s: &str) -> bool {
    let mut parts = s.split('.');
    let (Some(header), Some(payload), Some(signature)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }

    if !is_jwt_signature_segment(signature) {
        return false;
    }

    let header = decode_jwt_json_segment(header);
    let payload = decode_jwt_json_segment(payload);
    let (Some(header), Some(payload)) = (header, payload) else {
        return false;
    };

    header.is_object()
        && payload.is_object()
        && header
            .as_object()
            .is_some_and(|header| header.contains_key("alg") || header.contains_key("enc"))
}

fn decode_jwt_json_segment(segment: &str) -> Option<serde_json::Value> {
    let decoded = decode_jwt_segment(segment)?;
    serde_json::from_slice(&decoded).ok()
}

fn decode_jwt_segment(segment: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .or_else(|_| URL_SAFE.decode(segment))
        .ok()
}

fn is_jwt_signature_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() >= 8
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '='))
}

pub(super) fn classify_by_extension(path: &Path) -> (&'static str, &'static str) {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "pem" => (
            "PEM file (unknown type)",
            "Read the PEM header to determine key type, then use the matching uselesskey API",
        ),
        "der" => (
            "DER-encoded file",
            "fx.rsa(\"key\", RsaSpec::rs256()).private_key_der()  -- or .public_key_der(), .cert_der()",
        ),
        "key" => (
            "Key file",
            "fx.rsa(\"key\", RsaSpec::rs256()).private_key_pem()  -- or ecdsa/ed25519 variant",
        ),
        "crt" | "cer" => (
            "Certificate file",
            "fx.x509_self_signed(\"ca\", X509Spec::default()).cert_pem()",
        ),
        "p12" | "pfx" => (
            "PKCS#12 bundle",
            "fx.x509_self_signed(\"ca\", X509Spec::default()) for cert/key material, then build PKCS#12 at runtime",
        ),
        "pub" => (
            "Public key file",
            "fx.rsa(\"key\", RsaSpec::rs256()).public_key_pem()  -- or ecdsa/ed25519 variant",
        ),
        _ => (
            "Secret-shaped file",
            "Delete the file and use the appropriate uselesskey fixture API",
        ),
    }
}
