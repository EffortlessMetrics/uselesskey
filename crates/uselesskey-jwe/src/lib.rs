#![forbid(unsafe_code)]

//! JWE fixture generation for `uselesskey`.

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce as AesNonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;
use uselesskey_core::Factory;
use uselesskey_core_symmetric_spec::{AadMode, AeadVectorSpec, NoncePolicy, PlaintextMode, SymmetricSpec};
use uselesskey_symmetric::SymmetricFactoryExt;

/// Cache domain for JWE fixtures.
pub const DOMAIN_JWE_FIXTURE: &str = "uselesskey:jwe:fixture";

/// JWE key management algorithm (v1 supports `dir` only).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum JweAlg {
    /// Direct encryption using a shared symmetric key.
    Dir,
}

impl JweAlg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Dir => "dir",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::Dir => 1,
        }
    }
}

/// JWE content-encryption algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum JweEnc {
    /// AES-128-GCM
    A128Gcm,
    /// AES-256-GCM
    A256Gcm,
    /// ChaCha20-Poly1305 (`C20P`)
    C20P,
}

impl JweEnc {
    fn as_str(self) -> &'static str {
        match self {
            Self::A128Gcm => "A128GCM",
            Self::A256Gcm => "A256GCM",
            Self::C20P => "C20P",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::A128Gcm => 1,
            Self::A256Gcm => 2,
            Self::C20P => 3,
        }
    }

    fn symmetric_spec(self) -> SymmetricSpec {
        match self {
            Self::A128Gcm => SymmetricSpec::aes128_gcm(),
            Self::A256Gcm => SymmetricSpec::aes256_gcm(),
            Self::C20P => SymmetricSpec::chacha20_poly1305(),
        }
    }
}

/// JWE payload source mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum JwePayloadSource {
    /// Fixed payload bytes.
    FixedBytes,
    /// Stable JSON payload.
    JsonBody,
    /// Deterministic random-shape bytes.
    RandomShape,
}

impl JwePayloadSource {
    fn plaintext_mode(self) -> PlaintextMode {
        match self {
            Self::FixedBytes => PlaintextMode::FixedBytes,
            Self::JsonBody => PlaintextMode::JsonBody,
            Self::RandomShape => PlaintextMode::RandomShape,
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::FixedBytes => 1,
            Self::JsonBody => 2,
            Self::RandomShape => 3,
        }
    }
}

/// Serialization mode for JWE fixture output.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum JweSerialization {
    /// Compact serialization.
    Compact,
    /// General JSON serialization.
    Json,
}

impl JweSerialization {
    fn tag(self) -> u8 {
        match self {
            Self::Compact => 1,
            Self::Json => 2,
        }
    }
}

/// Specification for deterministic JWE fixture generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JweSpec {
    /// Key management algorithm.
    pub alg: JweAlg,
    /// Content encryption algorithm.
    pub enc: JweEnc,
    /// Additional protected header fields.
    pub protected_header: BTreeMap<String, String>,
    /// Payload shaping mode.
    pub payload_source: JwePayloadSource,
    /// Nonce derivation policy for content encryption.
    pub nonce_policy: NoncePolicy,
    /// Output serialization format.
    pub serialization: JweSerialization,
}

impl JweSpec {
    /// Start a direct-encryption JWE spec.
    pub fn dir(enc: JweEnc) -> Self {
        Self {
            alg: JweAlg::Dir,
            enc,
            protected_header: BTreeMap::new(),
            payload_source: JwePayloadSource::JsonBody,
            nonce_policy: NoncePolicy::Derived,
            serialization: JweSerialization::Compact,
        }
    }

    /// Stable fingerprint bytes used for deterministic derivation.
    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.alg.tag(), self.enc.tag(), self.payload_source.tag(), self.serialization.tag()];
        match &self.nonce_policy {
            NoncePolicy::Derived => out.push(0),
            NoncePolicy::Explicit(bytes) => { out.push(1); out.push(bytes.len() as u8); out.extend_from_slice(bytes); }
        }
        for (k, v) in &self.protected_header {
            out.push(k.len() as u8);
            out.extend_from_slice(k.as_bytes());
            out.push(v.len() as u8);
            out.extend_from_slice(v.as_bytes());
        }
        out
    }
}

/// Fixture representation for generated JWE.
#[derive(Clone, Debug)]
pub struct JweFixture {
    /// Requested spec.
    pub spec: JweSpec,
    /// Compact serialization, when requested.
    pub compact: Option<String>,
    /// JSON serialization object, when requested.
    pub json: Option<Value>,
    /// Protected header JSON object.
    pub protected_header: Value,
    /// CEK algorithm for metadata.
    pub cek_algorithm: &'static str,
    /// CEK key identifier metadata.
    pub cek_kid: Option<String>,
}

/// JWE generation/decryption errors.
#[derive(Debug, Error, Clone)]
pub enum JweError {
    /// Unsupported key management algorithm.
    #[error("unsupported JWE alg: {0}")]
    UnsupportedAlg(&'static str),
    /// Parsing failed.
    #[error("failed to parse compact JWE")]
    ParseCompact,
    /// Base64url decoding failed.
    #[error("failed base64url decode for {0}")]
    Decode(&'static str),
    /// Decryption failed.
    #[error("JWE decryption failed")]
    Decrypt,
    /// JSON serialization failed.
    #[error("JSON serialization failed")]
    Json,
    /// Symmetric fixture operation failed.
    #[error("symmetric fixture error: {0}")]
    Symmetric(String),
}

/// Extension trait adding JWE fixture generation on [`Factory`].
pub trait JweFactoryExt {
    /// Create a deterministic JWE fixture.
    fn jwe(&self, label: impl AsRef<str>, spec: JweSpec) -> Result<JweFixture, JweError>;
}

impl JweFactoryExt for Factory {
    fn jwe(&self, label: impl AsRef<str>, spec: JweSpec) -> Result<JweFixture, JweError> {
        let spec_bytes = spec.stable_bytes();
        let out = self.get_or_init(DOMAIN_JWE_FIXTURE, label.as_ref(), &spec_bytes, "good", |_| {
            build_jwe(self, label.as_ref(), &spec)
        });
        out.as_ref().clone()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonJwe {
    protected: String,
    encrypted_key: String,
    iv: String,
    ciphertext: String,
    tag: String,
}

impl JweFixture {
    /// Decrypt compact or JSON JWE fixture with the fixture CEK.
    pub fn decrypt_with_cek(&self, cek: &[u8]) -> Result<Vec<u8>, JweError> {
        let (protected_b64, iv_b64, ciphertext_b64, tag_b64) = if let Some(compact) = &self.compact {
            let parts: Vec<&str> = compact.split('.').collect();
            if parts.len() != 5 {
                return Err(JweError::ParseCompact);
            }
            if !parts[1].is_empty() {
                return Err(JweError::UnsupportedAlg("encrypted_key must be empty for dir"));
            }
            (parts[0].to_string(), parts[2].to_string(), parts[3].to_string(), parts[4].to_string())
        } else {
            let json = self.json.as_ref().ok_or(JweError::ParseCompact)?;
            (
                json.get("protected").and_then(Value::as_str).ok_or(JweError::ParseCompact)?.to_string(),
                json.get("iv").and_then(Value::as_str).ok_or(JweError::ParseCompact)?.to_string(),
                json.get("ciphertext").and_then(Value::as_str).ok_or(JweError::ParseCompact)?.to_string(),
                json.get("tag").and_then(Value::as_str).ok_or(JweError::ParseCompact)?.to_string(),
            )
        };

        let aad = protected_b64.as_bytes();
        let iv = URL_SAFE_NO_PAD.decode(iv_b64).map_err(|_| JweError::Decode("iv"))?;
        let ciphertext = URL_SAFE_NO_PAD.decode(ciphertext_b64).map_err(|_| JweError::Decode("ciphertext"))?;
        let tag = URL_SAFE_NO_PAD.decode(tag_b64).map_err(|_| JweError::Decode("tag"))?;

        let mut joined = ciphertext;
        joined.extend_from_slice(&tag);

        decrypt(self.spec.enc, cek, &iv, aad, &joined)
    }
}

fn build_jwe(factory: &Factory, label: &str, spec: &JweSpec) -> Result<JweFixture, JweError> {
    if !matches!(spec.alg, JweAlg::Dir) {
        return Err(JweError::UnsupportedAlg("only dir is supported in v1"));
    }

    let symmetric = factory.symmetric(label, spec.enc.symmetric_spec());
    let vector_spec = AeadVectorSpec::new(
        spec.enc.symmetric_spec(),
        spec.payload_source.plaintext_mode(),
        AadMode::None,
        spec.nonce_policy.clone(),
    );
    let vector = factory
        .aead_vector(label, vector_spec)
        .map_err(|e| JweError::Symmetric(e.to_string()))?;

    let mut header_map = Map::new();
    header_map.insert("alg".into(), Value::String(spec.alg.as_str().to_string()));
    header_map.insert("enc".into(), Value::String(spec.enc.as_str().to_string()));
    for (k, v) in &spec.protected_header {
        header_map.insert(k.clone(), Value::String(v.clone()));
    }
    let protected_header = Value::Object(header_map.clone());
    let protected_json = serde_json::to_vec(&protected_header).map_err(|_| JweError::Json)?;
    let protected_b64 = URL_SAFE_NO_PAD.encode(protected_json);

    let (ciphertext_bytes, tag_bytes) = encrypt(spec.enc, symmetric.key_bytes(), &vector.nonce, protected_b64.as_bytes(), &vector.plaintext)?;
    let iv = URL_SAFE_NO_PAD.encode(&vector.nonce);
    let ciphertext = URL_SAFE_NO_PAD.encode(ciphertext_bytes);
    let tag = URL_SAFE_NO_PAD.encode(tag_bytes);

    let compact = format!("{protected_b64}..{iv}.{ciphertext}.{tag}");

    let json = serde_json::to_value(JsonJwe {
        protected: protected_b64.clone(),
        encrypted_key: String::new(),
        iv,
        ciphertext,
        tag,
    })
    .map_err(|_| JweError::Json)?;

    Ok(JweFixture {
        spec: spec.clone(),
        compact: (spec.serialization == JweSerialization::Compact).then_some(compact),
        json: (spec.serialization == JweSerialization::Json).then_some(json),
        protected_header,
        cek_algorithm: spec.enc.as_str(),
        cek_kid: symmetric.kid().map(ToOwned::to_owned),
    })
}


fn encrypt(enc: JweEnc, cek: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), JweError> {
    let mut buffer = plaintext.to_vec();
    let tag = match enc {
        JweEnc::A128Gcm => {
            use aes_gcm::aead::AeadInPlace;
            let cipher = Aes128Gcm::new_from_slice(cek).map_err(|_| JweError::Decrypt)?;
            cipher.encrypt_in_place_detached(AesNonce::from_slice(iv), aad, &mut buffer).map_err(|_| JweError::Decrypt)?.to_vec()
        }
        JweEnc::A256Gcm => {
            use aes_gcm::aead::AeadInPlace;
            let cipher = Aes256Gcm::new_from_slice(cek).map_err(|_| JweError::Decrypt)?;
            cipher.encrypt_in_place_detached(AesNonce::from_slice(iv), aad, &mut buffer).map_err(|_| JweError::Decrypt)?.to_vec()
        }
        JweEnc::C20P => {
            use chacha20poly1305::aead::AeadInPlace;
            let cipher = ChaCha20Poly1305::new_from_slice(cek).map_err(|_| JweError::Decrypt)?;
            cipher.encrypt_in_place_detached(ChaNonce::from_slice(iv), aad, &mut buffer).map_err(|_| JweError::Decrypt)?.to_vec()
        }
    };
    Ok((buffer, tag))
}

fn decrypt(enc: JweEnc, cek: &[u8], iv: &[u8], aad: &[u8], ciphertext_and_tag: &[u8]) -> Result<Vec<u8>, JweError> {
    match enc {
        JweEnc::A128Gcm => {
            let cipher = Aes128Gcm::new_from_slice(cek).map_err(|_| JweError::Decrypt)?;
            cipher.decrypt(AesNonce::from_slice(iv), aes_gcm::aead::Payload { msg: ciphertext_and_tag, aad }).map_err(|_| JweError::Decrypt)
        }
        JweEnc::A256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(cek).map_err(|_| JweError::Decrypt)?;
            cipher.decrypt(AesNonce::from_slice(iv), aes_gcm::aead::Payload { msg: ciphertext_and_tag, aad }).map_err(|_| JweError::Decrypt)
        }
        JweEnc::C20P => {
            let cipher = ChaCha20Poly1305::new_from_slice(cek).map_err(|_| JweError::Decrypt)?;
            cipher.decrypt(ChaNonce::from_slice(iv), chacha20poly1305::aead::Payload { msg: ciphertext_and_tag, aad }).map_err(|_| JweError::Decrypt)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uselesskey_core::{Factory, Seed};

    #[test]
    fn compact_jwe_parse_and_decrypt_roundtrip() {
        let fx = Factory::deterministic(Seed::from_env_value("jwe-compact").expect("seed"));
        let mut spec = JweSpec::dir(JweEnc::A256Gcm);
        spec.protected_header.insert("typ".into(), "JWT".into());
        spec.payload_source = JwePayloadSource::JsonBody;
        spec.serialization = JweSerialization::Compact;

        let jwe = fx.jwe("svc", spec.clone()).expect("jwe fixture");
        let cek = fx.symmetric("svc", spec.enc.symmetric_spec());
        let plaintext = jwe.decrypt_with_cek(cek.key_bytes()).expect("decrypt jwe");

        assert!(!plaintext.is_empty());
        assert!(jwe.compact.is_some());
        assert!(jwe.json.is_none());
    }

    #[test]
    fn json_jwe_is_deterministic() {
        let fx = Factory::deterministic(Seed::from_env_value("jwe-json").expect("seed"));
        let mut spec = JweSpec::dir(JweEnc::C20P);
        spec.serialization = JweSerialization::Json;
        spec.payload_source = JwePayloadSource::FixedBytes;
        spec.protected_header.insert("cty".into(), "application/json".into());

        let first = fx.jwe("svc-json", spec.clone()).expect("first");
        fx.clear_cache();
        let second = fx.jwe("svc-json", spec).expect("second");

        assert_eq!(first.json, second.json);
        assert!(first.compact.is_none());
        assert!(first.json.is_some());
    }
}
