#![forbid(unsafe_code)]

//! Deterministic WebAuthn ceremony fixtures.
//!
//! This crate provides realistic fixture shapes for registration/assertion
//! testing. It is not a full WebAuthn server implementation.

use ciborium::{ser::into_writer, value::Value};
use serde_json::json;
use sha2::{Digest, Sha256};
use uselesskey_core::Factory;

/// Stable cache domain for WebAuthn fixtures.
pub const DOMAIN_WEBAUTHN_FIXTURE: &str = "uselesskey:webauthn:fixture:v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationMode {
    Packed,
    SelfAttestation,
}

impl AttestationMode {
    fn as_tag(self) -> &'static str {
        match self {
            Self::Packed => "packed",
            Self::SelfAttestation => "self",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebAuthnSpec {
    pub rp_id: String,
    pub challenge: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub authenticator_model: String,
    pub attestation_mode: AttestationMode,
}

impl WebAuthnSpec {
    pub fn packed(rp_id: impl Into<String>, challenge: impl AsRef<[u8]>) -> Self {
        Self {
            rp_id: rp_id.into(),
            challenge: challenge.as_ref().to_vec(),
            credential_id: b"uk-credential-id".to_vec(),
            authenticator_model: "UK-PASSKEY-MOCK".to_string(),
            attestation_mode: AttestationMode::Packed,
        }
    }

    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_field(&mut out, "rp_id", self.rp_id.as_bytes());
        write_field(&mut out, "challenge", &self.challenge);
        write_field(&mut out, "credential_id", &self.credential_id);
        write_field(
            &mut out,
            "authenticator_model",
            self.authenticator_model.as_bytes(),
        );
        write_field(
            &mut out,
            "attestation_mode",
            self.attestation_mode.as_tag().as_bytes(),
        );
        out
    }
}

#[derive(Clone, Debug)]
pub struct RegistrationFixture {
    pub spec: WebAuthnSpec,
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub rp_id_hash: [u8; 32],
    pub sign_count: u32,
    pub aaguid: [u8; 16],
}

#[derive(Clone, Debug)]
pub struct AssertionFixture {
    pub spec: WebAuthnSpec,
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub rp_id_hash: [u8; 32],
    pub sign_count: u32,
}

pub trait WebAuthnFactoryExt {
    fn webauthn_registration(
        &self,
        label: impl AsRef<str>,
        spec: WebAuthnSpec,
    ) -> RegistrationFixture;

    fn webauthn_assertion(&self, label: impl AsRef<str>, spec: WebAuthnSpec) -> AssertionFixture;
}

impl WebAuthnFactoryExt for Factory {
    fn webauthn_registration(
        &self,
        label: impl AsRef<str>,
        spec: WebAuthnSpec,
    ) -> RegistrationFixture {
        let spec_bytes = spec.stable_bytes();
        self.get_or_init(
            DOMAIN_WEBAUTHN_FIXTURE,
            label.as_ref(),
            &spec_bytes,
            "registration",
            move |seed| build_registration(spec, *seed.bytes()),
        )
        .as_ref()
        .clone()
    }

    fn webauthn_assertion(&self, label: impl AsRef<str>, spec: WebAuthnSpec) -> AssertionFixture {
        let spec_bytes = spec.stable_bytes();
        self.get_or_init(
            DOMAIN_WEBAUTHN_FIXTURE,
            label.as_ref(),
            &spec_bytes,
            "assertion",
            move |seed| build_assertion(spec, *seed.bytes()),
        )
        .as_ref()
        .clone()
    }
}

fn build_registration(spec: WebAuthnSpec, seed: [u8; 32]) -> RegistrationFixture {
    let rp_id_hash = sha256_arr(spec.rp_id.as_bytes());
    let sign_count = deterministic_sign_count(&spec);
    let aaguid = deterministic_aaguid(&seed, &spec.authenticator_model);
    let client_data_json = build_client_data_json("webauthn.create", &spec.challenge, &spec.rp_id);

    let credential_public_key = cbor_public_key(&seed);
    let auth_data = build_authenticator_data(
        rp_id_hash,
        sign_count,
        Some((
            &aaguid,
            &spec.credential_id,
            credential_public_key.as_slice(),
        )),
    );

    let att_stmt = Value::Map(vec![
        (Value::Text("alg".to_string()), Value::Integer((-7).into())),
        (
            Value::Text("sig".to_string()),
            Value::Bytes(mock_signature(
                &seed,
                &[auth_data.as_slice(), client_data_json.as_slice()].concat(),
                b"attestation",
            )),
        ),
    ]);

    let root = Value::Map(vec![
        (
            Value::Text("fmt".to_string()),
            Value::Text(
                match spec.attestation_mode {
                    AttestationMode::Packed => "packed",
                    AttestationMode::SelfAttestation => "self",
                }
                .to_string(),
            ),
        ),
        (Value::Text("attStmt".to_string()), att_stmt),
        (
            Value::Text("authData".to_string()),
            Value::Bytes(auth_data.clone()),
        ),
    ]);

    let mut attestation_object = Vec::new();
    into_writer(&root, &mut attestation_object).expect("serialize attestation object");

    RegistrationFixture {
        spec,
        client_data_json,
        authenticator_data: auth_data,
        attestation_object,
        rp_id_hash,
        sign_count,
        aaguid,
    }
}

fn build_assertion(spec: WebAuthnSpec, seed: [u8; 32]) -> AssertionFixture {
    let rp_id_hash = sha256_arr(spec.rp_id.as_bytes());
    let sign_count = deterministic_sign_count(&spec).saturating_add(1);
    let client_data_json = build_client_data_json("webauthn.get", &spec.challenge, &spec.rp_id);
    let auth_data = build_authenticator_data(rp_id_hash, sign_count, None);
    let signature = mock_signature(
        &seed,
        &[auth_data.as_slice(), client_data_json.as_slice()].concat(),
        b"assertion",
    );

    AssertionFixture {
        spec,
        client_data_json,
        authenticator_data: auth_data,
        signature,
        rp_id_hash,
        sign_count,
    }
}

fn build_client_data_json(kind: &str, challenge: &[u8], rp_id: &str) -> Vec<u8> {
    let val = json!({
        "type": kind,
        "challenge": base64url(challenge),
        "origin": format!("https://{rp_id}"),
        "crossOrigin": false
    });
    serde_json::to_vec(&val).expect("serialize clientDataJSON")
}

fn build_authenticator_data(
    rp_id_hash: [u8; 32],
    sign_count: u32,
    attested: Option<(&[u8; 16], &[u8], &[u8])>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&rp_id_hash);
    let mut flags: u8 = 0x01; // user present
    if attested.is_some() {
        flags |= 0x40; // attested credential data included
    }
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());

    if let Some((aaguid, credential_id, credential_public_key)) = attested {
        out.extend_from_slice(aaguid);
        out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        out.extend_from_slice(credential_id);
        out.extend_from_slice(credential_public_key);
    }

    out
}

fn cbor_public_key(seed: &[u8; 32]) -> Vec<u8> {
    // COSE EC2 public key map shape used by many WebAuthn implementations.
    let x = sha256_arr(&[seed.as_slice(), b"x"].concat());
    let y = sha256_arr(&[seed.as_slice(), b"y"].concat());

    let map = Value::Map(
        vec![
            (Value::Integer(1.into()), Value::Integer(2.into())), // kty: EC2
            (Value::Integer(3.into()), Value::Integer((-7).into())), // alg: ES256
            (Value::Integer((-1).into()), Value::Integer(1.into())), // crv: P-256
            (Value::Integer((-2).into()), Value::Bytes(x.to_vec())),
            (Value::Integer((-3).into()), Value::Bytes(y.to_vec())),
        ]
        .into_iter()
        .collect(),
    );
    let mut out = Vec::new();
    into_writer(&map, &mut out).expect("serialize credential public key");
    out
}

fn deterministic_sign_count(spec: &WebAuthnSpec) -> u32 {
    let digest = sha256_arr(&spec.stable_bytes());
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

fn deterministic_aaguid(seed: &[u8; 32], model: &str) -> [u8; 16] {
    let digest = sha256_arr(&[seed.as_slice(), model.as_bytes()].concat());
    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&digest[..16]);
    aaguid
}

fn mock_signature(seed: &[u8; 32], body: &[u8], context: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(seed);
    h.update(context);
    h.update(body);
    h.finalize().to_vec()
}

fn base64url(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut chunks = input.chunks_exact(3);
    for chunk in &mut chunks {
        let n = ((chunk[0] as u32) << 16) + ((chunk[1] as u32) << 8) + chunk[2] as u32;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(n & 0x3f) as usize] as char);
    }

    match chunks.remainder() {
        [byte] => {
            let n = (*byte as u32) << 16;
            out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        }
        [first, second] => {
            let n = ((*first as u32) << 16) + ((*second as u32) << 8);
            out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        }
        [] => {}
        _ => unreachable!("chunks_exact remainder is shorter than the chunk size"),
    }
    out
}

fn sha256_arr(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

fn write_field(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    out.extend_from_slice(name.as_bytes());
    out.push(0x1f);
    if let Ok(short_len) = u16::try_from(value.len()) {
        out.extend_from_slice(&short_len.to_be_bytes());
    } else {
        // Backward-compatible extension:
        // - values <= u16::MAX keep the original encoding
        // - longer values use 0xffff + u32 length, avoiding truncation collisions
        let len32 = u32::try_from(value.len())
            .expect("webauthn stable_bytes field length exceeds u32::MAX");
        out.extend_from_slice(&u16::MAX.to_be_bytes());
        out.extend_from_slice(&len32.to_be_bytes());
    }
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use ciborium::{de::from_reader, value::Value};
    use uselesskey_core::Seed;

    use super::*;

    #[test]
    fn registration_is_deterministic() {
        let fx = Factory::deterministic(Seed::from_env_value("webauthn-det").unwrap());
        let spec = WebAuthnSpec::packed("example.com", b"challenge-a");

        let a = fx.webauthn_registration("alice", spec.clone());
        let b = fx.webauthn_registration("alice", spec);

        assert_eq!(a.attestation_object, b.attestation_object);
        assert_eq!(a.sign_count, b.sign_count);
    }

    #[test]
    fn attestation_object_is_cbor_map() {
        let fx = Factory::random();
        let reg = fx.webauthn_registration(
            "alice",
            WebAuthnSpec::packed("example.com", b"challenge-cbor"),
        );
        let v: Value = from_reader(reg.attestation_object.as_slice()).expect("parse cbor");
        let m = match v {
            Value::Map(entries) => entries,
            _ => panic!("attestation object must be cbor map"),
        };
        assert!(m.iter().any(|(k, _)| *k == Value::Text("fmt".to_string())));
        assert!(
            m.iter()
                .any(|(k, _)| *k == Value::Text("authData".to_string()))
        );
    }

    #[test]
    fn assertion_sign_count_monotonic_per_fixture() {
        let fx = Factory::deterministic(Seed::from_env_value("webauthn-sign-count").unwrap());
        let spec = WebAuthnSpec::packed("example.com", b"challenge-sign");
        let reg = fx.webauthn_registration("alice", spec.clone());
        let assertion = fx.webauthn_assertion("alice", spec);
        assert_eq!(assertion.sign_count, reg.sign_count.saturating_add(1));
    }

    #[test]
    fn client_data_contains_challenge() {
        let fx = Factory::random();
        let challenge = b"abc-123";
        let reg = fx.webauthn_registration("alice", WebAuthnSpec::packed("example.com", challenge));
        let json: serde_json::Value =
            serde_json::from_slice(&reg.client_data_json).expect("parse clientDataJSON");
        assert_eq!(json["challenge"], base64url(challenge));
        assert_eq!(json["origin"], "https://example.com");
    }

    #[test]
    fn attestation_mode_tags_are_stable() {
        assert_eq!(AttestationMode::Packed.as_tag(), "packed");
        assert_eq!(AttestationMode::SelfAttestation.as_tag(), "self");

        let mut spec = WebAuthnSpec::packed("example.com", b"challenge-mode");
        spec.attestation_mode = AttestationMode::SelfAttestation;
        let stable = spec.stable_bytes();

        assert_contains_bytes(&stable, b"attestation_mode");
        assert_contains_bytes(&stable, b"self");
    }

    #[test]
    fn authenticator_data_layout_matches_webauthn_shape() {
        let rp_id_hash = [0x11; 32];
        let sign_count = 0x0102_0304;
        let aaguid = [0x22; 16];
        let credential_id = b"cred";
        let credential_public_key = b"public-key";

        let reg = build_authenticator_data(
            rp_id_hash,
            sign_count,
            Some((&aaguid, credential_id, credential_public_key)),
        );

        assert_eq!(&reg[..32], &rp_id_hash);
        assert_eq!(reg[32], 0x41);
        assert_eq!(&reg[33..37], &sign_count.to_be_bytes());
        assert_eq!(&reg[37..53], &aaguid);
        assert_eq!(u16::from_be_bytes(reg[53..55].try_into().unwrap()), 4);
        assert_eq!(&reg[55..59], credential_id);
        assert_eq!(&reg[59..], credential_public_key);

        let assertion = build_authenticator_data(rp_id_hash, sign_count, None);
        assert_eq!(assertion.len(), 37);
        assert_eq!(&assertion[..32], &rp_id_hash);
        assert_eq!(assertion[32], 0x01);
        assert_eq!(&assertion[33..37], &sign_count.to_be_bytes());
    }

    #[test]
    fn cbor_public_key_has_ec2_es256_shape() {
        let encoded = cbor_public_key(&[4_u8; 32]);
        let v: Value = from_reader(encoded.as_slice()).expect("parse public key cbor");
        let entries = match v {
            Value::Map(entries) => entries,
            _ => panic!("public key must be cbor map"),
        };

        assert_eq!(
            value_by_integer_key(&entries, 1),
            Some(&Value::Integer(2.into()))
        );
        assert_eq!(
            value_by_integer_key(&entries, 3),
            Some(&Value::Integer((-7).into()))
        );
        assert_eq!(
            value_by_integer_key(&entries, -1),
            Some(&Value::Integer(1.into()))
        );
        let x = bytes_by_integer_key(&entries, -2).expect("x coordinate");
        let y = bytes_by_integer_key(&entries, -3).expect("y coordinate");
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);
        assert_ne!(x, y);
    }

    #[test]
    fn deterministic_values_are_sha256_derived() {
        let seed = [3_u8; 32];
        let mut spec = WebAuthnSpec::packed("example.com", b"challenge-derived");
        spec.authenticator_model = "UK-MODEL-A".to_string();

        let digest = Sha256::digest(spec.stable_bytes());
        let expected_count = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        let mut aaguid_input = Vec::new();
        aaguid_input.extend_from_slice(&seed);
        aaguid_input.extend_from_slice(spec.authenticator_model.as_bytes());
        let digest = Sha256::digest(aaguid_input);
        let mut expected_aaguid = [0_u8; 16];
        expected_aaguid.copy_from_slice(&digest[..16]);

        let reg = build_registration(spec.clone(), seed);
        assert_eq!(reg.rp_id_hash, sha256_arr(spec.rp_id.as_bytes()));
        assert_eq!(reg.sign_count, expected_count);
        assert_eq!(reg.aaguid, expected_aaguid);

        let assertion = build_assertion(spec, seed);
        assert_eq!(assertion.sign_count, expected_count.saturating_add(1));
        assert_eq!(assertion.rp_id_hash, reg.rp_id_hash);
    }

    #[test]
    fn mock_signature_hashes_seed_context_and_body() {
        let seed = [5_u8; 32];
        let body = b"auth-data-and-client-data";
        let context = b"assertion";
        let mut h = Sha256::new();
        h.update(seed);
        h.update(context);
        h.update(body);

        assert_eq!(mock_signature(&seed, body, context), h.finalize().to_vec());
    }

    #[test]
    fn base64url_matches_known_no_padding_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
            (&[0xfb, 0xff], "-_8"),
        ];

        for (input, expected) in cases {
            assert_eq!(base64url(input), *expected);
        }
    }

    #[test]
    fn sha256_arr_matches_known_digest() {
        assert_eq!(
            sha256_arr(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn stable_bytes_keeps_legacy_short_length_encoding() {
        let spec = WebAuthnSpec::packed("example.com", b"short-challenge");
        let bytes = spec.stable_bytes();
        let marker = b"challenge\x1f";
        let at = bytes
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("challenge marker present");
        let len_offset = at + marker.len();
        assert_eq!(&bytes[len_offset..len_offset + 2], &[0, 15]);
    }

    #[test]
    fn stable_bytes_long_challenge_uses_extended_length_prefix() {
        let long = vec![0xAB; 70_000];
        let spec = WebAuthnSpec::packed("example.com", &long);
        let bytes = spec.stable_bytes();
        let marker = b"challenge\x1f";
        let at = bytes
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("challenge marker present");
        let len_offset = at + marker.len();
        assert_eq!(&bytes[len_offset..len_offset + 2], &[0xFF, 0xFF]);
        assert_eq!(
            &bytes[len_offset + 2..len_offset + 6],
            &(70_000u32).to_be_bytes()
        );
    }

    fn assert_contains_bytes(haystack: &[u8], needle: &[u8]) {
        assert!(
            haystack
                .windows(needle.len())
                .any(|window| window == needle),
            "expected bytes to contain {:?}",
            String::from_utf8_lossy(needle)
        );
    }

    fn value_by_integer_key(entries: &[(Value, Value)], key: i64) -> Option<&Value> {
        entries
            .iter()
            .find_map(|(k, v)| (*k == Value::Integer(key.into())).then_some(v))
    }

    fn bytes_by_integer_key(entries: &[(Value, Value)], key: i64) -> Option<&[u8]> {
        match value_by_integer_key(entries, key)? {
            Value::Bytes(bytes) => Some(bytes.as_slice()),
            _ => None,
        }
    }
}
