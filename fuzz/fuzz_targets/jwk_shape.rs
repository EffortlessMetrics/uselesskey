#![no_main]

use libfuzzer_sys::fuzz_target;

use uselesskey_core_jwk_shape::{AnyJwk, Jwks, OctJwk, PrivateJwk, PublicJwk, RsaPublicJwk};

fn string_from_bytes(bytes: &[u8], fallback: &str) -> String {
    if bytes.is_empty() {
        return fallback.to_string();
    }

    bytes
        .iter()
        .map(|byte| {
            let c = (byte % 62) as usize;
            match c {
                0..=9 => (b'0' + c as u8) as char,
                10..=35 => (b'a' + (c - 10) as u8) as char,
                _ => (b'A' + (c - 36) as u8) as char,
            }
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let mut jwks = Jwks {
        keys: Vec::new(),
    };

    for (idx, chunk) in data.chunks(16).take(64).enumerate() {
        let kid = string_from_bytes(chunk, "fallback");
        let material = string_from_bytes(&chunk.iter().rev().copied().collect::<Vec<_>>(), "material");

        match idx % 3 {
            0 => {
                let public = PublicJwk::Rsa(RsaPublicJwk {
                    kty: "RSA",
                    use_: "sig",
                    alg: "RS256",
                    kid: kid.clone(),
                    n: material.clone(),
                    e: "AQAB".to_string(),
                });
                jwks.keys.push(AnyJwk::Public(public));
            }
            1 => {
                let private = PrivateJwk::Oct(OctJwk {
                    kty: "oct",
                    use_: "sig",
                    alg: "HS256",
                    kid: kid.clone(),
                    k: material,
                });
                jwks.keys.push(AnyJwk::Private(private));
            }
            _ => {
                let public = PublicJwk::Rsa(RsaPublicJwk {
                    kty: "RSA",
                    use_: "sig",
                    alg: "RS256",
                    kid,
                    n: material,
                    e: "AQAB".to_string(),
                });
                jwks.keys.push(AnyJwk::Public(public));
            }
        }
    }

    let rendered = jwks.to_string();
    let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("serialized jwks should be JSON");
    assert!(parsed["keys"].as_array().is_some());

    for key in parsed["keys"].as_array().unwrap() {
        assert!(key.get("kid").is_some());
        assert!(!key.get("kid").unwrap().as_str().unwrap().is_empty());
    }
});
