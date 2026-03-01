#![no_main]

use libfuzzer_sys::fuzz_target;

use uselesskey_core_jwk_shape::{
    AnyJwk, EcPublicJwk, Jwks, OctJwk, OkpPublicJwk, PrivateJwk, PublicJwk, RsaPublicJwk,
};

/// Build a deterministic string from fuzz bytes (alphanumeric only).
fn string_from_bytes(bytes: &[u8], fallback: &str) -> String {
    if bytes.is_empty() {
        return fallback.to_string();
    }
    bytes
        .iter()
        .map(|b| {
            let c = (*b % 36) as usize;
            if c < 10 {
                (b'0' + c as u8) as char
            } else {
                (b'a' + (c - 10) as u8) as char
            }
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    // --- Part 1: Fuzz arbitrary JSON parsing (panic-freedom). ---
    // Feed raw fuzz bytes directly to serde_json; this exercises the JSON
    // parser with arbitrary input that might look like JWK/JWKS without
    // allocating an owned String for non-UTF8 inputs.
    let _ = serde_json::from_slice::<serde_json::Value>(data);

    // --- Part 2: Build JWKs from fuzz data and round-trip through JSON. ---
    if data.len() < 4 {
        return;
    }

    let kid = string_from_bytes(&data[..data.len().min(16)], "kid");
    let material = string_from_bytes(&data[1..data.len().min(17)], "n_value");

    // Choose JWK variant based on first byte.
    let jwk: AnyJwk = match data[0] % 5 {
        0 => AnyJwk::Public(PublicJwk::Rsa(RsaPublicJwk {
            kty: "RSA",
            use_: "sig",
            alg: "RS256",
            kid: kid.clone(),
            n: material.clone(),
            e: "AQAB".to_string(),
        })),
        1 => AnyJwk::Public(PublicJwk::Ec(EcPublicJwk {
            kty: "EC",
            use_: "sig",
            alg: "ES256",
            kid: kid.clone(),
            crv: "P-256",
            x: material.clone(),
            y: material.clone(),
        })),
        2 => AnyJwk::Public(PublicJwk::Okp(OkpPublicJwk {
            kty: "OKP",
            use_: "sig",
            alg: "EdDSA",
            kid: kid.clone(),
            crv: "Ed25519",
            x: material.clone(),
        })),
        3 => AnyJwk::Private(PrivateJwk::Oct(OctJwk {
            kty: "oct",
            use_: "sig",
            alg: "HS256",
            kid: kid.clone(),
            k: material.clone(),
        })),
        _ => AnyJwk::Public(PublicJwk::Rsa(RsaPublicJwk {
            kty: "RSA",
            use_: "enc",
            alg: "RS512",
            kid: kid.clone(),
            n: material.clone(),
            e: "AQAB".to_string(),
        })),
    };

    // Serialize a single JWK to JSON and re-parse as Value.
    let single_json = serde_json::to_string(&jwk).expect("AnyJwk serialization");
    let parsed: serde_json::Value =
        serde_json::from_str(&single_json).expect("AnyJwk JSON re-parse");
    assert!(parsed.get("kid").is_some());

    // Build a JWKS with multiple keys and round-trip.
    let mut jwks = Jwks {
        keys: Vec::new(),
    };
    for (idx, chunk) in data.chunks(8).take(32).enumerate() {
        let k = string_from_bytes(chunk, &format!("k{idx}"));
        if idx % 2 == 0 {
            jwks.keys.push(AnyJwk::Public(PublicJwk::Rsa(RsaPublicJwk {
                kty: "RSA",
                use_: "sig",
                alg: "RS256",
                kid: k,
                n: "AQAB".to_string(),
                e: "AQAB".to_string(),
            })));
        } else {
            jwks.keys.push(AnyJwk::Private(PrivateJwk::Oct(OctJwk {
                kty: "oct",
                use_: "sig",
                alg: "HS256",
                kid: k,
                k: "a2V5".to_string(),
            })));
        }
    }

    let jwks_json = jwks.to_string();
    let jwks_parsed: serde_json::Value =
        serde_json::from_str(&jwks_json).expect("JWKS JSON re-parse");
    assert!(jwks_parsed["keys"].is_array());
});
