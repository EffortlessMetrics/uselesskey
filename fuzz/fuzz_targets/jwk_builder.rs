#![no_main]

use libfuzzer_sys::fuzz_target;
use uselesskey_jwk::{JwksBuilder, OctJwk, PrivateJwk, PublicJwk, RsaPublicJwk};

const ALPHABET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";

fn kid_from_bytes(bytes: &[u8], index: usize) -> String {
    let mut kid = String::new();
    for &b in bytes.iter().take(16) {
        kid.push(ALPHABET[(b as usize) % ALPHABET.len()] as char);
    }

    if kid.is_empty() {
        kid.push('k');
        kid.push(char::from(b'0' + (index as u8 % 10)));
    }

    kid
}

fuzz_target!(|data: &[u8]| {
    let mut builder = JwksBuilder::new();
    let mut count = 0usize;

    for (index, chunk) in data.chunks(8).take(64).enumerate() {
        let kid = kid_from_bytes(chunk, index);

        if index % 2 == 0 {
            let jwk = PublicJwk::Rsa(RsaPublicJwk {
                kty: "RSA",
                use_: "sig",
                alg: "RS256",
                kid,
                n: "AQAB".to_string(),
                e: "AQAB".to_string(),
            });
            builder.push_public(jwk);
        } else {
            let jwk = PrivateJwk::Oct(OctJwk {
                kty: "oct",
                use_: "sig",
                alg: "HS256",
                kid,
                k: "a2V5".to_string(),
            });
            builder.push_private(jwk);
        }

        count += 1;
    }

    let jwks = builder.build();
    assert_eq!(jwks.keys.len(), count);

    let value = jwks.to_value();
    assert!(value["keys"].is_array());

    let rendered = jwks.to_string();
    let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("JWKS JSON");
    assert!(parsed["keys"].is_array());
});
