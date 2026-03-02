#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey_jwk::{EcPublicJwk, JwksBuilder, OkpPublicJwk, PublicJwk};

#[derive(Arbitrary, Debug)]
struct KeyEntry {
    kid: String,
    use_okp: bool,
}

#[derive(Arbitrary, Debug)]
struct Input {
    keys: Vec<KeyEntry>,
}

fuzz_target!(|input: Input| {
    if input.keys.len() > 128 {
        return;
    }

    // Build JWKS twice with the same keys in the same order → must be identical
    let build = |entries: &[KeyEntry]| {
        let mut builder = JwksBuilder::new();
        for entry in entries {
            if entry.use_okp {
                builder.push_public(PublicJwk::Okp(OkpPublicJwk {
                    kty: "OKP",
                    use_: "sig",
                    alg: "EdDSA",
                    crv: "Ed25519",
                    kid: entry.kid.clone(),
                    x: "dGVzdA".to_string(),
                }));
            } else {
                builder.push_public(PublicJwk::Ec(EcPublicJwk {
                    kty: "EC",
                    use_: "sig",
                    alg: "ES256",
                    crv: "P-256",
                    kid: entry.kid.clone(),
                    x: "dGVzdA".to_string(),
                    y: "dGVzdA".to_string(),
                }));
            }
        }
        builder.build()
    };

    let jwks1 = build(&input.keys);
    let jwks2 = build(&input.keys);

    // Same input → same output
    assert_eq!(jwks1.to_string(), jwks2.to_string());

    // Output must be sorted by kid
    let kids: Vec<&str> = jwks1.keys.iter().map(|k| k.kid()).collect();
    for pair in kids.windows(2) {
        assert!(pair[0] <= pair[1], "JWKS keys must be sorted by kid");
    }

    // JSON must be valid
    let json = jwks1.to_string();
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(
        parsed["keys"].as_array().unwrap().len(),
        input.keys.len()
    );
});
