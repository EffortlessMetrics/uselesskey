#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey_jwk::{EcPublicJwk, JwksBuilder, OctJwk, OkpPublicJwk, PrivateJwk, PublicJwk};

#[derive(Arbitrary, Debug)]
enum FuzzKey {
    Ec { kid: String },
    Okp { kid: String },
    Oct { kid: String },
}

#[derive(Arbitrary, Debug)]
struct JwksBuilderInput {
    keys: Vec<FuzzKey>,
}

fuzz_target!(|input: JwksBuilderInput| {
    let mut builder = JwksBuilder::new();
    let mut count = 0usize;

    for key in input.keys.iter().take(64) {
        match key {
            FuzzKey::Ec { kid } => {
                builder.push_public(PublicJwk::Ec(EcPublicJwk {
                    kty: "EC",
                    use_: "sig",
                    alg: "ES256",
                    crv: "P-256",
                    kid: kid.clone(),
                    x: "dGVzdC14".to_string(),
                    y: "dGVzdC15".to_string(),
                }));
            }
            FuzzKey::Okp { kid } => {
                builder.push_public(PublicJwk::Okp(OkpPublicJwk {
                    kty: "OKP",
                    use_: "sig",
                    alg: "EdDSA",
                    crv: "Ed25519",
                    kid: kid.clone(),
                    x: "dGVzdC14".to_string(),
                }));
            }
            FuzzKey::Oct { kid } => {
                builder.push_private(PrivateJwk::Oct(OctJwk {
                    kty: "oct",
                    use_: "sig",
                    alg: "HS256",
                    kid: kid.clone(),
                    k: "a2V5".to_string(),
                }));
            }
        }
        count += 1;
    }

    let jwks = builder.build();
    assert_eq!(jwks.keys.len(), count);

    let json = jwks.to_string();
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("JWKS must be valid JSON");
    assert!(parsed["keys"].is_array());
    assert_eq!(parsed["keys"].as_array().unwrap().len(), count);

    // Verify to_value matches parsed JSON.
    let value = jwks.to_value();
    assert_eq!(value, parsed);
});
