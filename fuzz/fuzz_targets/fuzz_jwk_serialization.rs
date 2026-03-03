#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey_core_jwk_shape::{
    AnyJwk, EcPublicJwk, Jwks, OctJwk, OkpPublicJwk, PrivateJwk, PublicJwk, RsaPublicJwk,
};
use uselesskey_jwk::JwksBuilder;

#[derive(Arbitrary, Debug)]
struct JwkSerdeInput {
    keys: Vec<FuzzJwkKey>,
    raw_json: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
enum FuzzJwkKey {
    Rsa { kid: String, n: String, alg_idx: u8 },
    Ec { kid: String, x: String, y: String, crv_idx: u8 },
    Okp { kid: String, x: String },
    Oct { kid: String, k: String, alg_idx: u8 },
}

fuzz_target!(|input: JwkSerdeInput| {
    // Cap sizes.
    if input.keys.len() > 64 || input.raw_json.len() > 4096 {
        return;
    }
    for key in &input.keys {
        match key {
            FuzzJwkKey::Rsa { kid, n, .. } if kid.len() > 256 || n.len() > 256 => return,
            FuzzJwkKey::Ec { kid, x, y, .. }
                if kid.len() > 256 || x.len() > 256 || y.len() > 256 =>
            {
                return;
            }
            FuzzJwkKey::Okp { kid, x } if kid.len() > 256 || x.len() > 256 => return,
            FuzzJwkKey::Oct { kid, k, .. } if kid.len() > 256 || k.len() > 256 => return,
            _ => {}
        }
    }

    // --- Part 1: Fuzz raw JSON parsing (panic-freedom) ---
    let _ = serde_json::from_slice::<serde_json::Value>(&input.raw_json);

    // --- Part 2: Build JWKs from fuzz data and round-trip ---
    let rsa_algs = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"];
    let ec_crvs = ["P-256", "P-384"];
    let hmac_algs = ["HS256", "HS384", "HS512"];

    let mut builder = JwksBuilder::new();
    let mut jwks_manual = Jwks { keys: Vec::new() };

    for key in &input.keys {
        match key {
            FuzzJwkKey::Rsa { kid, n, alg_idx } => {
                let alg = rsa_algs[*alg_idx as usize % rsa_algs.len()];
                let jwk = PublicJwk::Rsa(RsaPublicJwk {
                    kty: "RSA",
                    use_: "sig",
                    alg,
                    kid: kid.clone(),
                    n: n.clone(),
                    e: "AQAB".to_string(),
                });
                builder.push_public(jwk.clone());
                jwks_manual.keys.push(AnyJwk::Public(jwk));
            }
            FuzzJwkKey::Ec {
                kid,
                x,
                y,
                crv_idx,
            } => {
                let crv = ec_crvs[*crv_idx as usize % ec_crvs.len()];
                let alg = if crv == "P-256" { "ES256" } else { "ES384" };
                let jwk = PublicJwk::Ec(EcPublicJwk {
                    kty: "EC",
                    use_: "sig",
                    alg,
                    kid: kid.clone(),
                    crv,
                    x: x.clone(),
                    y: y.clone(),
                });
                builder.push_public(jwk.clone());
                jwks_manual.keys.push(AnyJwk::Public(jwk));
            }
            FuzzJwkKey::Okp { kid, x } => {
                let jwk = PublicJwk::Okp(OkpPublicJwk {
                    kty: "OKP",
                    use_: "sig",
                    alg: "EdDSA",
                    kid: kid.clone(),
                    crv: "Ed25519",
                    x: x.clone(),
                });
                builder.push_public(jwk.clone());
                jwks_manual.keys.push(AnyJwk::Public(jwk));
            }
            FuzzJwkKey::Oct { kid, k, alg_idx } => {
                let alg = hmac_algs[*alg_idx as usize % hmac_algs.len()];
                let jwk = PrivateJwk::Oct(OctJwk {
                    kty: "oct",
                    use_: "sig",
                    alg,
                    kid: kid.clone(),
                    k: k.clone(),
                });
                builder.push_private(jwk.clone());
                jwks_manual.keys.push(AnyJwk::Private(jwk));
            }
        }
    }

    // JwksBuilder round-trip.
    let built = builder.build();
    assert_eq!(built.keys.len(), input.keys.len());
    let json_str = built.to_string();
    let parsed: serde_json::Value =
        serde_json::from_str(&json_str).expect("JwksBuilder output must be valid JSON");
    assert!(parsed["keys"].is_array());
    assert_eq!(parsed["keys"].as_array().unwrap().len(), input.keys.len());

    // Manual Jwks round-trip.
    let manual_json = jwks_manual.to_string();
    let manual_parsed: serde_json::Value =
        serde_json::from_str(&manual_json).expect("Manual JWKS must be valid JSON");
    assert!(manual_parsed["keys"].is_array());

    // Individual key serialization round-trip.
    for key in &jwks_manual.keys {
        let key_json = serde_json::to_string(key).expect("AnyJwk must serialize");
        let key_val: serde_json::Value =
            serde_json::from_str(&key_json).expect("AnyJwk must re-parse");
        assert!(key_val.get("kid").is_some());
        assert!(key_val.get("kty").is_some());
    }

    // to_value must match parsed JSON.
    let value = built.to_value();
    assert_eq!(value, parsed);
});
