//! Build JWK and JWKS documents for mock OIDC/OAuth servers.
//!
//! Run with: `cargo run -p uselesskey --example jwk_jwks --features "rsa ecdsa ed25519 jwk"`

fn main() {
    #[cfg(all(feature = "jwk", feature = "rsa"))]
    {
        use uselesskey::{Factory, RsaFactoryExt, RsaSpec};

        let fx = Factory::random();

        println!("=== Single-key JWKS ===");
        let kp = fx.rsa("issuer", RsaSpec::rs256());
        let jwk = kp.public_jwk();
        let jwk_value = jwk.to_value();
        println!("  kty: {}", jwk_value["kty"]);
        println!("  alg: {}", jwk_value["alg"]);
        println!("  kid: {}", jwk_value["kid"]);

        let jwks = kp.public_jwks();
        let jwks_value = jwks.to_value();
        println!(
            "  keys: {} key(s)",
            jwks_value["keys"].as_array().map(|a| a.len()).unwrap_or(0)
        );

        println!("\n=== Multi-key JWKS ===");
        let mut builder = uselesskey::jwk::JwksBuilder::new();

        let rsa = fx.rsa("auth-rsa", RsaSpec::rs256());
        builder.push_public(rsa.public_jwk());

        #[cfg(feature = "ecdsa")]
        {
            use uselesskey::{EcdsaFactoryExt, EcdsaSpec};
            let ec = fx.ecdsa("auth-ec", EcdsaSpec::es256());
            builder.push_public(ec.public_jwk());
        }

        #[cfg(feature = "ed25519")]
        {
            use uselesskey::{Ed25519FactoryExt, Ed25519Spec};
            let ed = fx.ed25519("auth-ed", Ed25519Spec::new());
            builder.push_public(ed.public_jwk());
        }

        let jwks = builder.build();
        let value = jwks.to_value();
        let keys = value["keys"].as_array().unwrap();
        println!("  Total keys: {}", keys.len());
        for k in keys {
            println!("    - kty={}, alg={}, kid={}", k["kty"], k["alg"], k["kid"]);
        }
    }

    #[cfg(not(all(feature = "jwk", feature = "rsa")))]
    println!("Enable features 'jwk' and 'rsa' to run this example.");
}
