//! Generate fixtures for every supported key type.
//!
//! Run with: `cargo run -p uselesskey --example all_key_types --features full`

use uselesskey::Factory;

fn main() {
    let fx = Factory::random();

    // --- RSA ---
    #[cfg(feature = "rsa")]
    {
        use uselesskey::{RsaFactoryExt, RsaSpec};

        println!("=== RSA ===");
        for (name, spec) in [
            ("RS256 (2048)", RsaSpec::rs256()),
            ("RSA 3072", RsaSpec::new(3072)),
            ("RSA 4096", RsaSpec::new(4096)),
        ] {
            let kp = fx.rsa("demo", spec);
            println!(
                "  {name}: PEM={} bytes, DER={} bytes",
                kp.private_key_pkcs8_pem().len(),
                kp.private_key_pkcs8_der().len()
            );
        }
    }

    // --- ECDSA ---
    #[cfg(feature = "ecdsa")]
    {
        use uselesskey::{EcdsaFactoryExt, EcdsaSpec};

        println!("\n=== ECDSA ===");
        for (name, spec) in [
            ("P-256 (ES256)", EcdsaSpec::es256()),
            ("P-384 (ES384)", EcdsaSpec::es384()),
        ] {
            let kp = fx.ecdsa("demo", spec);
            println!("  {name}: PEM={} bytes", kp.private_key_pkcs8_pem().len());
        }
    }

    // --- Ed25519 ---
    #[cfg(feature = "ed25519")]
    {
        use uselesskey::{Ed25519FactoryExt, Ed25519Spec};

        println!("\n=== Ed25519 ===");
        let kp = fx.ed25519("demo", Ed25519Spec::new());
        println!("  EdDSA: PEM={} bytes", kp.private_key_pkcs8_pem().len());
    }

    // --- HMAC ---
    #[cfg(feature = "hmac")]
    {
        use uselesskey::{HmacFactoryExt, HmacSpec};

        println!("\n=== HMAC ===");
        for (name, spec) in [
            ("HS256", HmacSpec::hs256()),
            ("HS384", HmacSpec::hs384()),
            ("HS512", HmacSpec::hs512()),
        ] {
            let kp = fx.hmac("demo", spec);
            println!("  {name}: secret={} bytes", kp.secret_bytes().len());
        }
    }

    // --- Token ---
    #[cfg(feature = "token")]
    {
        use uselesskey::{TokenFactoryExt, TokenSpec};

        println!("\n=== Token ===");
        let api = fx.token("demo", TokenSpec::api_key());
        println!("  API key:  {}", api.value());

        let bearer = fx.token("demo", TokenSpec::bearer());
        println!("  Bearer:   {}", bearer.authorization_header());

        let oauth = fx.token("demo", TokenSpec::oauth_access_token());
        println!(
            "  OAuth JWT: {} (parts: {})",
            &oauth.value()[..40],
            oauth.value().split('.').count()
        );
    }

    // --- X.509 ---
    #[cfg(feature = "x509")]
    {
        use uselesskey::{ChainSpec, X509FactoryExt, X509Spec};

        println!("\n=== X.509 ===");
        let self_signed = fx.x509_self_signed("demo", X509Spec::self_signed("test.example.com"));
        println!(
            "  Self-signed: cert={} bytes, key={} bytes",
            self_signed.cert_pem().len(),
            self_signed.private_key_pkcs8_pem().len()
        );

        let chain = fx.x509_chain("demo", ChainSpec::new("test.example.com"));
        println!(
            "  Chain: root={} bytes, chain={} bytes",
            chain.root_cert_pem().len(),
            chain.chain_pem().len()
        );

        // Negative X.509
        let expired = chain.expired_leaf();
        println!(
            "  Expired leaf:   cert={} bytes",
            expired.leaf_cert_pem().len()
        );

        let mismatch = chain.hostname_mismatch("wrong.example.com");
        println!(
            "  Host mismatch:  cert={} bytes",
            mismatch.leaf_cert_pem().len()
        );
    }

    println!("\n✓ All key types generated successfully");
}
