//! Adapter example: uselesskey + rustls for TLS setup.
//!
//! Demonstrates converting uselesskey X.509 fixtures into rustls types
//! for building TLS server and client configurations.
//!
//! Run with: cargo run -p uselesskey --example adapter_rustls --features full

#[cfg(feature = "x509")]
fn main() {
    use uselesskey::{ChainSpec, Factory, Seed, X509FactoryExt, X509Spec};
    use uselesskey_rustls::{
        RustlsCertExt, RustlsChainExt, RustlsClientConfigExt, RustlsPrivateKeyExt,
        RustlsServerConfigExt,
    };

    let fx = Factory::deterministic(Seed::from_env_value("rustls-demo").unwrap());

    // =========================================================================
    // 1. Self-signed certificate → rustls types
    // =========================================================================
    println!("=== Self-Signed → rustls Types ===\n");

    let cert = fx.x509_self_signed("localhost", X509Spec::self_signed("localhost"));

    // Convert to rustls-pki-types.
    let cert_der = cert.certificate_der_rustls();
    let key_der = cert.private_key_der_rustls();

    println!("  CertificateDer : {} bytes", cert_der.as_ref().len());
    println!("  PrivateKeyDer  : {} bytes", key_der.secret_der().len());

    // =========================================================================
    // 2. Certificate chain → rustls types
    // =========================================================================
    println!("\n=== Chain → rustls Types ===\n");

    let chain = fx.x509_chain(
        "api-service",
        ChainSpec::new("api.example.com")
            .with_sans(vec!["localhost".to_string(), "127.0.0.1".to_string()]),
    );

    // chain_der_rustls() returns leaf + intermediate (what a TLS server presents).
    let chain_certs = chain.chain_der_rustls();
    println!(
        "  Chain certs (leaf + intermediate) : {} certs",
        chain_certs.len()
    );
    for (i, c) in chain_certs.iter().enumerate() {
        println!("    cert[{i}] : {} bytes", c.as_ref().len());
    }

    // root_certificate_der_rustls() returns the root CA for the trust store.
    let root = chain.root_certificate_der_rustls();
    println!("  Root CA cert : {} bytes", root.as_ref().len());

    // Private key for the leaf certificate.
    let chain_key = chain.private_key_der_rustls();
    println!(
        "  Leaf private key : {} bytes",
        chain_key.secret_der().len()
    );

    // =========================================================================
    // 3. Build a rustls ServerConfig (one-liner)
    // =========================================================================
    println!("\n=== rustls ServerConfig ===\n");

    let server_config = chain.server_config_rustls();
    println!("  ServerConfig created : ✓");
    println!(
        "  ALPN protocols       : {:?}",
        server_config.alpn_protocols
    );

    // Also works with self-signed certs.
    let self_signed_config = cert.server_config_rustls();
    println!("  Self-signed config   : ✓");
    println!(
        "  ALPN protocols       : {:?}",
        self_signed_config.alpn_protocols
    );

    // =========================================================================
    // 4. Build a rustls ClientConfig (trusts the chain's root CA)
    // =========================================================================
    println!("\n=== rustls ClientConfig ===\n");

    let client_config = chain.client_config_rustls();
    println!("  ClientConfig created : ✓");
    println!(
        "  ALPN protocols       : {:?}",
        client_config.alpn_protocols
    );

    println!("\n=== All rustls adapter examples passed ===");
}

#[cfg(not(feature = "x509"))]
fn main() {
    eprintln!("Enable 'x509' feature:");
    eprintln!("  cargo run -p uselesskey --example adapter_rustls --features full");
}
