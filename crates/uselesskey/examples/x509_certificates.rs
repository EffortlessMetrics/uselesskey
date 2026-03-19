//! X.509 certificate fixtures for testing TLS and PKI code.
//!
//! This example demonstrates:
//! - Self-signed certificates with various specs (CN, SANs, validity)
//! - Three-level certificate chains (Root CA → Intermediate → Leaf)
//! - X.509 negative fixtures (expired, not-yet-valid, wrong key usage)
//! - Chain negative fixtures (hostname mismatch, unknown CA, revoked leaf)
//! - Writing certificates to tempfiles for external tools
//!
//! Run with: cargo run -p uselesskey --example x509_certificates --features "x509"

#[cfg(feature = "x509")]
fn main() {
    use uselesskey::negative::CorruptPem;
    use uselesskey::{ChainNegative, ChainSpec, Factory, Seed, X509FactoryExt, X509Spec};

    // Use a deterministic factory so output is reproducible across runs.
    let seed = Seed::from_env_value("x509-demo").unwrap();
    let fx = Factory::deterministic(seed);

    // =========================================================================
    // 1. Self-signed certificates with various specs
    // =========================================================================
    println!("=== Self-Signed Certificates ===\n");

    // Basic self-signed leaf certificate
    let basic = fx.x509_self_signed("basic", X509Spec::self_signed("api.example.com"));
    println!("Basic leaf certificate:");
    println!("  Subject CN: api.example.com");
    println!("  Cert PEM:   {} bytes", basic.cert_pem().len());
    println!("  Cert DER:   {} bytes", basic.cert_der().len());
    println!(
        "  Key PEM:    {} bytes",
        basic.private_key_pkcs8_pem().len()
    );
    assert!(basic.cert_pem().contains("-----BEGIN CERTIFICATE-----"));

    // Certificate with Subject Alternative Names
    let with_sans = fx.x509_self_signed(
        "multi-domain",
        X509Spec::self_signed("app.example.com").with_sans(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "app.internal".to_string(),
        ]),
    );
    println!("\nMulti-domain certificate (with SANs):");
    println!("  Subject CN: app.example.com");
    println!("  SANs: localhost, 127.0.0.1, app.internal");
    println!("  Cert DER: {} bytes", with_sans.cert_der().len());

    // Short-lived certificate (e.g., for testing rotation)
    let short_lived = fx.x509_self_signed(
        "ephemeral",
        X509Spec::self_signed("short.example.com").with_validity_days(1),
    );
    println!("\nShort-lived certificate (1 day validity):");
    println!("  Cert DER: {} bytes", short_lived.cert_der().len());

    // Self-signed CA certificate
    let ca = fx.x509_self_signed("root-ca", X509Spec::self_signed_ca("My Test CA"));
    println!("\nSelf-signed CA certificate:");
    println!("  Subject CN: My Test CA");
    println!("  is_ca: {}", ca.spec().is_ca);
    assert!(ca.spec().is_ca);

    // Combined identity file (cert + key in one PEM)
    let identity = basic.identity_pem();
    println!("\nIdentity PEM (cert + key combined):");
    println!("  Total length: {} bytes", identity.len());
    assert!(identity.contains("-----BEGIN CERTIFICATE-----"));
    assert!(identity.contains("-----BEGIN PRIVATE KEY-----"));

    // =========================================================================
    // 2. Certificate chains (Root CA → Intermediate → Leaf)
    // =========================================================================
    println!("\n=== Certificate Chains ===\n");

    let chain = fx.x509_chain(
        "tls-service",
        ChainSpec::new("service.example.com")
            .with_sans(vec!["localhost".to_string(), "127.0.0.1".to_string()]),
    );

    println!("Three-level chain for service.example.com:");
    println!(
        "  Root cert:         {} bytes PEM",
        chain.root_cert_pem().len()
    );
    println!(
        "  Intermediate cert: {} bytes PEM",
        chain.intermediate_cert_pem().len()
    );
    println!(
        "  Leaf cert:         {} bytes PEM",
        chain.leaf_cert_pem().len()
    );

    // chain_pem() = leaf + intermediate (what a TLS server presents)
    let server_chain = chain.chain_pem();
    let cert_count = server_chain.matches("-----BEGIN CERTIFICATE-----").count();
    println!("  Server chain (leaf + intermediate): {} certs", cert_count);
    assert_eq!(cert_count, 2);

    // full_chain_pem() = leaf + intermediate + root (for debugging)
    let full = chain.full_chain_pem();
    let full_count = full.matches("-----BEGIN CERTIFICATE-----").count();
    println!("  Full chain (includes root): {} certs", full_count);
    assert_eq!(full_count, 3);

    // =========================================================================
    // 3. X.509 negative fixtures (self-signed)
    // =========================================================================
    println!("\n=== Self-Signed Negative Fixtures ===\n");

    let valid = fx.x509_self_signed("negative-test", X509Spec::self_signed("test.example.com"));

    // Expired certificate
    let expired = valid.expired();
    println!("Expired certificate:");
    println!(
        "  DER differs from valid: {}",
        expired.cert_der() != valid.cert_der()
    );
    assert_ne!(expired.cert_der(), valid.cert_der());

    // Not-yet-valid certificate
    let future = valid.not_yet_valid();
    println!("Not-yet-valid certificate:");
    println!(
        "  DER differs from valid: {}",
        future.cert_der() != valid.cert_der()
    );
    assert_ne!(future.cert_der(), valid.cert_der());

    // Wrong key usage (CA flag set but key_cert_sign missing)
    let bad_ku = valid.wrong_key_usage();
    println!("Wrong key usage certificate:");
    println!(
        "  is_ca: {}, key_cert_sign: {}",
        bad_ku.spec().is_ca,
        bad_ku.spec().key_usage.key_cert_sign
    );
    assert!(bad_ku.spec().is_ca);
    assert!(!bad_ku.spec().key_usage.key_cert_sign);

    // Corrupt PEM encoding
    let bad_header = valid.corrupt_cert_pem(CorruptPem::BadHeader);
    println!("Corrupt PEM (bad header):");
    println!("  Starts with: {}", &bad_header[..45]);
    assert!(bad_header.contains("CORRUPTED"));

    let bad_base64 = valid.corrupt_cert_pem(CorruptPem::BadBase64);
    println!("Corrupt PEM (bad base64):");
    println!(
        "  Contains invalid data: {}",
        bad_base64.contains("THIS_IS_NOT_BASE64")
    );
    assert!(bad_base64.contains("THIS_IS_NOT_BASE64"));

    // Truncated DER
    let truncated = valid.truncate_cert_der(10);
    println!("Truncated DER:");
    println!(
        "  Original: {} bytes → Truncated: {} bytes",
        valid.cert_der().len(),
        truncated.len()
    );
    assert_eq!(truncated.len(), 10);

    // Deterministic corruption (same variant string → same output)
    let corrupt_a = valid.corrupt_cert_pem_deterministic("corrupt:scenario-1");
    let corrupt_b = valid.corrupt_cert_pem_deterministic("corrupt:scenario-1");
    println!("Deterministic corruption:");
    println!(
        "  Same variant → identical output: {}",
        corrupt_a == corrupt_b
    );
    assert_eq!(corrupt_a, corrupt_b);

    // =========================================================================
    // 4. Chain negative fixtures
    // =========================================================================
    println!("\n=== Chain Negative Fixtures ===\n");

    let good_chain = fx.x509_chain("neg-chain", ChainSpec::new("secure.example.com"));

    // Hostname mismatch: leaf cert has a different hostname than expected
    let mismatch = good_chain.hostname_mismatch("evil.example.com");
    println!("Hostname mismatch chain:");
    println!("  Leaf cert CN differs from 'secure.example.com'");
    assert_ne!(good_chain.leaf_cert_der(), mismatch.leaf_cert_der());

    // Unknown CA: chain signed by a different root
    let unknown = good_chain.unknown_ca();
    println!("Unknown CA chain:");
    println!(
        "  Root cert differs: {}",
        good_chain.root_cert_der() != unknown.root_cert_der()
    );
    assert_ne!(good_chain.root_cert_der(), unknown.root_cert_der());

    // Expired leaf certificate
    let expired_leaf = good_chain.expired_leaf();
    println!("Expired leaf chain:");
    println!(
        "  Leaf cert differs: {}",
        good_chain.leaf_cert_der() != expired_leaf.leaf_cert_der()
    );
    assert_ne!(good_chain.leaf_cert_der(), expired_leaf.leaf_cert_der());

    // Expired intermediate certificate
    let expired_int = good_chain.expired_intermediate();
    println!("Expired intermediate chain:");
    println!(
        "  Intermediate differs: {}",
        good_chain.intermediate_cert_der() != expired_int.intermediate_cert_der()
    );

    // Revoked leaf (includes CRL)
    let revoked = good_chain.revoked_leaf();
    println!("Revoked leaf chain:");
    if let Some(crl_pem) = revoked.crl_pem() {
        println!("  CRL PEM: {} bytes", crl_pem.len());
        assert!(crl_pem.contains("-----BEGIN X509 CRL-----"));
    }

    // Using the generic ChainNegative enum directly
    let mismatch2 = good_chain.negative(ChainNegative::HostnameMismatch {
        wrong_hostname: "attacker.example.com".to_string(),
    });
    println!("Generic negative (HostnameMismatch):");
    println!(
        "  Leaf cert differs: {}",
        good_chain.leaf_cert_der() != mismatch2.leaf_cert_der()
    );

    // =========================================================================
    // 5. Tempfile outputs (for tools that need file paths)
    // =========================================================================
    println!("\n=== Tempfile Outputs ===\n");

    let cert = fx.x509_self_signed("tempfile-demo", X509Spec::self_signed("localhost"));
    let cert_file = cert.write_cert_pem().expect("write cert");
    let key_file = cert.write_private_key_pem().expect("write key");
    let id_file = cert.write_identity_pem().expect("write identity");

    println!("Certificate: {}", cert_file.path().display());
    println!("Private key: {}", key_file.path().display());
    println!("Identity:    {}", id_file.path().display());
    assert!(cert_file.path().exists());
    assert!(key_file.path().exists());
    assert!(id_file.path().exists());

    let chain = fx.x509_chain("tempfile-chain", ChainSpec::new("localhost"));
    let chain_file = chain.write_chain_pem().expect("write chain");
    let root_file = chain.write_root_cert_pem().expect("write root");

    println!("Chain PEM:   {}", chain_file.path().display());
    println!("Root CA:     {}", root_file.path().display());
    println!("\n(All tempfiles auto-delete when dropped)");

    println!("\n=== All X.509 examples completed successfully ===");
}

#[cfg(not(feature = "x509"))]
fn main() {
    eprintln!("Enable required feature to run this example:");
    eprintln!("  cargo run -p uselesskey --example x509_certificates --features \"x509\"");
}
