use cucumber::then;

// =========================================================================
// Private key conversions (RSA, ECDSA, Ed25519)
// =========================================================================

#[then("the RSA key should convert to a valid rustls PrivateKeyDer")]
fn rustls_rsa_private_key(world: &mut crate::UselessWorld) {
    use uselesskey_rustls::RustlsPrivateKeyExt;

    let rsa = world.rsa.as_ref().expect("RSA key not set");
    let key = rsa.private_key_der_rustls();
    assert!(
        !key.secret_der().is_empty(),
        "rustls PrivateKeyDer should be non-empty"
    );
}

#[then("the rustls PrivateKeyDer should match the RSA PKCS8 DER")]
fn rustls_rsa_private_key_matches(world: &mut crate::UselessWorld) {
    use uselesskey_rustls::RustlsPrivateKeyExt;

    let rsa = world.rsa.as_ref().expect("RSA key not set");
    let key = rsa.private_key_der_rustls();
    assert_eq!(key.secret_der(), rsa.private_key_pkcs8_der());
}

#[then("the ECDSA key should convert to a valid rustls PrivateKeyDer")]
fn rustls_ecdsa_private_key(world: &mut crate::UselessWorld) {
    use uselesskey_rustls::RustlsPrivateKeyExt;

    let ecdsa = world.ecdsa.as_ref().expect("ECDSA key not set");
    let key = ecdsa.private_key_der_rustls();
    assert!(
        !key.secret_der().is_empty(),
        "rustls PrivateKeyDer should be non-empty"
    );
}

#[then("the Ed25519 key should convert to a valid rustls PrivateKeyDer")]
fn rustls_ed25519_private_key(world: &mut crate::UselessWorld) {
    use uselesskey_rustls::RustlsPrivateKeyExt;

    let ed = world.ed25519.as_ref().expect("Ed25519 key not set");
    let key = ed.private_key_der_rustls();
    assert!(
        !key.secret_der().is_empty(),
        "rustls PrivateKeyDer should be non-empty"
    );
}

// =========================================================================
// X.509 self-signed cert
// =========================================================================

#[then("the X.509 cert should convert to a valid rustls CertificateDer")]
fn rustls_x509_cert(world: &mut crate::UselessWorld) {
    use uselesskey_rustls::RustlsCertExt;

    let cert = world.x509.as_ref().expect("X509 cert not set");
    let cert_der = cert.certificate_der_rustls();
    assert!(
        !cert_der.as_ref().is_empty(),
        "rustls CertificateDer should be non-empty"
    );
}

#[then("the X.509 cert rustls CertificateDer should match the cert DER")]
fn rustls_x509_cert_matches(world: &mut crate::UselessWorld) {
    use uselesskey_rustls::RustlsCertExt;

    let cert = world.x509.as_ref().expect("X509 cert not set");
    let cert_der = cert.certificate_der_rustls();
    assert_eq!(cert_der.as_ref(), cert.cert_der());
}

#[then("the X.509 cert should convert to a valid rustls PrivateKeyDer")]
fn rustls_x509_private_key(world: &mut crate::UselessWorld) {
    use uselesskey_rustls::RustlsPrivateKeyExt;

    let cert = world.x509.as_ref().expect("X509 cert not set");
    let key = cert.private_key_der_rustls();
    assert!(
        !key.secret_der().is_empty(),
        "rustls PrivateKeyDer should be non-empty"
    );
}

// =========================================================================
// X.509 chain
// =========================================================================

#[then("the X.509 chain should produce 2 rustls certificate DERs")]
fn rustls_chain_certs(world: &mut crate::UselessWorld) {
    use uselesskey_rustls::RustlsChainExt;

    let chain = world.x509_chain.as_ref().expect("X509 chain not set");
    let certs = chain.chain_der_rustls();
    assert_eq!(certs.len(), 2, "chain should have leaf + intermediate");
}

#[then("the X.509 chain should produce a rustls root certificate")]
fn rustls_chain_root(world: &mut crate::UselessWorld) {
    use uselesskey_rustls::RustlsChainExt;

    let chain = world.x509_chain.as_ref().expect("X509 chain not set");
    let root = chain.root_certificate_der_rustls();
    assert!(
        !root.as_ref().is_empty(),
        "rustls root CertificateDer should be non-empty"
    );
}

#[then("the X.509 chain rustls root should match the root DER")]
fn rustls_chain_root_matches(world: &mut crate::UselessWorld) {
    use uselesskey_rustls::RustlsChainExt;

    let chain = world.x509_chain.as_ref().expect("X509 chain not set");
    let root = chain.root_certificate_der_rustls();
    assert_eq!(root.as_ref(), chain.root_cert_der());
}
