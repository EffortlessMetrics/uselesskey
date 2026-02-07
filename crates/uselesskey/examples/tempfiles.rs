#[cfg(feature = "x509")]
fn main() {
    use uselesskey::{Factory, X509FactoryExt, X509Spec};

    let fx = Factory::random();
    let cert = fx.x509_self_signed("example.com", X509Spec::self_signed("example.com"));

    let cert_file = cert.write_cert_pem().expect("write cert");
    let key_file = cert.write_private_key_pem().expect("write key");
    let identity_file = cert.write_identity_pem().expect("write identity");

    println!("cert:     {}", cert_file.path().display());
    println!("key:      {}", key_file.path().display());
    println!("identity: {}", identity_file.path().display());
}

#[cfg(not(feature = "x509"))]
fn main() {
    eprintln!("Enable the 'x509' feature to run this example.");
}
