#[cfg(feature = "path-deps")]
use uselesskey_path as uselesskey;
#[cfg(feature = "published")]
use uselesskey_pub as uselesskey;

use uselesskey::{ChainSpec, Factory, RsaFactoryExt, RsaSpec, TokenFactoryExt, TokenSpec, X509FactoryExt};

fn main() {
    let fx = Factory::deterministic_from_str("canary-facade-minimal");

    let rsa = fx.rsa("issuer", RsaSpec::rs256());
    assert!(rsa.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));

    let token = fx.token("svc-api", TokenSpec::api_key());
    assert!(token.value().starts_with("uk_test_"));

    let chain = fx.x509_chain("svc", ChainSpec::new("test.example.com"));
    assert!(chain.chain_pem().contains("BEGIN CERTIFICATE"));
}

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        super::main();
    }
}
