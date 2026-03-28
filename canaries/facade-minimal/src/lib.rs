#[cfg(test)]
mod tests {
    use uselesskey::{
        ChainSpec, Factory, RsaFactoryExt, RsaSpec, TokenFactoryExt, TokenSpec, X509FactoryExt,
    };

    #[test]
    fn facade_minimal_generates_key_token_and_cert() {
        let fx = Factory::deterministic_from_str("canary-facade-minimal-v1");

        let rsa = fx.rsa("service-signing", RsaSpec::rs256());
        let token = fx.token("service-token", TokenSpec::bearer());
        let cert = fx.x509_chain("service-cert", ChainSpec::new("service.example.com"));

        assert!(rsa.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(token.authorization_header().starts_with("Bearer "));
        assert!(cert.chain_pem().contains("BEGIN CERTIFICATE"));
    }
}
