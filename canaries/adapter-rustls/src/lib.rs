#[cfg(test)]
mod tests {
    use uselesskey::{ChainSpec, Factory, X509FactoryExt};
    use uselesskey_rustls::{RustlsClientConfigExt, RustlsServerConfigExt};

    #[test]
    fn rustls_adapter_builds_server_and_client_configs() {
        let fx = Factory::deterministic_from_str("canary-rustls-adapter-v1");
        let chain = fx.x509_chain("tls-service", ChainSpec::new("tls.example.com"));

        let server = chain.server_config_rustls();
        let client = chain.client_config_rustls();

        let _ = (server, client);
    }
}
