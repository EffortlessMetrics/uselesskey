use uselesskey_core::Factory;
use uselesskey_rustls::{RustlsClientConfigExt, RustlsServerConfigExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt};

fn run() {
    let fx = Factory::deterministic_from_str("canary-adapter-rustls");
    let chain = fx.x509_chain("svc", ChainSpec::new("test.example.com"));

    let server = chain.server_config_rustls();
    let client = chain.client_config_rustls();

    assert!(server.alpn_protocols.is_empty());
    assert!(client.alpn_protocols.is_empty());
}

fn main() {
    run();
}

#[cfg(test)]
mod tests {
    #[test]
    fn rustls_adapter_builds_configs() {
        super::run();
    }
}
