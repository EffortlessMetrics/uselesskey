use uselesskey_core::Factory;
use uselesskey_rustls::{RustlsClientConfigExt, RustlsServerConfigExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt};

fn main() {
    let fx = Factory::deterministic_from_str("adapter-rustls-canary");
    let chain = fx.x509_chain("svc", ChainSpec::new("test.example.com"));

    let server = chain.server_config_rustls();
    let client = chain.client_config_rustls();

    let _ = (server, client);
}
