#[cfg(feature = "path-deps")]
use uselesskey_path as uselesskey;
#[cfg(feature = "published")]
use uselesskey_pub as uselesskey;
#[cfg(feature = "path-deps")]
use uselesskey_rustls_path as uselesskey_rustls;
#[cfg(feature = "published")]
use uselesskey_rustls_pub as uselesskey_rustls;

use uselesskey::{ChainSpec, Factory, X509FactoryExt};
use uselesskey_rustls::{RustlsClientConfigExt, RustlsServerConfigExt};

fn main() {
    let fx = Factory::deterministic_from_str("canary-adapter-rustls");
    let chain = fx.x509_chain("svc", ChainSpec::new("test.example.com"));

    let _server_cfg = chain.server_config_rustls();
    let _client_cfg = chain.client_config_rustls();
}

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        super::main();
    }
}
