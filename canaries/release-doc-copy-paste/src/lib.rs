#[cfg(test)]
mod tests {
    use std::path::Path;

    use uselesskey::{ChainSpec, Factory, X509FactoryExt};
    use uselesskey_rustls::{RustlsClientConfigExt, RustlsServerConfigExt};

    const DEP_SNIPPET: &str = r#"[dev-dependencies]
uselesskey = { version = "0.5.1", features = ["x509"] }
uselesskey-rustls = { version = "0.5.1", features = ["tls-config", "rustls-ring"] }"#;

    const EXAMPLE_SNIPPET: &str = r#"use uselesskey::{ChainSpec, Factory, X509FactoryExt};
use uselesskey_rustls::{RustlsServerConfigExt, RustlsClientConfigExt};

let fx = Factory::random();
let chain = fx.x509_chain("my-service", ChainSpec::new("test.example.com"));

let server_config = chain.server_config_rustls();
let client_config = chain.client_config_rustls();"#;

    #[test]
    fn readme_still_contains_the_published_dependency_snippet_and_example() {
        let readme = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../README.md"))
            .expect("workspace README should be readable");

        assert!(readme.contains(DEP_SNIPPET), "dependency snippet drifted");
        assert!(
            readme.contains(EXAMPLE_SNIPPET),
            "example snippet drifted"
        );
    }

    #[test]
    fn readme_copy_paste_example_executes() {
        let mode = std::env::var("USELESSKEY_CANARY_MODE").unwrap_or_else(|_| "path".to_string());
        if mode == "published" {
            let published_version = std::env::var("USELESSKEY_CANARY_PUBLISHED_VERSION")
                .expect("published canary mode must declare the version under test");
            assert!(
                !published_version.trim().is_empty(),
                "published version should not be empty"
            );
        }

        let fx = Factory::random();
        let chain = fx.x509_chain("my-service", ChainSpec::new("test.example.com"));

        let server_config = chain.server_config_rustls();
        let client_config = chain.client_config_rustls();

        let _ = (server_config, client_config);
    }
}
