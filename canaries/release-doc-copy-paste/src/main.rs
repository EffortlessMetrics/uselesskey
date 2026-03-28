use std::path::Path;

use uselesskey::{Factory, RsaFactoryExt, RsaSpec};

fn run() {
    let fx = Factory::random();
    let rsa = fx.rsa("my-service", RsaSpec::rs256());

    let private_pem = rsa.private_key_pkcs8_pem();
    let public_der = rsa.public_key_spki_der();

    assert!(private_pem.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(!public_der.is_empty());
}

fn main() {
    run();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docs_example_runs() {
        run();
    }

    #[test]
    fn docs_dependency_snippet_parity() {
        if std::env::var("USELESSKEY_CANARY_PUBLISHED").is_ok() {
            return;
        }
        let expected = std::fs::read_to_string("SNIPPET.toml").expect("read canary snippet");
        let docs = std::fs::read_to_string(Path::new("../../crates/uselesskey/README.md"))
            .expect("read facade docs");
        assert!(
            docs.contains(expected.trim()),
            "canary dependency snippet must match docs"
        );
    }

    #[test]
    fn docs_example_parity() {
        if std::env::var("USELESSKEY_CANARY_PUBLISHED").is_ok() {
            return;
        }
        let expected = std::fs::read_to_string("EXAMPLE.rs").expect("read canary example");
        let docs = std::fs::read_to_string(Path::new("../../crates/uselesskey/README.md"))
            .expect("read facade docs");
        assert!(
            docs.contains(expected.trim()),
            "canary example must match docs"
        );
    }
}
