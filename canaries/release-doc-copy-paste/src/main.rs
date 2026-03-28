#[cfg(feature = "path-deps")]
use uselesskey_path as uselesskey;
#[cfg(feature = "published")]
use uselesskey_pub as uselesskey;

// Dependency snippet copied from README/docs dependency reminders:
// [dev-dependencies]
// uselesskey = { version = "0.5.1", features = ["rsa"] }

use uselesskey::{Factory, RsaFactoryExt, RsaSpec};

fn main() {
    // Quick start snippet copied from README with a deterministic seed for stable assertion.
    let fx = Factory::deterministic_from_str("canary-release-doc-copy-paste");
    let rsa = fx.rsa("issuer", RsaSpec::rs256());

    let pkcs8_pem = rsa.private_key_pkcs8_pem();
    let spki_der = rsa.public_key_spki_der();

    assert!(pkcs8_pem.contains("BEGIN PRIVATE KEY"));
    assert!(!spki_der.is_empty());
}

#[cfg(test)]
mod tests {
    #[test]
    fn quick_start_parity() {
        super::main();
    }
}
