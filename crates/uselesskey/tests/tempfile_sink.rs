//! Integration tests for tempfile/sink functionality across all key types.
//!
//! Tests every `write_*` method on RSA, ECDSA, Ed25519, HMAC, Token, X.509
//! key fixtures, verifying content round-trips and cleanup-on-drop.

mod testutil;

use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;
use std::thread::JoinHandle;

use uselesskey::prelude::*;
use uselesskey_test_support::{TestError, TestResult, require_ok, require_some};

trait TestContext<T> {
    fn test_context(self, message: impl fmt::Display) -> TestResult<T>;
}

impl<T, E: fmt::Display> TestContext<T> for Result<T, E> {
    fn test_context(self, message: impl fmt::Display) -> TestResult<T> {
        require_ok(self, message)
    }
}

impl<T> TestContext<T> for Option<T> {
    fn test_context(self, message: impl fmt::Display) -> TestResult<T> {
        require_some(self, message)
    }
}

trait JoinTestContext<T> {
    fn join_test(self, message: impl fmt::Display) -> TestResult<T>;
}

impl<T> JoinTestContext<T> for JoinHandle<TestResult<T>> {
    fn join_test(self, message: impl fmt::Display) -> TestResult<T> {
        self.join()
            .map_err(|_| TestError(format!("{message}: worker thread panicked")))?
    }
}

fn fx() -> Factory {
    testutil::fx()
}

// ===========================================================================
// RSA tempfile writes
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_write_private_key_pkcs8_pem_round_trip() -> TestResult<()> {
    let kp = fx().rsa("sink-rsa-priv", RsaSpec::rs256());
    let temp = kp
        .write_private_key_pkcs8_pem()
        .test_context("write private PKCS#8 PEM tempfile")?;

    assert!(temp.path().exists());
    let content = temp
        .read_to_string()
        .test_context("read tempfile as UTF-8")?;
    assert_eq!(content, kp.private_key_pkcs8_pem());
    assert!(content.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(content.contains("-----END PRIVATE KEY-----"));

    let filename = temp
        .path()
        .file_name()
        .test_context("read tempfile filename")?
        .to_string_lossy();
    assert!(filename.ends_with(".pkcs8.pem"), "filename: {filename}");
    Ok(())
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_write_public_key_spki_pem_round_trip() -> TestResult<()> {
    let kp = fx().rsa("sink-rsa-pub", RsaSpec::rs256());
    let temp = kp
        .write_public_key_spki_pem()
        .test_context("write public SPKI PEM tempfile")?;

    assert!(temp.path().exists());
    let content = temp
        .read_to_string()
        .test_context("read tempfile as UTF-8")?;
    assert_eq!(content, kp.public_key_spki_pem());
    assert!(content.contains("-----BEGIN PUBLIC KEY-----"));

    let filename = temp
        .path()
        .file_name()
        .test_context("read tempfile filename")?
        .to_string_lossy();
    assert!(filename.ends_with(".spki.pem"), "filename: {filename}");
    Ok(())
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_tempfile_paths_unique_across_invocations() -> TestResult<()> {
    let kp = fx().rsa("sink-rsa-uniq", RsaSpec::rs256());
    let a = kp
        .write_private_key_pkcs8_pem()
        .test_context("write private PKCS#8 PEM tempfile")?;
    let b = kp
        .write_private_key_pkcs8_pem()
        .test_context("write private PKCS#8 PEM tempfile")?;
    assert_ne!(a.path(), b.path(), "each call produces a new tempfile");
    Ok(())
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_private_and_public_tempfiles_coexist() -> TestResult<()> {
    let kp = fx().rsa("sink-rsa-both", RsaSpec::rs256());
    let priv_temp = kp
        .write_private_key_pkcs8_pem()
        .test_context("write private PKCS#8 PEM tempfile")?;
    let pub_temp = kp
        .write_public_key_spki_pem()
        .test_context("write public SPKI PEM tempfile")?;

    assert_ne!(priv_temp.path(), pub_temp.path());
    assert!(priv_temp.path().exists());
    assert!(pub_temp.path().exists());
    assert!(
        priv_temp
            .read_to_string()
            .test_context("read tempfile as UTF-8")?
            .contains("PRIVATE KEY")
    );
    assert!(
        pub_temp
            .read_to_string()
            .test_context("read tempfile as UTF-8")?
            .contains("PUBLIC KEY")
    );
    Ok(())
}

// ===========================================================================
// ECDSA tempfile writes
// ===========================================================================

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_write_private_key_pkcs8_pem_round_trip() -> TestResult<()> {
    let kp = fx().ecdsa("sink-ec-priv", EcdsaSpec::es256());
    let temp = kp
        .write_private_key_pkcs8_pem()
        .test_context("write private PKCS#8 PEM tempfile")?;

    assert!(temp.path().exists());
    let content = temp
        .read_to_string()
        .test_context("read tempfile as UTF-8")?;
    assert_eq!(content, kp.private_key_pkcs8_pem());
    assert!(content.contains("-----BEGIN PRIVATE KEY-----"));
    Ok(())
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_write_public_key_spki_pem_round_trip() -> TestResult<()> {
    let kp = fx().ecdsa("sink-ec-pub", EcdsaSpec::es256());
    let temp = kp
        .write_public_key_spki_pem()
        .test_context("write public SPKI PEM tempfile")?;

    assert!(temp.path().exists());
    let content = temp
        .read_to_string()
        .test_context("read tempfile as UTF-8")?;
    assert_eq!(content, kp.public_key_spki_pem());
    assert!(content.contains("-----BEGIN PUBLIC KEY-----"));
    Ok(())
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_es384_tempfile_round_trip() -> TestResult<()> {
    let kp = fx().ecdsa("sink-ec384", EcdsaSpec::es384());
    let temp = kp
        .write_private_key_pkcs8_pem()
        .test_context("write private PKCS#8 PEM tempfile")?;
    assert_eq!(
        temp.read_to_string()
            .test_context("read tempfile as UTF-8")?,
        kp.private_key_pkcs8_pem()
    );
    Ok(())
}

// ===========================================================================
// Ed25519 tempfile writes
// ===========================================================================

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_write_private_key_pkcs8_pem_round_trip() -> TestResult<()> {
    let kp = fx().ed25519("sink-ed-priv", Ed25519Spec::new());
    let temp = kp
        .write_private_key_pkcs8_pem()
        .test_context("write private PKCS#8 PEM tempfile")?;

    assert!(temp.path().exists());
    let content = temp
        .read_to_string()
        .test_context("read tempfile as UTF-8")?;
    assert_eq!(content, kp.private_key_pkcs8_pem());
    assert!(content.contains("-----BEGIN PRIVATE KEY-----"));
    Ok(())
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_write_public_key_spki_pem_round_trip() -> TestResult<()> {
    let kp = fx().ed25519("sink-ed-pub", Ed25519Spec::new());
    let temp = kp
        .write_public_key_spki_pem()
        .test_context("write public SPKI PEM tempfile")?;

    assert!(temp.path().exists());
    let content = temp
        .read_to_string()
        .test_context("read tempfile as UTF-8")?;
    assert_eq!(content, kp.public_key_spki_pem());
    assert!(content.contains("-----BEGIN PUBLIC KEY-----"));
    Ok(())
}

// ===========================================================================
// X.509 tempfile writes (certificates for TLS)
// ===========================================================================

#[test]
#[cfg(feature = "x509")]
fn x509_write_cert_pem_round_trip() -> TestResult<()> {
    let cert = fx().x509_self_signed("sink-x509-cert", X509Spec::self_signed("sink.example.com"));
    let temp = cert
        .write_cert_pem()
        .test_context("write certificate PEM tempfile")?;

    assert!(temp.path().exists());
    let content = temp
        .read_to_string()
        .test_context("read tempfile as UTF-8")?;
    assert_eq!(content, cert.cert_pem());
    assert!(content.contains("-----BEGIN CERTIFICATE-----"));

    let filename = temp
        .path()
        .file_name()
        .test_context("read tempfile filename")?
        .to_string_lossy();
    assert!(filename.ends_with(".crt.pem"), "filename: {filename}");
    Ok(())
}

#[test]
#[cfg(feature = "x509")]
fn x509_write_cert_der_round_trip() -> TestResult<()> {
    let cert = fx().x509_self_signed("sink-x509-der", X509Spec::self_signed("sink.example.com"));
    let temp = cert
        .write_cert_der()
        .test_context("write certificate DER tempfile")?;

    assert!(temp.path().exists());
    let content = temp.read_to_bytes().test_context("read tempfile bytes")?;
    assert_eq!(content, cert.cert_der());
    assert_eq!(content[0], 0x30, "DER starts with SEQUENCE tag");

    let filename = temp
        .path()
        .file_name()
        .test_context("read tempfile filename")?
        .to_string_lossy();
    assert!(filename.ends_with(".crt.der"), "filename: {filename}");
    Ok(())
}

#[test]
#[cfg(feature = "x509")]
fn x509_write_private_key_pem_round_trip() -> TestResult<()> {
    let cert = fx().x509_self_signed("sink-x509-key", X509Spec::self_signed("sink.example.com"));
    let temp = cert
        .write_private_key_pem()
        .test_context("write X.509 private-key PEM tempfile")?;

    assert!(temp.path().exists());
    let content = temp
        .read_to_string()
        .test_context("read tempfile as UTF-8")?;
    assert_eq!(content, cert.private_key_pkcs8_pem());
    assert!(content.contains("-----BEGIN PRIVATE KEY-----"));

    let filename = temp
        .path()
        .file_name()
        .test_context("read tempfile filename")?
        .to_string_lossy();
    assert!(filename.ends_with(".key.pem"), "filename: {filename}");
    Ok(())
}

#[test]
#[cfg(feature = "x509")]
fn x509_write_identity_pem_contains_cert_and_key() -> TestResult<()> {
    let cert = fx().x509_self_signed("sink-x509-id", X509Spec::self_signed("sink.example.com"));
    let temp = cert
        .write_identity_pem()
        .test_context("write X.509 identity PEM tempfile")?;

    assert!(temp.path().exists());
    let content = temp
        .read_to_string()
        .test_context("read tempfile as UTF-8")?;
    assert!(content.contains("-----BEGIN CERTIFICATE-----"));
    assert!(content.contains("-----BEGIN PRIVATE KEY-----"));

    let filename = temp
        .path()
        .file_name()
        .test_context("read tempfile filename")?
        .to_string_lossy();
    assert!(filename.ends_with(".identity.pem"), "filename: {filename}");
    Ok(())
}

#[test]
#[cfg(feature = "x509")]
fn x509_all_tempfile_paths_are_unique() -> TestResult<()> {
    let cert = fx().x509_self_signed(
        "sink-x509-unique",
        X509Spec::self_signed("sink.example.com"),
    );
    let paths: HashSet<PathBuf> = [
        cert.write_cert_pem()
            .test_context("write certificate PEM tempfile")?
            .path()
            .to_path_buf(),
        cert.write_cert_der()
            .test_context("write certificate DER tempfile")?
            .path()
            .to_path_buf(),
        cert.write_private_key_pem()
            .test_context("write X.509 private-key PEM tempfile")?
            .path()
            .to_path_buf(),
        cert.write_identity_pem()
            .test_context("write X.509 identity PEM tempfile")?
            .path()
            .to_path_buf(),
    ]
    .into_iter()
    .collect();

    assert_eq!(paths.len(), 4, "each tempfile must have a unique path");
    Ok(())
}

// ===========================================================================
// X.509 chain tempfile writes
// ===========================================================================

#[test]
#[cfg(feature = "x509")]
fn x509_chain_write_leaf_cert_pem() -> TestResult<()> {
    let chain = fx().x509_chain("sink-chain", ChainSpec::new("leaf.example.com"));
    let temp = chain
        .write_leaf_cert_pem()
        .test_context("write leaf certificate PEM tempfile")?;

    assert!(temp.path().exists());
    let content = temp
        .read_to_string()
        .test_context("read tempfile as UTF-8")?;
    assert_eq!(content, chain.leaf_cert_pem());
    assert!(content.contains("-----BEGIN CERTIFICATE-----"));
    Ok(())
}

#[test]
#[cfg(feature = "x509")]
fn x509_chain_write_leaf_cert_der() -> TestResult<()> {
    let chain = fx().x509_chain("sink-chain-der", ChainSpec::new("leaf.example.com"));
    let temp = chain
        .write_leaf_cert_der()
        .test_context("write leaf certificate DER tempfile")?;

    assert!(temp.path().exists());
    assert_eq!(
        temp.read_to_bytes().test_context("read tempfile bytes")?,
        chain.leaf_cert_der()
    );
    Ok(())
}

#[test]
#[cfg(feature = "x509")]
fn x509_chain_write_chain_pem() -> TestResult<()> {
    let chain = fx().x509_chain("sink-chain-chain", ChainSpec::new("leaf.example.com"));
    let temp = chain
        .write_chain_pem()
        .test_context("write certificate-chain PEM tempfile")?;

    let content = temp
        .read_to_string()
        .test_context("read tempfile as UTF-8")?;
    // Chain PEM should contain multiple certificates
    let cert_count = content.matches("-----BEGIN CERTIFICATE-----").count();
    assert!(
        cert_count >= 2,
        "chain PEM should have at least 2 certs, got {cert_count}"
    );
    Ok(())
}

#[test]
#[cfg(feature = "x509")]
fn x509_chain_write_full_chain_pem() -> TestResult<()> {
    let chain = fx().x509_chain("sink-chain-full", ChainSpec::new("leaf.example.com"));
    let temp = chain
        .write_full_chain_pem()
        .test_context("write full certificate-chain PEM tempfile")?;

    let content = temp
        .read_to_string()
        .test_context("read tempfile as UTF-8")?;
    let cert_count = content.matches("-----BEGIN CERTIFICATE-----").count();
    assert!(
        cert_count >= 3,
        "full chain PEM should have at least 3 certs (leaf+intermediate+root), got {cert_count}"
    );
    Ok(())
}

#[test]
#[cfg(feature = "x509")]
fn x509_chain_write_root_cert_pem() -> TestResult<()> {
    let chain = fx().x509_chain("sink-chain-root", ChainSpec::new("leaf.example.com"));
    let temp = chain
        .write_root_cert_pem()
        .test_context("write root certificate PEM tempfile")?;

    let content = temp
        .read_to_string()
        .test_context("read tempfile as UTF-8")?;
    assert_eq!(content, chain.root_cert_pem());
    assert!(content.contains("-----BEGIN CERTIFICATE-----"));
    Ok(())
}

#[test]
#[cfg(feature = "x509")]
fn x509_chain_write_leaf_private_key_pem() -> TestResult<()> {
    let chain = fx().x509_chain("sink-chain-key", ChainSpec::new("leaf.example.com"));
    let temp = chain
        .write_leaf_private_key_pem()
        .test_context("write leaf private-key PEM tempfile")?;

    let content = temp
        .read_to_string()
        .test_context("read tempfile as UTF-8")?;
    assert_eq!(content, chain.leaf_private_key_pkcs8_pem());
    assert!(content.contains("-----BEGIN PRIVATE KEY-----"));
    Ok(())
}

// ===========================================================================
// Tempfiles for TLS configuration scenario
// ===========================================================================

#[test]
#[cfg(feature = "x509")]
fn x509_tempfiles_for_tls_config() -> TestResult<()> {
    let cert = fx().x509_self_signed("tls-server", X509Spec::self_signed("localhost"));

    // A typical TLS setup needs cert + key as files
    let cert_file = cert
        .write_cert_pem()
        .test_context("write certificate PEM tempfile")?;
    let key_file = cert
        .write_private_key_pem()
        .test_context("write X.509 private-key PEM tempfile")?;

    // Both files exist and have content
    assert!(cert_file.path().exists());
    assert!(key_file.path().exists());

    let cert_content = cert_file
        .read_to_string()
        .test_context("read tempfile as UTF-8")?;
    let key_content = key_file
        .read_to_string()
        .test_context("read tempfile as UTF-8")?;

    assert!(cert_content.contains("CERTIFICATE"));
    assert!(key_content.contains("PRIVATE KEY"));

    // Paths are different
    assert_ne!(cert_file.path(), key_file.path());
    Ok(())
}

// ===========================================================================
// Cleanup verification across key types
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_tempfile_cleaned_up_on_drop() -> TestResult<()> {
    let path = {
        let kp = fx().rsa("sink-rsa-drop", RsaSpec::rs256());
        let temp = kp
            .write_private_key_pkcs8_pem()
            .test_context("write private PKCS#8 PEM tempfile")?;
        let p = temp.path().to_path_buf();
        assert!(p.exists());
        p
    };
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(!path.exists(), "RSA tempfile should be cleaned up on drop");
    Ok(())
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_tempfile_cleaned_up_on_drop() -> TestResult<()> {
    let path = {
        let kp = fx().ecdsa("sink-ec-drop", EcdsaSpec::es256());
        let temp = kp
            .write_private_key_pkcs8_pem()
            .test_context("write private PKCS#8 PEM tempfile")?;
        let p = temp.path().to_path_buf();
        assert!(p.exists());
        p
    };
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(
        !path.exists(),
        "ECDSA tempfile should be cleaned up on drop"
    );
    Ok(())
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_tempfile_cleaned_up_on_drop() -> TestResult<()> {
    let path = {
        let kp = fx().ed25519("sink-ed-drop", Ed25519Spec::new());
        let temp = kp
            .write_private_key_pkcs8_pem()
            .test_context("write private PKCS#8 PEM tempfile")?;
        let p = temp.path().to_path_buf();
        assert!(p.exists());
        p
    };
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(
        !path.exists(),
        "Ed25519 tempfile should be cleaned up on drop"
    );
    Ok(())
}

#[test]
#[cfg(feature = "x509")]
fn x509_tempfile_cleaned_up_on_drop() -> TestResult<()> {
    let paths: Vec<PathBuf> = {
        let cert =
            fx().x509_self_signed("sink-x509-drop", X509Spec::self_signed("drop.example.com"));
        let cert_pem = cert
            .write_cert_pem()
            .test_context("write certificate PEM tempfile")?;
        let cert_der = cert
            .write_cert_der()
            .test_context("write certificate DER tempfile")?;
        let key_pem = cert
            .write_private_key_pem()
            .test_context("write X.509 private-key PEM tempfile")?;
        let identity = cert
            .write_identity_pem()
            .test_context("write X.509 identity PEM tempfile")?;
        vec![
            cert_pem.path().to_path_buf(),
            cert_der.path().to_path_buf(),
            key_pem.path().to_path_buf(),
            identity.path().to_path_buf(),
        ]
    };
    std::thread::sleep(std::time::Duration::from_millis(50));
    for p in &paths {
        assert!(
            !p.exists(),
            "X.509 tempfile should be cleaned up on drop: {p:?}"
        );
    }
    Ok(())
}

// ===========================================================================
// Concurrent tempfile writes from multiple threads (all key types)
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_concurrent_tempfile_writes() -> TestResult<()> {
    let factory = fx();
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let fx = factory.clone();
            std::thread::spawn(move || -> TestResult<_> {
                let label = format!("sink-rsa-conc-{i}");
                let kp = fx.rsa(&label, RsaSpec::rs256());
                let priv_temp = kp
                    .write_private_key_pkcs8_pem()
                    .test_context("write concurrent RSA private-key tempfile")?;
                let pub_temp = kp
                    .write_public_key_spki_pem()
                    .test_context("write concurrent RSA public-key tempfile")?;
                assert!(priv_temp.path().exists());
                assert!(pub_temp.path().exists());
                Ok((
                    priv_temp.path().to_path_buf(),
                    pub_temp.path().to_path_buf(),
                    priv_temp,
                    pub_temp,
                ))
            })
        })
        .collect();

    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join_test("join concurrent RSA tempfile worker"))
        .collect::<TestResult<_>>()?;
    let all_paths: HashSet<_> = results
        .iter()
        .flat_map(|(a, b, _, _)| [a.clone(), b.clone()])
        .collect();

    assert_eq!(
        all_paths.len(),
        8,
        "all concurrent tempfile paths must be unique"
    );
    Ok(())
}

#[test]
#[cfg(all(feature = "ecdsa", feature = "ed25519"))]
fn mixed_key_types_concurrent_tempfile_writes() -> TestResult<()> {
    let factory = fx();

    let ec_handle = {
        let fx = factory.clone();
        std::thread::spawn(move || -> TestResult<_> {
            let kp = fx.ecdsa("sink-mixed-ec", EcdsaSpec::es256());
            let temp = kp
                .write_private_key_pkcs8_pem()
                .test_context("write concurrent ECDSA private-key tempfile")?;
            Ok((temp.path().to_path_buf(), temp))
        })
    };

    let ed_handle = {
        let fx = factory.clone();
        std::thread::spawn(move || -> TestResult<_> {
            let kp = fx.ed25519("sink-mixed-ed", Ed25519Spec::new());
            let temp = kp
                .write_private_key_pkcs8_pem()
                .test_context("write concurrent Ed25519 private-key tempfile")?;
            Ok((temp.path().to_path_buf(), temp))
        })
    };

    let (ec_path, _ec_temp) = ec_handle.join_test("join ECDSA tempfile worker")?;
    let (ed_path, _ed_temp) = ed_handle.join_test("join Ed25519 tempfile worker")?;

    assert_ne!(
        ec_path, ed_path,
        "different key type tempfiles must be distinct"
    );
    Ok(())
}

// ===========================================================================
// Direct TempArtifact usage (re-exported from facade)
// ===========================================================================

#[test]
fn temp_artifact_reexported_from_facade() -> TestResult<()> {
    let temp = TempArtifact::new_string("uk-facade-", ".pem", "facade-test-data")
        .test_context("create string-backed tempfile artifact")?;
    assert!(temp.path().exists());
    assert_eq!(
        temp.read_to_string()
            .test_context("read tempfile as UTF-8")?,
        "facade-test-data"
    );
    Ok(())
}

#[test]
fn temp_artifact_debug_does_not_leak() -> TestResult<()> {
    let temp = TempArtifact::new_string("uk-facade-", ".pem", "SUPER_SECRET_KEY_MATERIAL")
        .test_context("create string-backed tempfile artifact")?;
    let dbg = format!("{temp:?}");
    assert!(dbg.contains("TempArtifact"));
    assert!(
        !dbg.contains("SUPER_SECRET_KEY_MATERIAL"),
        "debug must not leak key content"
    );
    Ok(())
}
