//! Demonstrates writing key fixtures to temporary files.
//!
//! Many libraries require file paths instead of in-memory keys (e.g., TLS
//! libraries, CLI tools). This example shows two approaches:
//!
//! 1. **Built-in wrapper methods** (`write_private_key_pkcs8_pem()`, etc.) -
//!    the simplest approach that handles tempfile creation automatically.
//!
//! 2. **Manual tempfile approach** - for custom file naming or when you need
//!    more control over the tempfile lifecycle.
//!
//! # Running this example
//!
//! With RSA (default feature):
//! ```bash
//! cargo run -p uselesskey --example tempfile_paths
//! ```
//!
//! With Ed25519:
//! ```bash
//! cargo run -p uselesskey --example tempfile_paths --features "ed25519"
//! ```
//!
//! With both:
//! ```bash
//! cargo run -p uselesskey --example tempfile_paths --features "rsa,ed25519"
//! ```

#[cfg(any(feature = "rsa", feature = "ed25519"))]
use uselesskey::Factory;

fn main() {
    println!("=== Tempfile Path Examples ===\n");

    #[cfg(any(feature = "rsa", feature = "ed25519"))]
    {
        // Create a factory (random mode for this example)
        let fx = Factory::random();

        #[cfg(feature = "rsa")]
        rsa_example(&fx);

        #[cfg(feature = "ed25519")]
        ed25519_example(&fx);
    }

    #[cfg(not(any(feature = "rsa", feature = "ed25519")))]
    {
        eprintln!("Enable 'rsa' or 'ed25519' feature to run this example.");
        eprintln!("  cargo run -p uselesskey --example tempfile_paths --features rsa");
    }
}

/// RSA example using both built-in wrappers and manual tempfile approach.
#[cfg(feature = "rsa")]
fn rsa_example(fx: &Factory) {
    use std::io::Write;

    use uselesskey::{RsaFactoryExt, RsaSpec};

    println!("--- RSA Key Fixtures ---\n");

    // Generate an RSA keypair
    let keypair = fx.rsa("example-service", RsaSpec::rs256());

    // =========================================================
    // Approach 1: Built-in wrapper methods (recommended)
    // =========================================================
    println!("1. Built-in wrapper methods:");

    // Write private key to a tempfile
    let private_key_file = keypair
        .write_private_key_pkcs8_pem()
        .expect("failed to write private key");

    // Write public key to a tempfile
    let public_key_file = keypair
        .write_public_key_spki_pem()
        .expect("failed to write public key");

    println!("   Private key: {}", private_key_file.path().display());
    println!("   Public key:  {}", public_key_file.path().display());

    // Verify the files exist and contain valid data
    assert!(private_key_file.path().exists());
    assert!(public_key_file.path().exists());

    // Read back and verify content
    let read_back = private_key_file
        .read_to_string()
        .expect("failed to read private key");
    assert!(
        read_back.contains("-----BEGIN PRIVATE KEY-----"),
        "Private key should be PEM formatted"
    );

    let read_back_pub = public_key_file
        .read_to_string()
        .expect("failed to read public key");
    assert!(
        read_back_pub.contains("-----BEGIN PUBLIC KEY-----"),
        "Public key should be PEM formatted"
    );

    println!("   Verified: both files contain valid PEM data\n");

    // =========================================================
    // Approach 2: Manual tempfile creation (for more control)
    // =========================================================
    println!("2. Manual tempfile approach:");

    // Use tempfile crate directly for custom naming or configuration
    let mut manual_file = tempfile::Builder::new()
        .prefix("my-custom-prefix-")
        .suffix(".key.pem")
        .tempfile()
        .expect("failed to create tempfile");

    // Write the PEM content manually
    manual_file
        .write_all(keypair.private_key_pkcs8_pem().as_bytes())
        .expect("failed to write to tempfile");
    manual_file.flush().expect("failed to flush");

    println!("   Custom tempfile: {}", manual_file.path().display());

    // Read back to verify
    let manual_content = std::fs::read_to_string(manual_file.path()).expect("failed to read back");
    assert!(manual_content.contains("-----BEGIN PRIVATE KEY-----"));

    println!("   Verified: custom tempfile contains valid PEM data\n");

    // Files are automatically cleaned up when they go out of scope
    // (both TempArtifact and NamedTempFile implement Drop)
}

/// Ed25519 example using built-in wrappers.
#[cfg(feature = "ed25519")]
fn ed25519_example(fx: &Factory) {
    use uselesskey::{Ed25519FactoryExt, Ed25519Spec};

    println!("--- Ed25519 Key Fixtures ---\n");

    // Generate an Ed25519 keypair
    let keypair = fx.ed25519("signing-key", Ed25519Spec::default());

    // Write to tempfiles using built-in methods
    let private_key_file = keypair
        .write_private_key_pkcs8_pem()
        .expect("failed to write private key");

    let public_key_file = keypair
        .write_public_key_spki_pem()
        .expect("failed to write public key");

    println!("   Private key: {}", private_key_file.path().display());
    println!("   Public key:  {}", public_key_file.path().display());

    // Verify
    let priv_content = private_key_file
        .read_to_string()
        .expect("failed to read private key");
    let pub_content = public_key_file
        .read_to_string()
        .expect("failed to read public key");

    assert!(priv_content.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(pub_content.contains("-----BEGIN PUBLIC KEY-----"));

    println!("   Verified: both files contain valid PEM data\n");
}
