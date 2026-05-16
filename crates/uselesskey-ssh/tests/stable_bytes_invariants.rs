//! Pinned-byte invariants for SSH spec/cert types.
//!
//! These tests freeze the exact stable-bytes encodings used in deterministic
//! derivation. Changing any of these values silently would shift every
//! downstream SSH fixture without bumping a derivation version. Bumping the
//! derivation version is a deliberate act and should be the only reason these
//! tests need to be updated.

use uselesskey_ssh::{SshCertSpec, SshCertType, SshSpec, SshValidity};
use uselesskey_test_support::{TestResult, ensure, ensure_eq};

#[test]
fn ssh_spec_stable_bytes_pin_exact_values_per_variant() -> TestResult<()> {
    ensure_eq!(SshSpec::Ed25519.stable_bytes(), [1u8]);
    ensure_eq!(SshSpec::Rsa.stable_bytes(), [2u8]);
    Ok(())
}

#[test]
fn ssh_spec_stable_bytes_are_pairwise_distinct() -> TestResult<()> {
    let ed = SshSpec::Ed25519.stable_bytes();
    let rsa = SshSpec::Rsa.stable_bytes();
    ensure!(
        ed != rsa,
        "SshSpec variants must have distinct stable_bytes: ed={ed:?} rsa={rsa:?}"
    );
    Ok(())
}

#[test]
fn ssh_cert_type_stable_byte_pins_exact_values() -> TestResult<()> {
    ensure_eq!(SshCertType::User.stable_byte(), 1u8);
    ensure_eq!(SshCertType::Host.stable_byte(), 2u8);
    Ok(())
}

#[test]
fn ssh_cert_type_stable_byte_user_and_host_are_distinct() -> TestResult<()> {
    ensure!(SshCertType::User.stable_byte() != SshCertType::Host.stable_byte());
    Ok(())
}

#[test]
fn ssh_cert_spec_user_defaults_have_empty_options_and_extensions() -> TestResult<()> {
    let spec = SshCertSpec::user(["alice"], SshValidity::new(1, 2));

    ensure_eq!(spec.cert_type, SshCertType::User);
    ensure!(
        spec.critical_options.is_empty(),
        "SshCertSpec::user must default to empty critical_options, got {:?}",
        spec.critical_options
    );
    ensure!(
        spec.extensions.is_empty(),
        "SshCertSpec::user must default to empty extensions, got {:?}",
        spec.extensions
    );
    ensure_eq!(spec.principals, vec!["alice".to_string()]);
    Ok(())
}

#[test]
fn ssh_cert_spec_host_defaults_have_empty_options_and_extensions() -> TestResult<()> {
    let spec = SshCertSpec::host(["host1.internal"], SshValidity::new(1, 2));

    ensure_eq!(spec.cert_type, SshCertType::Host);
    ensure!(
        spec.critical_options.is_empty(),
        "SshCertSpec::host must default to empty critical_options, got {:?}",
        spec.critical_options
    );
    ensure!(
        spec.extensions.is_empty(),
        "SshCertSpec::host must default to empty extensions, got {:?}",
        spec.extensions
    );
    ensure_eq!(spec.principals, vec!["host1.internal".to_string()]);
    Ok(())
}

#[test]
fn ssh_cert_spec_user_and_host_with_same_inputs_differ_only_by_cert_type() -> TestResult<()> {
    let validity = SshValidity::new(100, 200);
    let user = SshCertSpec::user(["alice"], validity);
    let host = SshCertSpec::host(["alice"], validity);

    ensure_eq!(user.principals, host.principals);
    ensure_eq!(user.validity, host.validity);
    ensure_eq!(user.critical_options, host.critical_options);
    ensure_eq!(user.extensions, host.extensions);
    ensure!(user.cert_type != host.cert_type);
    ensure!(user.stable_bytes() != host.stable_bytes());
    Ok(())
}
