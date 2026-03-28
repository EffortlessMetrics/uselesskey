use std::collections::BTreeMap;

use uselesskey_core::Factory;
use uselesskey_ssh::{CertType, SshCertSpec, SshFactoryExt, SshSpec, SshValidity};

#[test]
fn deterministic_authorized_keys_line_for_ed25519() {
    let fx = Factory::deterministic_from_str("ssh-fixtures");
    let a = fx.ssh_key("deploy", SshSpec::ed25519());
    let b = fx.ssh_key("deploy", SshSpec::ed25519());

    assert_eq!(a.authorized_keys_line(), b.authorized_keys_line());
}

#[test]
fn openssh_private_key_round_trip_parse() {
    let fx = Factory::deterministic_from_str("ssh-fixtures");
    let key = fx.ssh_key("deploy", SshSpec::rsa_2048());

    let parsed = ssh_key::private::PrivateKey::from_openssh(key.openssh_private_key())
        .expect("private key should parse");

    let reencoded = parsed.to_openssh(ssh_key::LineEnding::LF).expect("encode");
    assert_eq!(reencoded.to_string(), key.openssh_private_key());
}

#[test]
fn cert_contains_principals_and_validity() {
    let fx = Factory::deterministic_from_str("ssh-fixtures");

    let mut critical = BTreeMap::new();
    critical.insert("force-command".to_string(), "/usr/bin/deploy".to_string());

    let mut exts = BTreeMap::new();
    exts.insert("permit-pty".to_string(), "".to_string());

    let mut spec = SshCertSpec::new(
        CertType::User,
        vec!["deploy".to_string(), "ops".to_string()],
        SshValidity::new(1_700_000_000, 1_800_000_000),
    );
    spec.critical_options = critical;
    spec.extensions = exts;

    let cert = fx.ssh_cert("deploy-cert", spec);
    let parsed = ssh_key::certificate::Certificate::from_openssh(cert.cert_line()).expect("parse cert");

    assert_eq!(parsed.valid_after(), 1_700_000_000);
    assert_eq!(parsed.valid_before(), 1_800_000_000);
    assert_eq!(parsed.valid_principals().len(), 2);
}
