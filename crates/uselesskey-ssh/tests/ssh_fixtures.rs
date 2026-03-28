use ssh_key::{Certificate, PrivateKey, PublicKey};
use uselesskey_core::Factory;
use uselesskey_ssh::{
    SshCertSpec, SshCertType, SshCertValidity, SshFactoryExt, SshSpec,
};

#[test]
fn round_trip_parse_openssh_keys() {
    let fx = Factory::deterministic_from_str("ssh-roundtrip-seed");

    for spec in [SshSpec::ed25519(), SshSpec::rsa()] {
        let key = fx.ssh_key("deploy", spec);

        let parsed_private = PrivateKey::from_openssh(key.private_key_openssh())
            .expect("private key fixture must parse");
        let parsed_public = PublicKey::from_openssh(key.authorized_keys_line())
            .expect("authorized_keys line must parse");

        assert_eq!(
            parsed_private
                .public_key()
                .to_openssh()
                .expect("public key encoding must succeed"),
            parsed_public
                .to_openssh()
                .expect("public key encoding must succeed")
        );
    }
}

#[test]
fn authorized_keys_lines_are_deterministic() {
    let fx_a = Factory::deterministic_from_str("ssh-authz-seed");
    let fx_b = Factory::deterministic_from_str("ssh-authz-seed");

    let a = fx_a.ssh_key("host-a", SshSpec::ed25519());
    let b = fx_b.ssh_key("host-a", SshSpec::ed25519());
    let c = fx_a.ssh_key("host-b", SshSpec::ed25519());

    assert_eq!(a.authorized_keys_line(), b.authorized_keys_line());
    assert_ne!(a.authorized_keys_line(), c.authorized_keys_line());
}

#[test]
fn cert_principals_and_validity_match_spec() {
    let fx = Factory::deterministic_from_str("ssh-cert-seed");

    let spec = SshCertSpec {
        principals: vec!["deploy".to_string(), "ci".to_string()],
        validity: SshCertValidity::new(1_700_000_000, 1_800_000_000),
        cert_type: SshCertType::User,
        critical_options: vec![("force-command".to_string(), "/usr/bin/deploy".to_string())],
        extensions: vec![("permit-pty".to_string(), "".to_string())],
        subject_key: SshSpec::ed25519(),
        ca_key: SshSpec::ed25519(),
    };

    let cert_fx = fx.ssh_cert("deploy-cert", spec.clone());
    let parsed = Certificate::from_openssh(cert_fx.certificate_openssh())
        .expect("certificate fixture must parse");

    assert_eq!(parsed.valid_principals(), spec.principals.as_slice());
    assert_eq!(parsed.valid_after(), spec.validity.valid_after);
    assert_eq!(parsed.valid_before(), spec.validity.valid_before);
    assert_eq!(parsed.cert_type(), ssh_key::certificate::CertType::User);

    let force_command = parsed
        .critical_options()
        .iter()
        .find(|(k, _)| *k == "force-command")
        .map(|(_, v)| v.as_str());
    assert_eq!(force_command, Some("/usr/bin/deploy"));

    let permit_pty = parsed
        .extensions()
        .iter()
        .find(|(k, _)| *k == "permit-pty")
        .map(|(_, v)| v.as_str());
    assert_eq!(permit_pty, Some(""));
}
