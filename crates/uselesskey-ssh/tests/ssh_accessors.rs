use ssh_key::{Certificate, PrivateKey};
use uselesskey_core::Factory;
use uselesskey_ssh::{SshCertFactoryExt, SshCertSpec, SshFactoryExt, SshSpec, SshValidity};

#[test]
fn key_pair_getters_return_label_and_spec() {
    let fx = Factory::deterministic_from_str("ssh-accessor-seed");
    let key = fx.ssh_key("deploy", SshSpec::ed25519());

    assert_eq!(key.label(), "deploy");
    assert_eq!(key.spec(), SshSpec::Ed25519);
}

#[test]
fn key_pair_debug_omits_key_material() {
    let fx = Factory::deterministic_from_str("ssh-debug-seed");
    let key = fx.ssh_key("deploy", SshSpec::ed25519());

    let dbg = format!("{key:?}");
    assert!(dbg.contains("SshKeyPair"));
    assert!(dbg.contains("deploy"));
    assert!(!dbg.contains(key.private_key_openssh()));
}

#[test]
fn key_pair_private_key_is_openssh_pem() {
    let fx = Factory::deterministic_from_str("ssh-pem-seed");
    let key = fx.ssh_key("deploy", SshSpec::ed25519());

    let pem = key.private_key_openssh();
    assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    assert!(pem.contains("-----END OPENSSH PRIVATE KEY-----"));
}

#[test]
fn key_pair_authorized_key_line_has_algorithm_prefix() {
    let fx = Factory::deterministic_from_str("ssh-authz-line-seed");

    let ed = fx.ssh_key("ed", SshSpec::ed25519());
    assert!(ed.authorized_key_line().starts_with("ssh-ed25519 "));

    let rsa = fx.ssh_key("rsa", SshSpec::rsa());
    assert!(rsa.authorized_key_line().starts_with("ssh-rsa "));
}

#[test]
fn different_specs_produce_different_keys() {
    let fx = Factory::deterministic_from_str("ssh-spec-diff-seed");
    let ed = fx.ssh_key("same-label", SshSpec::ed25519());
    let rsa = fx.ssh_key("same-label", SshSpec::rsa());

    assert_ne!(ed.private_key_openssh(), rsa.private_key_openssh());
    assert_ne!(ed.authorized_key_line(), rsa.authorized_key_line());
}

#[test]
fn cert_fixture_getters_return_label_and_spec() {
    let fx = Factory::deterministic_from_str("ssh-cert-accessor-seed");
    let spec = SshCertSpec::user(["alice"], SshValidity::new(0, 100));
    let cert = fx.ssh_cert("cert-label", spec.clone());

    assert_eq!(cert.label(), "cert-label");
    assert_eq!(cert.spec(), &spec);
}

#[test]
fn cert_fixture_debug_omits_key_material() {
    let fx = Factory::deterministic_from_str("ssh-cert-debug-seed");
    let spec = SshCertSpec::user(["alice"], SshValidity::new(0, 100));
    let cert = fx.ssh_cert("cert-label", spec);

    let dbg = format!("{cert:?}");
    assert!(dbg.contains("SshCertFixture"));
    assert!(dbg.contains("cert-label"));
    assert!(!dbg.contains(cert.private_key_openssh()));
}

#[test]
fn cert_fixture_private_key_is_openssh_pem() {
    let fx = Factory::deterministic_from_str("ssh-cert-pem-seed");
    let spec = SshCertSpec::user(["alice"], SshValidity::new(0, 100));
    let cert = fx.ssh_cert("cert-pem", spec);

    let pem = cert.private_key_openssh();
    assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));

    PrivateKey::from_openssh(pem).expect("cert private key fixture must parse");
}

#[test]
fn cert_fixture_certificate_helper_matches_openssh() {
    let fx = Factory::deterministic_from_str("ssh-cert-helper-seed");
    let spec = SshCertSpec::user(["alice"], SshValidity::new(0, 100));
    let cert_fx = fx.ssh_cert("cert", spec);

    let from_helper = cert_fx.certificate();
    let from_string = Certificate::from_openssh(cert_fx.certificate_openssh()).unwrap();

    assert_eq!(
        from_helper.to_openssh().unwrap(),
        from_string.to_openssh().unwrap()
    );
}

#[test]
fn cert_with_no_principals_marks_all_valid() {
    let fx = Factory::deterministic_from_str("ssh-cert-empty-seed");
    let spec = SshCertSpec::user(std::iter::empty::<&str>(), SshValidity::new(0, 100));
    let cert = fx.ssh_cert("any-principal", spec).certificate();

    assert!(cert.valid_principals().is_empty());
}

#[test]
fn cert_with_different_validity_produces_different_material() {
    let fx = Factory::deterministic_from_str("ssh-cert-validity-seed");
    let a = fx
        .ssh_cert(
            "label",
            SshCertSpec::user(["alice"], SshValidity::new(0, 100)),
        )
        .certificate_openssh()
        .to_string();
    let b = fx
        .ssh_cert(
            "label",
            SshCertSpec::user(["alice"], SshValidity::new(0, 200)),
        )
        .certificate_openssh()
        .to_string();
    assert_ne!(a, b);
}
