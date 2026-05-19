use ssh_key::{Certificate, PrivateKey, PublicKey, certificate::CertType};
use uselesskey_core::Factory;
use uselesskey_ssh::{
    SshCertFactoryExt, SshCertSpec, SshCertType, SshFactoryExt, SshSpec, SshValidity,
};
use uselesskey_test_support::{TestResult, ensure, ensure_eq, require_ok};

#[test]
fn round_trip_parse_openssh_keys() {
    let fx = Factory::deterministic_from_str("ssh-roundtrip-seed");

    for spec in [SshSpec::ed25519(), SshSpec::rsa()] {
        let key = fx.ssh_key("deploy", spec);

        let parsed_private = PrivateKey::from_openssh(key.private_key_openssh())
            .expect("private key fixture must parse");
        let parsed_public = PublicKey::from_openssh(key.authorized_key_line())
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

    assert_eq!(a.authorized_key_line(), b.authorized_key_line());
    assert_ne!(a.authorized_key_line(), c.authorized_key_line());
}

#[test]
fn cert_principals_and_validity_match_spec() {
    let fx = Factory::deterministic_from_str("ssh-cert-seed");

    let spec = SshCertSpec {
        principals: vec!["deploy".to_string(), "ci".to_string()],
        validity: SshValidity::new(1_700_000_000, 1_800_000_000),
        cert_type: SshCertType::User,
        critical_options: vec![("force-command".to_string(), "/usr/bin/deploy".to_string())],
        extensions: vec![("permit-pty".to_string(), "".to_string())],
    };

    let cert_fx = fx.ssh_cert("deploy-cert", spec.clone());
    let parsed = Certificate::from_openssh(cert_fx.certificate_openssh())
        .expect("certificate fixture must parse");

    assert_eq!(parsed.valid_principals(), spec.principals.as_slice());
    assert_eq!(parsed.valid_after(), spec.validity.valid_after);
    assert_eq!(parsed.valid_before(), spec.validity.valid_before);
    assert_eq!(parsed.cert_type(), CertType::User);

    let force_command = parsed
        .critical_options()
        .get("force-command")
        .map(String::as_str);
    assert_eq!(force_command, Some("/usr/bin/deploy"));

    let permit_pty = parsed.extensions().get("permit-pty").map(String::as_str);
    assert_eq!(permit_pty, Some(""));
}

#[test]
fn host_cert_decodes_with_host_cert_type() -> TestResult<()> {
    let fx = Factory::deterministic_from_str("ssh-host-cert-seed");
    let spec = SshCertSpec::host(
        ["host1.internal", "host2.internal"],
        SshValidity::new(1_700_000_000, 1_700_001_000),
    );

    let cert_fx = fx.ssh_cert("host-cert", spec.clone());
    let parsed = require_ok(
        Certificate::from_openssh(cert_fx.certificate_openssh()),
        "host certificate fixture must parse",
    )?;

    ensure_eq!(parsed.cert_type(), CertType::Host);
    ensure_eq!(
        parsed.valid_principals(),
        &["host1.internal".to_string(), "host2.internal".to_string()][..]
    );
    ensure_eq!(parsed.valid_after(), spec.validity.valid_after);
    ensure_eq!(parsed.valid_before(), spec.validity.valid_before);
    Ok(())
}

#[test]
fn empty_principals_yields_all_principals_valid() -> TestResult<()> {
    let fx = Factory::deterministic_from_str("ssh-empty-principals-seed");
    let spec = SshCertSpec {
        principals: Vec::new(),
        validity: SshValidity::new(1_700_000_000, 1_700_000_300),
        cert_type: SshCertType::User,
        critical_options: Vec::new(),
        extensions: Vec::new(),
    };

    let cert_fx = fx.ssh_cert("anyone", spec);
    let parsed = require_ok(
        Certificate::from_openssh(cert_fx.certificate_openssh()),
        "empty-principals certificate fixture must parse",
    )?;

    ensure!(
        parsed.valid_principals().is_empty(),
        "an empty principals list must encode 'all principals valid', got {:?}",
        parsed.valid_principals()
    );
    Ok(())
}

#[test]
fn key_pair_accessors_report_label_and_spec() -> TestResult<()> {
    let fx = Factory::deterministic_from_str("ssh-key-accessors-seed");
    let key = fx.ssh_key("my-deploy", SshSpec::ed25519());

    ensure_eq!(key.label(), "my-deploy");
    ensure_eq!(key.spec(), SshSpec::Ed25519);

    let rsa_key = fx.ssh_key("my-rsa", SshSpec::rsa());
    ensure_eq!(rsa_key.label(), "my-rsa");
    ensure_eq!(rsa_key.spec(), SshSpec::Rsa);
    Ok(())
}

#[test]
fn cert_fixture_accessors_report_label_and_spec() -> TestResult<()> {
    let fx = Factory::deterministic_from_str("ssh-cert-accessors-seed");
    let spec = SshCertSpec::user(["alice"], SshValidity::new(1_700_000_000, 1_700_000_600));
    let cert_fx = fx.ssh_cert("alice-cert", spec.clone());

    ensure_eq!(cert_fx.label(), "alice-cert");
    ensure_eq!(cert_fx.spec(), &spec);
    Ok(())
}

#[test]
fn ssh_spec_default_is_ed25519() -> TestResult<()> {
    ensure_eq!(SshSpec::default(), SshSpec::Ed25519);
    ensure_eq!(SshCertType::default(), SshCertType::User);
    Ok(())
}

#[test]
fn ssh_cert_type_stable_byte_distinguishes_variants() -> TestResult<()> {
    ensure!(SshCertType::User.stable_byte() != SshCertType::Host.stable_byte());
    Ok(())
}

#[test]
fn key_pair_debug_omits_key_material() -> TestResult<()> {
    let fx = Factory::deterministic_from_str("ssh-debug-seed");
    let key = fx.ssh_key("debug-host", SshSpec::ed25519());
    let dbg = format!("{key:?}");

    ensure!(dbg.contains("SshKeyPair"));
    ensure!(dbg.contains("debug-host"));
    ensure!(
        !dbg.contains("BEGIN OPENSSH PRIVATE KEY"),
        "Debug output must not leak private key material: {dbg}"
    );
    ensure!(
        !dbg.contains("ssh-ed25519 "),
        "Debug output must not leak the public key body: {dbg}"
    );
    Ok(())
}

#[test]
fn cert_fixture_debug_omits_key_material() -> TestResult<()> {
    let fx = Factory::deterministic_from_str("ssh-cert-debug-seed");
    let cert = fx.ssh_cert(
        "debug-cert",
        SshCertSpec::user(["alice"], SshValidity::new(1, 2)),
    );
    let dbg = format!("{cert:?}");

    ensure!(dbg.contains("SshCertFixture"));
    ensure!(dbg.contains("debug-cert"));
    ensure!(
        !dbg.contains("BEGIN OPENSSH PRIVATE KEY"),
        "Debug output must not leak private key material: {dbg}"
    );
    ensure!(
        !dbg.contains("ssh-ed25519-cert-v01"),
        "Debug output must not leak the certificate body: {dbg}"
    );
    Ok(())
}

#[test]
fn cert_spec_stable_bytes_change_with_critical_options_and_extensions() -> TestResult<()> {
    let base = SshCertSpec::user(["alice"], SshValidity::new(1, 2));
    let with_option = SshCertSpec {
        critical_options: vec![("force-command".to_string(), "/bin/echo".to_string())],
        ..base.clone()
    };
    let with_extension = SshCertSpec {
        extensions: vec![("permit-pty".to_string(), String::new())],
        ..base.clone()
    };

    ensure!(base.stable_bytes() != with_option.stable_bytes());
    ensure!(base.stable_bytes() != with_extension.stable_bytes());
    ensure!(with_option.stable_bytes() != with_extension.stable_bytes());
    Ok(())
}

#[test]
fn cert_spec_stable_bytes_change_with_validity_and_cert_type() -> TestResult<()> {
    let user = SshCertSpec::user(["alice"], SshValidity::new(1, 2));
    let later = SshCertSpec::user(["alice"], SshValidity::new(10, 20));
    let host = SshCertSpec::host(["alice"], SshValidity::new(1, 2));

    ensure!(user.stable_bytes() != later.stable_bytes());
    ensure!(user.stable_bytes() != host.stable_bytes());
    Ok(())
}

#[test]
fn deterministic_key_survives_cache_clear() -> TestResult<()> {
    let fx = Factory::deterministic_from_str("ssh-cache-clear-key");
    let before = fx.ssh_key("deploy", SshSpec::ed25519());
    let before_priv = before.private_key_openssh().to_string();
    let before_pub = before.authorized_key_line().to_string();

    fx.clear_cache();

    let after = fx.ssh_key("deploy", SshSpec::ed25519());
    ensure_eq!(after.private_key_openssh(), before_priv.as_str());
    ensure_eq!(after.authorized_key_line(), before_pub.as_str());
    Ok(())
}

#[test]
fn deterministic_cert_survives_cache_clear() -> TestResult<()> {
    let fx = Factory::deterministic_from_str("ssh-cache-clear-cert");
    let spec = SshCertSpec::user(
        ["alice", "ci"],
        SshValidity::new(1_700_000_010, 1_700_000_999),
    );

    let before = fx.ssh_cert("alice-cert", spec.clone());
    let cert_before = before.certificate_openssh().to_string();

    fx.clear_cache();

    let after = fx.ssh_cert("alice-cert", spec);
    ensure_eq!(after.certificate_openssh(), cert_before.as_str());
    Ok(())
}
