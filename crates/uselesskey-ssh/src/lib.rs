#![forbid(unsafe_code)]

//! OpenSSH key and certificate fixtures built on `uselesskey-core`.
//!
//! This crate provides deterministic and random fixtures for infra and deployment tests:
//! - authorized_keys public key lines
//! - OpenSSH private key export
//! - OpenSSH certificates (principals, validity windows, critical options, extensions)

mod cert;
mod keypair;
mod spec;

pub use cert::{DOMAIN_SSH_CERT, SshCertificate};
pub use keypair::{DOMAIN_SSH_KEYPAIR, SshFactoryExt, SshKeyPair};
pub use spec::{SshCertSpec, SshCertSpecWithOptions, SshCertType, SshSpec, SshValidity};

#[cfg(test)]
mod tests {
    use ssh_key::{Certificate, PrivateKey, PublicKey};
    use uselesskey_core::{Factory, Seed};

    use crate::{
        SshCertSpec, SshCertType, SshFactoryExt, SshSpec, SshValidity,
    };

    #[test]
    fn authorized_keys_is_deterministic() {
        let fx = Factory::deterministic(Seed::from_env_value("ssh-det").unwrap());

        let a = fx.ssh_key("deploy", SshSpec::ed25519());
        let b = fx.ssh_key("deploy", SshSpec::ed25519());

        assert_eq!(a.authorized_key_line(), b.authorized_key_line());
    }

    #[test]
    fn key_outputs_roundtrip_with_ssh_key_crate() {
        let fx = Factory::deterministic(Seed::from_env_value("ssh-roundtrip").unwrap());
        let key = fx.ssh_key("deploy", SshSpec::rsa());

        let parsed_priv = PrivateKey::from_openssh(key.private_key_openssh()).unwrap();
        let parsed_pub = PublicKey::from_openssh(key.authorized_key_line()).unwrap();

        assert_eq!(parsed_priv.algorithm(), key.private_key().algorithm());
        assert_eq!(parsed_pub.algorithm(), key.public_key().algorithm());
    }

    #[test]
    fn cert_has_expected_principals_and_validity() {
        let fx = Factory::deterministic(Seed::from_env_value("ssh-cert").unwrap());

        let cert = fx.ssh_cert_with_options(
            "host-a",
            SshCertSpec {
                principals: vec!["app.internal".to_string(), "deploy".to_string()],
                validity: SshValidity {
                    valid_after: 1_700_000_000,
                    valid_before: 1_800_000_000,
                },
                cert_type: SshCertType::Host,
            }
            .with_critical_options([("force-command", "/bin/true")])
            .with_extensions([("permit-pty", "")]),
        );

        let parsed = Certificate::from_openssh(cert.cert_openssh()).unwrap();

        assert_eq!(parsed.valid_principals(), &["app.internal", "deploy"]);
        assert_eq!(parsed.valid_after(), 1_700_000_000);
        assert_eq!(parsed.valid_before(), 1_800_000_000);
        assert_eq!(parsed.cert_type(), ssh_key::certificate::CertType::Host);

        assert_eq!(parsed.critical_options().get("force-command"), Some(&"/bin/true".to_string()));
        assert_eq!(parsed.extensions().get("permit-pty"), Some(&String::new()));
    }
}
