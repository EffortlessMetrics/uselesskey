include!(concat!(env!("OUT_DIR"), "/fixtures.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_script_materializes_expected_shape_fixtures() {
        assert_eq!(ENTROPY.len(), 64);

        let jwt = std::str::from_utf8(TOKEN).expect("jwt fixture should be utf-8");
        assert_eq!(jwt.split('.').count(), 3);

        let pem = std::str::from_utf8(PEM_SHAPE).expect("pem shape should be utf-8");
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));

        let ssh = std::str::from_utf8(SSH_SHAPE).expect("ssh fixture should be utf-8");
        assert!(ssh.starts_with("ssh-ed25519 "));
    }
}
