use uselesskey_core_x509_spec::{CertStatus, CrlReasonCode, CrlSpec, NoncePolicy, OcspSpec};

#[test]
fn crl_spec_stable_bytes_are_deterministic() {
    let spec = CrlSpec::default();
    assert_eq!(spec.stable_bytes(), spec.stable_bytes());
}

#[test]
fn ocsp_spec_stable_bytes_include_status_and_nonce() {
    let good = OcspSpec::default();
    let revoked = OcspSpec {
        cert_status: CertStatus::Revoked,
        revocation_reason: Some(CrlReasonCode::KeyCompromise),
        nonce_policy: NoncePolicy::Deterministic,
        ..OcspSpec::default()
    };

    assert_ne!(good.stable_bytes(), revoked.stable_bytes());
}
