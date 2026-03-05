use uselesskey_core::negative::CorruptPem;
use uselesskey_core_x509::{KeyUsage, NotBeforeOffset, X509Spec};
use uselesskey_x509_negative::{
    X509Negative, corrupt_cert_der_deterministic, corrupt_cert_pem, corrupt_cert_pem_deterministic,
    truncate_cert_der,
};

#[test]
fn x509_negative_variants_apply_expected_policy() {
    let base = X509Spec::self_signed("test");

    let expired = X509Negative::Expired.apply_to_spec(&base);
    assert_eq!(expired.not_before_offset, NotBeforeOffset::DaysAgo(395));
    assert_eq!(expired.validity_days, 365);

    let not_yet_valid = X509Negative::NotYetValid.apply_to_spec(&base);
    assert_eq!(
        not_yet_valid.not_before_offset,
        NotBeforeOffset::DaysFromNow(30)
    );
    assert_eq!(not_yet_valid.validity_days, 365);

    let wrong_key_usage = X509Negative::WrongKeyUsage.apply_to_spec(&base);
    assert!(wrong_key_usage.is_ca);
    assert_eq!(
        wrong_key_usage.key_usage,
        KeyUsage {
            key_cert_sign: false,
            crl_sign: false,
            digital_signature: true,
            key_encipherment: true,
        }
    );
}

#[test]
fn cert_pem_helpers_corrupt_and_are_stable() {
    let pem = "-----BEGIN CERTIFICATE-----\nAAA=\n-----END CERTIFICATE-----\n";

    assert_ne!(corrupt_cert_pem(pem, CorruptPem::BadHeader), pem);

    let a = corrupt_cert_pem_deterministic(pem, "corrupt:v1");
    let b = corrupt_cert_pem_deterministic(pem, "corrupt:v1");
    assert_eq!(a, b);
    assert_ne!(a, pem);
}

#[test]
fn cert_der_helpers_corrupt_and_truncate() {
    let der = vec![0x30, 0x03, 0x02, 0x01, 0x01];

    assert_eq!(truncate_cert_der(&der, 2), der[..2].to_vec());

    let a = corrupt_cert_der_deterministic(&der, "corrupt:v1");
    let b = corrupt_cert_der_deterministic(&der, "corrupt:v1");
    assert_eq!(a, b);
    assert_ne!(a, der);
}
