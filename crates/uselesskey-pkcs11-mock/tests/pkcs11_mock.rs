use uselesskey_core_seed::Seed;
use uselesskey_pkcs11_mock::{CertificateHandle, KeyHandle, Pkcs11Mock, Pkcs11MockSpec};

#[test]
fn deterministic_handles_and_metadata_are_stable() {
    let seed = Seed::from_text("pkcs11-seed");
    let spec = Pkcs11MockSpec::new("payments");

    let a = Pkcs11Mock::deterministic(seed, "slot-a", &spec);
    let b = Pkcs11Mock::deterministic(seed, "slot-a", &spec);

    assert_eq!(a.key_handle(), b.key_handle());
    assert_eq!(a.certificate_handle(), b.certificate_handle());
    assert_eq!(a.slot_metadata(), b.slot_metadata());
    assert_eq!(a.token_metadata(), b.token_metadata());
    assert_eq!(
        a.certificate_der(a.certificate_handle()).unwrap(),
        b.certificate_der(b.certificate_handle()).unwrap()
    );
}

#[test]
fn sign_verify_roundtrip_and_handle_errors() {
    let seed = Seed::from_text("pkcs11-sign-seed");
    let spec = Pkcs11MockSpec::new("issuer");
    let mock = Pkcs11Mock::deterministic(seed, "issuer-slot", &spec);
    let msg = b"hello pkcs11";

    let sig = mock.sign(mock.key_handle(), msg).unwrap();
    assert!(mock.verify(msg, &sig));
    assert!(!mock.verify(b"tampered", &sig));

    assert!(mock.sign(KeyHandle(9999), msg).is_err());
    assert!(mock.certificate_der(CertificateHandle(9999)).is_err());
}
