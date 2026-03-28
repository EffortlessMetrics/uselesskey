use uselesskey_core::{Factory, Seed};
use uselesskey_pkcs11_mock::{
    Pkcs11MockError, Pkcs11MockFactoryExt, Pkcs11MockSpec, Pkcs11Provider,
};

#[test]
fn deterministic_certificate_lookup() {
    let fx = Factory::deterministic(Seed::from_env_value("pkcs11-cert").unwrap());
    let mock = fx.pkcs11_mock("slot-a", Pkcs11MockSpec::default());

    let handle = mock.key_handles()[0];
    let cert1 = mock.certificate(handle).unwrap();
    let cert2 = mock.certificate(handle).unwrap();

    assert_eq!(cert1.subject_cn, cert2.subject_cn);
    assert_eq!(cert1.der, cert2.der);
}

#[test]
fn unknown_handle_errors() {
    let fx = Factory::random();
    let mock = fx.pkcs11_mock("slot-a", Pkcs11MockSpec::default());

    let err = mock.certificate(uselesskey_pkcs11_mock::KeyHandle(u64::MAX));
    assert_eq!(err, Err(Pkcs11MockError::UnknownHandle(uselesskey_pkcs11_mock::KeyHandle(u64::MAX))));
}

#[test]
fn sign_verify_roundtrip_all_handles() {
    let fx = Factory::deterministic(Seed::from_env_value("pkcs11-roundtrip").unwrap());
    let mock = fx.pkcs11_mock("slot-a", Pkcs11MockSpec::default());

    for handle in mock.key_handles() {
        let msg = format!("payload-{}", handle.0);
        let sig = mock.sign(*handle, msg.as_bytes()).unwrap();
        assert!(mock.verify(*handle, msg.as_bytes(), &sig).unwrap());
    }
}
