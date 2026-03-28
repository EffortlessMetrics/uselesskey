use uselesskey_core::Factory;
use uselesskey_core::Seed;
use uselesskey_x509::{ChainSpec, OcspCertStatus, X509FactoryExt};
use x509_parser::prelude::FromDer;

#[test]
fn crl_for_leaf_parses_and_binds_leaf_serial() {
    let fx = Factory::deterministic(Seed::from_env_value("revocation-seed").unwrap());
    let chain = fx.x509_chain("revocation", ChainSpec::new("revocation.example.com"));
    let fixture = chain.crl_for_leaf();

    let (_, crl) = x509_parser::revocation_list::CertificateRevocationList::from_der(fixture.der())
        .expect("parse CRL");
    let revoked = crl
        .iter_revoked_certificates()
        .next()
        .expect("one revoked serial");
    assert_eq!(revoked.raw_serial(), fixture.serial_bindings()[0].as_slice());
    assert_eq!(fixture.serial_bindings()[0], chain.ocsp_for_leaf(OcspCertStatus::Good).serial_bindings()[0]);
}

#[test]
fn revocation_fixture_der_is_deterministic() {
    let seed = Seed::from_env_value("revocation-seed").unwrap();
    let fx = Factory::deterministic(seed);
    let spec = ChainSpec::new("det-revocation.example.com");

    let chain1 = fx.x509_chain("det-revocation", spec.clone());
    let crl1 = chain1.crl_for_intermediate();
    let ocsp1 = chain1.ocsp_for_intermediate(OcspCertStatus::Unknown);

    fx.clear_cache();

    let chain2 = fx.x509_chain("det-revocation", spec);
    let crl2 = chain2.crl_for_intermediate();
    let ocsp2 = chain2.ocsp_for_intermediate(OcspCertStatus::Unknown);

    assert_eq!(crl1.der(), crl2.der());
    assert_eq!(ocsp1.der(), ocsp2.der());
}
