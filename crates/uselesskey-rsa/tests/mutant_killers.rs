use uselesskey_rsa::RsaSpec;

#[test]
fn rs256_exact_values() {
    let spec = RsaSpec::rs256();
    assert_eq!(spec.bits, 2048);
    assert_eq!(spec.exponent, 65537);
}

#[test]
fn new_uses_default_exponent() {
    let spec = RsaSpec::new(4096);
    assert_eq!(spec.bits, 4096);
    assert_eq!(spec.exponent, 65537);
}

#[test]
fn stable_bytes_exact_encoding() {
    let spec = RsaSpec::rs256();
    let bytes = spec.stable_bytes();
    // bits=2048 in big-endian = [0, 0, 8, 0]
    assert_eq!(&bytes[..4], &2048u32.to_be_bytes());
    // exponent=65537 in big-endian = [0, 1, 0, 1]
    assert_eq!(&bytes[4..], &65537u32.to_be_bytes());
}

#[test]
fn stable_bytes_different_bits_produce_different_bytes() {
    assert_ne!(
        RsaSpec::new(2048).stable_bytes(),
        RsaSpec::new(4096).stable_bytes()
    );
}
