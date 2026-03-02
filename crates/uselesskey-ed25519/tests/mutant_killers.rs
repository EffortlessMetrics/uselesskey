use uselesskey_ed25519::Ed25519Spec;

#[test]
fn new_and_default_are_equal() {
    assert_eq!(Ed25519Spec::new(), Ed25519Spec::default());
}

#[test]
fn stable_bytes_exact_values() {
    let spec = Ed25519Spec::new();
    assert_eq!(spec.stable_bytes(), [b'E', b'd', 0x01, 0x00]);
}

#[test]
fn stable_bytes_first_two_are_ascii() {
    let bytes = Ed25519Spec::new().stable_bytes();
    assert_eq!(bytes[0], 0x45); // 'E'
    assert_eq!(bytes[1], 0x64); // 'd'
}
