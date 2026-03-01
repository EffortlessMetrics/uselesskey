use cucumber::then;

// =========================================================================
// RSA
// =========================================================================

#[then("the RSA key should convert to a valid aws-lc-rs key pair")]
fn aws_lc_rs_rsa_convert(world: &mut crate::UselessWorld) {
    use uselesskey_aws_lc_rs::AwsLcRsRsaKeyPairExt;

    let rsa = world.rsa.as_ref().expect("RSA key not set");
    let kp = rsa.rsa_key_pair_aws_lc_rs();
    assert!(kp.public_modulus_len() > 0);
}

// =========================================================================
// ECDSA
// =========================================================================

#[then("the ECDSA key should convert to a valid aws-lc-rs ECDSA key pair")]
fn aws_lc_rs_ecdsa_convert(world: &mut crate::UselessWorld) {
    use uselesskey_aws_lc_rs::AwsLcRsEcdsaKeyPairExt;

    let ecdsa = world.ecdsa.as_ref().expect("ECDSA key not set");
    let _ = ecdsa.ecdsa_key_pair_aws_lc_rs();
}

// =========================================================================
// Ed25519
// =========================================================================

#[then("the Ed25519 key should convert to a valid aws-lc-rs Ed25519 key pair")]
fn aws_lc_rs_ed25519_convert(world: &mut crate::UselessWorld) {
    use uselesskey_aws_lc_rs::AwsLcRsEd25519KeyPairExt;

    let ed = world.ed25519.as_ref().expect("Ed25519 key not set");
    let _ = ed.ed25519_key_pair_aws_lc_rs();
}

// =========================================================================
// Deterministic
// =========================================================================

#[then("the aws-lc-rs RSA key pairs from the same seed should have equal modulus length")]
fn aws_lc_rs_rsa_deterministic(world: &mut crate::UselessWorld) {
    use uselesskey_aws_lc_rs::AwsLcRsRsaKeyPairExt;

    let rsa = world.rsa.as_ref().expect("RSA key not set");
    let kp1 = rsa.rsa_key_pair_aws_lc_rs();
    let kp2 = rsa.rsa_key_pair_aws_lc_rs();
    assert_eq!(kp1.public_modulus_len(), kp2.public_modulus_len());
}
