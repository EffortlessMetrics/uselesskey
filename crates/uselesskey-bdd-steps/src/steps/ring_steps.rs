use cucumber::then;

// =========================================================================
// RSA
// =========================================================================

#[then("the RSA key should convert to a valid ring key pair")]
fn ring_rsa_convert(world: &mut crate::UselessWorld) {
    use uselesskey_ring::RingRsaKeyPairExt;

    let rsa = world.rsa.as_ref().expect("RSA key not set");
    let kp = rsa.rsa_key_pair_ring();
    assert!(kp.public().modulus_len() > 0);
}

// =========================================================================
// ECDSA
// =========================================================================

#[then("the ECDSA key should convert to a valid ring ECDSA key pair")]
fn ring_ecdsa_convert(world: &mut crate::UselessWorld) {
    use uselesskey_ring::RingEcdsaKeyPairExt;

    let ecdsa = world.ecdsa.as_ref().expect("ECDSA key not set");
    let _ = ecdsa.ecdsa_key_pair_ring();
}

// =========================================================================
// Ed25519
// =========================================================================

#[then("the Ed25519 key should convert to a valid ring Ed25519 key pair")]
fn ring_ed25519_convert(world: &mut crate::UselessWorld) {
    use uselesskey_ring::RingEd25519KeyPairExt;

    let ed = world.ed25519.as_ref().expect("Ed25519 key not set");
    let _ = ed.ed25519_key_pair_ring();
}

// =========================================================================
// Deterministic: same seed + label → same converted key
// =========================================================================

#[then("the ring RSA key pairs from the same seed should have equal modulus length")]
fn ring_rsa_deterministic(world: &mut crate::UselessWorld) {
    use uselesskey_ring::RingRsaKeyPairExt;

    let rsa = world.rsa.as_ref().expect("RSA key not set");
    let kp1 = rsa.rsa_key_pair_ring();
    let kp2 = rsa.rsa_key_pair_ring();
    assert_eq!(kp1.public().modulus_len(), kp2.public().modulus_len());
}
