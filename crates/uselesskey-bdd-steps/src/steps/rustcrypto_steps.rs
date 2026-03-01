use cucumber::then;

// =========================================================================
// RSA
// =========================================================================

#[then("the RSA key should convert to valid RustCrypto RSA types")]
fn rustcrypto_rsa_convert(world: &mut crate::UselessWorld) {
    use uselesskey_rustcrypto::RustCryptoRsaExt;

    let rsa = world.rsa.as_ref().expect("RSA key not set");
    let _private = rsa.rsa_private_key();
    let _public = rsa.rsa_public_key();
}

#[then("the RustCrypto RSA types should sign and verify")]
fn rustcrypto_rsa_sign_verify(world: &mut crate::UselessWorld) {
    use rsa::pkcs1v15::{SigningKey, VerifyingKey};
    use rsa::signature::{Signer, Verifier};
    use uselesskey_rustcrypto::RustCryptoRsaExt;

    let rsa_kp = world.rsa.as_ref().expect("RSA key not set");
    let private_key = rsa_kp.rsa_private_key();
    let signing_key = SigningKey::<sha2::Sha256>::new_unprefixed(private_key);
    let signature = signing_key.sign(b"bdd test message");

    let public_key = rsa_kp.rsa_public_key();
    let verifying_key = VerifyingKey::<sha2::Sha256>::new_unprefixed(public_key);
    verifying_key
        .verify(b"bdd test message", &signature)
        .expect("RustCrypto RSA verify");
}

// =========================================================================
// ECDSA P-256
// =========================================================================

#[then("the ECDSA ES256 key should convert to a valid P-256 signing key")]
fn rustcrypto_p256_convert(world: &mut crate::UselessWorld) {
    use uselesskey_rustcrypto::RustCryptoEcdsaExt;

    let ecdsa = world.ecdsa.as_ref().expect("ECDSA key not set");
    let _signing = ecdsa.p256_signing_key();
    let _verifying = ecdsa.p256_verifying_key();
}

#[then("the RustCrypto P-256 types should sign and verify")]
fn rustcrypto_p256_sign_verify(world: &mut crate::UselessWorld) {
    use p256::ecdsa::signature::{Signer, Verifier};
    use uselesskey_rustcrypto::RustCryptoEcdsaExt;

    let ecdsa = world.ecdsa.as_ref().expect("ECDSA key not set");
    let signing_key = ecdsa.p256_signing_key();
    let signature: p256::ecdsa::Signature = signing_key.sign(b"bdd test message");

    let verifying_key = ecdsa.p256_verifying_key();
    verifying_key
        .verify(b"bdd test message", &signature)
        .expect("RustCrypto P-256 verify");
}

// =========================================================================
// ECDSA P-384
// =========================================================================

#[then("the ECDSA ES384 key should convert to a valid P-384 signing key")]
fn rustcrypto_p384_convert(world: &mut crate::UselessWorld) {
    use uselesskey_rustcrypto::RustCryptoEcdsaExt;

    let ecdsa = world.ecdsa.as_ref().expect("ECDSA key not set");
    let _signing = ecdsa.p384_signing_key();
    let _verifying = ecdsa.p384_verifying_key();
}

#[then("the RustCrypto P-384 types should sign and verify")]
fn rustcrypto_p384_sign_verify(world: &mut crate::UselessWorld) {
    use p384::ecdsa::signature::{Signer, Verifier};
    use uselesskey_rustcrypto::RustCryptoEcdsaExt;

    let ecdsa = world.ecdsa.as_ref().expect("ECDSA key not set");
    let signing_key = ecdsa.p384_signing_key();
    let signature: p384::ecdsa::Signature = signing_key.sign(b"bdd test message");

    let verifying_key = ecdsa.p384_verifying_key();
    verifying_key
        .verify(b"bdd test message", &signature)
        .expect("RustCrypto P-384 verify");
}

// =========================================================================
// Ed25519
// =========================================================================

#[then("the Ed25519 key should convert to a valid ed25519-dalek signing key")]
fn rustcrypto_ed25519_convert(world: &mut crate::UselessWorld) {
    use uselesskey_rustcrypto::RustCryptoEd25519Ext;

    let ed = world.ed25519.as_ref().expect("Ed25519 key not set");
    let _signing = ed.ed25519_signing_key();
    let _verifying = ed.ed25519_verifying_key();
}

#[then("the RustCrypto Ed25519 types should sign and verify")]
fn rustcrypto_ed25519_sign_verify(world: &mut crate::UselessWorld) {
    use ed25519_dalek::{Signer, Verifier};
    use uselesskey_rustcrypto::RustCryptoEd25519Ext;

    let ed = world.ed25519.as_ref().expect("Ed25519 key not set");
    let signing_key = ed.ed25519_signing_key();
    let signature = signing_key.sign(b"bdd test message");

    let verifying_key = ed.ed25519_verifying_key();
    verifying_key
        .verify(b"bdd test message", &signature)
        .expect("RustCrypto Ed25519 verify");
}

// =========================================================================
// HMAC
// =========================================================================

#[then("the HMAC secret should convert to a valid RustCrypto HMAC-SHA256")]
fn rustcrypto_hmac_sha256(world: &mut crate::UselessWorld) {
    use uselesskey_rustcrypto::RustCryptoHmacExt;

    let hmac_secret = world.hmac.as_ref().expect("HMAC secret not set");
    // Conversion succeeds if no panic; the returned type is hmac::Hmac<sha2::Sha256>.
    let _ = hmac_secret.hmac_sha256();
}

#[then("the HMAC secret should convert to a valid RustCrypto HMAC-SHA384")]
fn rustcrypto_hmac_sha384(world: &mut crate::UselessWorld) {
    use uselesskey_rustcrypto::RustCryptoHmacExt;

    let hmac_secret = world.hmac.as_ref().expect("HMAC secret not set");
    let _ = hmac_secret.hmac_sha384();
}

#[then("the HMAC secret should convert to a valid RustCrypto HMAC-SHA512")]
fn rustcrypto_hmac_sha512(world: &mut crate::UselessWorld) {
    use uselesskey_rustcrypto::RustCryptoHmacExt;

    let hmac_secret = world.hmac.as_ref().expect("HMAC secret not set");
    let _ = hmac_secret.hmac_sha512();
}
