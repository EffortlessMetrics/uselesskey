use jsonwebtoken::{DecodingKey, EncodingKey};

use super::JwtKeyExt;

impl JwtKeyExt for uselesskey_ed25519::Ed25519KeyPair {
    fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_ed_pem(self.private_key_pkcs8_pem().as_bytes())
            .expect("failed to create EncodingKey from Ed25519 PEM")
    }

    fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_ed_pem(self.public_key_spki_pem().as_bytes())
            .expect("failed to create DecodingKey from Ed25519 PEM")
    }
}
