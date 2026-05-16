use jsonwebtoken::{DecodingKey, EncodingKey};

use super::JwtKeyExt;

impl JwtKeyExt for uselesskey_ecdsa::EcdsaKeyPair {
    fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_ec_pem(self.private_key_pkcs8_pem().as_bytes())
            .expect("failed to create EncodingKey from EC PEM")
    }

    fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_ec_pem(self.public_key_spki_pem().as_bytes())
            .expect("failed to create DecodingKey from EC PEM")
    }
}
