use jsonwebtoken::{DecodingKey, EncodingKey};

use super::JwtKeyExt;

impl JwtKeyExt for uselesskey_rsa::RsaKeyPair {
    fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_rsa_pem(self.private_key_pkcs8_pem().as_bytes())
            .expect("failed to create EncodingKey from RSA PEM")
    }

    fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_rsa_pem(self.public_key_spki_pem().as_bytes())
            .expect("failed to create DecodingKey from RSA PEM")
    }
}
