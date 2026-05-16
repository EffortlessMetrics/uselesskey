use jsonwebtoken::{DecodingKey, EncodingKey};

use super::JwtKeyExt;

impl JwtKeyExt for uselesskey_hmac::HmacSecret {
    fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_secret(self.secret_bytes())
    }

    fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_secret(self.secret_bytes())
    }
}
