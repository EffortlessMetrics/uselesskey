//! Insta snapshot tests for uselesskey-jsonwebtoken adapter.
//!
//! These tests snapshot JWT token shapes produced by deterministic keys
//! to detect unintended changes in adapter output.

mod testutil;

use serde::Serialize;
use testutil::fx;
use uselesskey_jsonwebtoken::JwtKeyExt;

#[derive(Serialize)]
struct JwtRoundTrip {
    algorithm: &'static str,
    token_parts: usize,
    token_header_len: usize,
    claims_sub: String,
    claims_iss: String,
    roundtrip_ok: bool,
}

#[cfg(feature = "rsa")]
mod rsa_snapshots {
    use super::*;
    use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
    use serde::{Deserialize, Serialize};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        sub: String,
        exp: usize,
        iss: String,
    }

    #[test]
    fn snapshot_rsa_rs256_jwt_round_trip() {
        let fx = fx();
        let keypair = fx.rsa("snapshot-issuer", RsaSpec::rs256());

        let claims = Claims {
            sub: "user-1".into(),
            exp: 2_000_000_000,
            iss: "snapshot-issuer".into(),
        };
        let header = Header::new(Algorithm::RS256);
        let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();

        let validation = Validation::new(Algorithm::RS256);
        let decoded = decode::<Claims>(&token, &keypair.decoding_key(), &validation).unwrap();

        let result = JwtRoundTrip {
            algorithm: "RS256",
            token_parts: token.split('.').count(),
            token_header_len: token.split('.').next().unwrap().len(),
            claims_sub: decoded.claims.sub,
            claims_iss: decoded.claims.iss,
            roundtrip_ok: true,
        };

        insta::assert_yaml_snapshot!("rsa_rs256_round_trip", result);
    }
}

#[cfg(feature = "ecdsa")]
mod ecdsa_snapshots {
    use super::*;
    use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
    use serde::{Deserialize, Serialize};
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        sub: String,
        exp: usize,
        iss: String,
    }

    #[test]
    fn snapshot_ecdsa_es256_jwt_round_trip() {
        let fx = fx();
        let keypair = fx.ecdsa("snapshot-ecdsa", EcdsaSpec::es256());

        let claims = Claims {
            sub: "user-ec".into(),
            exp: 2_000_000_000,
            iss: "snapshot-ecdsa".into(),
        };
        let header = Header::new(Algorithm::ES256);
        let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();

        let validation = Validation::new(Algorithm::ES256);
        let decoded = decode::<Claims>(&token, &keypair.decoding_key(), &validation).unwrap();

        let result = JwtRoundTrip {
            algorithm: "ES256",
            token_parts: token.split('.').count(),
            token_header_len: token.split('.').next().unwrap().len(),
            claims_sub: decoded.claims.sub,
            claims_iss: decoded.claims.iss,
            roundtrip_ok: true,
        };

        insta::assert_yaml_snapshot!("ecdsa_es256_round_trip", result);
    }

    #[test]
    fn snapshot_ecdsa_es384_jwt_round_trip() {
        let fx = fx();
        let keypair = fx.ecdsa("snapshot-ecdsa-384", EcdsaSpec::es384());

        let claims = Claims {
            sub: "user-ec384".into(),
            exp: 2_000_000_000,
            iss: "snapshot-ecdsa-384".into(),
        };
        let header = Header::new(Algorithm::ES384);
        let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();

        let validation = Validation::new(Algorithm::ES384);
        let decoded = decode::<Claims>(&token, &keypair.decoding_key(), &validation).unwrap();

        let result = JwtRoundTrip {
            algorithm: "ES384",
            token_parts: token.split('.').count(),
            token_header_len: token.split('.').next().unwrap().len(),
            claims_sub: decoded.claims.sub,
            claims_iss: decoded.claims.iss,
            roundtrip_ok: true,
        };

        insta::assert_yaml_snapshot!("ecdsa_es384_round_trip", result);
    }
}

#[cfg(feature = "ed25519")]
mod ed25519_snapshots {
    use super::*;
    use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
    use serde::{Deserialize, Serialize};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        sub: String,
        exp: usize,
        iss: String,
    }

    #[test]
    fn snapshot_ed25519_jwt_round_trip() {
        let fx = fx();
        let keypair = fx.ed25519("snapshot-ed", Ed25519Spec::new());

        let claims = Claims {
            sub: "user-ed".into(),
            exp: 2_000_000_000,
            iss: "snapshot-ed".into(),
        };
        let header = Header::new(Algorithm::EdDSA);
        let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();

        let validation = Validation::new(Algorithm::EdDSA);
        let decoded = decode::<Claims>(&token, &keypair.decoding_key(), &validation).unwrap();

        let result = JwtRoundTrip {
            algorithm: "EdDSA",
            token_parts: token.split('.').count(),
            token_header_len: token.split('.').next().unwrap().len(),
            claims_sub: decoded.claims.sub,
            claims_iss: decoded.claims.iss,
            roundtrip_ok: true,
        };

        insta::assert_yaml_snapshot!("ed25519_round_trip", result);
    }
}

#[cfg(feature = "hmac")]
mod hmac_snapshots {
    use super::*;
    use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
    use serde::{Deserialize, Serialize};
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        sub: String,
        exp: usize,
        iss: String,
    }

    #[test]
    fn snapshot_hmac_hs256_jwt_round_trip() {
        let fx = fx();
        let secret = fx.hmac("snapshot-hmac", HmacSpec::hs256());

        let claims = Claims {
            sub: "user-hmac".into(),
            exp: 2_000_000_000,
            iss: "snapshot-hmac".into(),
        };
        let header = Header::new(Algorithm::HS256);
        let token = encode(&header, &claims, &secret.encoding_key()).unwrap();

        let validation = Validation::new(Algorithm::HS256);
        let decoded = decode::<Claims>(&token, &secret.decoding_key(), &validation).unwrap();

        let result = JwtRoundTrip {
            algorithm: "HS256",
            token_parts: token.split('.').count(),
            token_header_len: token.split('.').next().unwrap().len(),
            claims_sub: decoded.claims.sub,
            claims_iss: decoded.claims.iss,
            roundtrip_ok: true,
        };

        insta::assert_yaml_snapshot!("hmac_hs256_round_trip", result);
    }
}
