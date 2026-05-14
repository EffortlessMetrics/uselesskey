use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::WebhookProfile;

pub(crate) fn sign(
    profile: WebhookProfile,
    secret: &str,
    payload: &str,
    timestamp: i64,
) -> (BTreeMap<String, String>, String) {
    let mut headers = BTreeMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());

    match profile {
        WebhookProfile::GitHub => github_signature(secret, payload, headers),
        WebhookProfile::Stripe => stripe_signature(secret, payload, timestamp, headers),
        WebhookProfile::Slack => slack_signature(secret, payload, timestamp, headers),
    }
}

fn github_signature(
    secret: &str,
    payload: &str,
    mut headers: BTreeMap<String, String>,
) -> (BTreeMap<String, String>, String) {
    let signature_input = payload.to_string();
    let digest = hmac_sha256_hex(secret.as_bytes(), signature_input.as_bytes());
    headers.insert(
        "X-Hub-Signature-256".to_string(),
        format!("sha256={digest}"),
    );
    (headers, signature_input)
}

fn stripe_signature(
    secret: &str,
    payload: &str,
    timestamp: i64,
    mut headers: BTreeMap<String, String>,
) -> (BTreeMap<String, String>, String) {
    let signature_input = format!("{timestamp}.{payload}");
    let digest = hmac_sha256_hex(secret.as_bytes(), signature_input.as_bytes());
    headers.insert(
        "Stripe-Signature".to_string(),
        format!("t={timestamp},v1={digest}"),
    );
    (headers, signature_input)
}

fn slack_signature(
    secret: &str,
    payload: &str,
    timestamp: i64,
    mut headers: BTreeMap<String, String>,
) -> (BTreeMap<String, String>, String) {
    let signature_input = format!("v0:{timestamp}:{payload}");
    let digest = hmac_sha256_hex(secret.as_bytes(), signature_input.as_bytes());
    headers.insert(
        "X-Slack-Request-Timestamp".to_string(),
        timestamp.to_string(),
    );
    headers.insert("X-Slack-Signature".to_string(), format!("v0={digest}"));
    (headers, signature_input)
}

pub(crate) fn hmac_sha256_hex(secret: &[u8], msg: &[u8]) -> String {
    const SHA256_BLOCK_LEN: usize = 64;

    let mut key_block = [0_u8; SHA256_BLOCK_LEN];
    if secret.len() > SHA256_BLOCK_LEN {
        let digest = Sha256::digest(secret);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..secret.len()].copy_from_slice(secret);
    }

    let mut ipad = [0x36_u8; SHA256_BLOCK_LEN];
    let mut opad = [0x5c_u8; SHA256_BLOCK_LEN];
    for idx in 0..SHA256_BLOCK_LEN {
        ipad[idx] ^= key_block[idx];
        opad[idx] ^= key_block[idx];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    hex::encode(outer.finalize())
}
