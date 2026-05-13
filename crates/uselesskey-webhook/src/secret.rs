use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_chacha10::ChaCha20Rng;
use rand_core10::Rng;

use crate::WebhookProfile;

pub(crate) fn build_secret(profile: WebhookProfile, rng: &mut ChaCha20Rng) -> String {
    let mut secret_bytes = [0_u8; 32];
    rng.fill_bytes(&mut secret_bytes);

    match profile {
        WebhookProfile::GitHub => format!("ghs_{}", URL_SAFE_NO_PAD.encode(secret_bytes)),
        WebhookProfile::Stripe => format!("whsec_{}", hex::encode(secret_bytes)),
        WebhookProfile::Slack => hex::encode(secret_bytes),
    }
}
