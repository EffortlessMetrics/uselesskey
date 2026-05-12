use crate::{WebhookPayloadSpec, WebhookProfile};

pub(crate) fn stable_spec_bytes(
    profile: WebhookProfile,
    payload_spec: &WebhookPayloadSpec,
) -> Vec<u8> {
    let mut out = profile.stable_tag().as_bytes().to_vec();
    out.push(0);
    out.extend_from_slice(&payload_spec.stable_bytes());
    out
}

pub(crate) fn canonical_payload(
    profile: WebhookProfile,
    label: &str,
    payload_spec: WebhookPayloadSpec,
    nonce: u32,
) -> String {
    match payload_spec {
        WebhookPayloadSpec::Raw(payload) => payload,
        WebhookPayloadSpec::Canonical => provider_canonical_payload(profile, label, nonce),
    }
}

fn provider_canonical_payload(profile: WebhookProfile, label: &str, nonce: u32) -> String {
    match profile {
        WebhookProfile::GitHub => github_payload(label, nonce),
        WebhookProfile::Stripe => stripe_payload(label, nonce),
        WebhookProfile::Slack => slack_payload(label, nonce),
    }
}

fn github_payload(label: &str, nonce: u32) -> String {
    let repository = json_string(&format!("acme/{label}"));
    format!(
        "{{\"action\":\"opened\",\"repository\":{{\"full_name\":{repository}}},\"number\":{}}}",
        (nonce % 9000) + 1000
    )
}

fn stripe_payload(label: &str, nonce: u32) -> String {
    let label = json_string(label);
    let mut payload = format!(
        "{{\"id\":\"evt_{nonce:08x}\",\"type\":\"checkout.session.completed\",\"data\":{{\"object\":{{\"metadata\":{{\"label\":"
    );
    payload.push_str(&label);
    payload.push_str("}}}}");
    payload
}

fn slack_payload(label: &str, nonce: u32) -> String {
    let text = json_string(&format!("ping {label}"));
    format!(
        "{{\"type\":\"event_callback\",\"team_id\":\"T{nonce:08x}\",\"event\":{{\"type\":\"app_mention\",\"text\":{text}}}}}"
    )
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a string to JSON cannot fail")
}
