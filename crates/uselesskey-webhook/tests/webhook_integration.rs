use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use uselesskey_core::{Factory, Seed};
use uselesskey_webhook::{WebhookFactoryExt, WebhookPayloadSpec};

fn sign(secret: &str, data: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key init");
    mac.update(data.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn verify_github(secret: &str, payload: &[u8], provided: &str) -> bool {
    let expected = format!("sha256={}", sign(secret, &String::from_utf8_lossy(payload)));
    expected == provided
}

fn verify_stripe(secret: &str, payload: &[u8], timestamp: i64, provided: &str) -> bool {
    let base = format!("{timestamp}.{}", String::from_utf8_lossy(payload));
    let expected = format!("t={timestamp},v1={}", sign(secret, &base));
    expected == provided
}

fn verify_slack(secret: &str, payload: &[u8], timestamp: i64, provided: &str) -> bool {
    let base = format!("v0:{timestamp}:{}", String::from_utf8_lossy(payload));
    let expected = format!("v0={}", sign(secret, &base));
    expected == provided
}

#[test]
fn github_signature_verifies() {
    let fx = Factory::deterministic(Seed::from_env_value("webhook-github").unwrap());
    let wh = fx.webhook_github("repo", WebhookPayloadSpec::github_push());

    assert!(verify_github(
        &wh.secret,
        &wh.payload,
        wh.headers.get("X-Hub-Signature-256").expect("header")
    ));
}

#[test]
fn stripe_signature_verifies() {
    let fx = Factory::deterministic(Seed::from_env_value("webhook-stripe").unwrap());
    let wh = fx.webhook_stripe("billing", WebhookPayloadSpec::stripe_payment_succeeded());

    assert!(verify_stripe(
        &wh.secret,
        &wh.payload,
        wh.timestamp,
        wh.headers.get("Stripe-Signature").expect("header")
    ));
}

#[test]
fn slack_signature_verifies() {
    let fx = Factory::deterministic(Seed::from_env_value("webhook-slack").unwrap());
    let wh = fx.webhook_slack("chatops", WebhookPayloadSpec::slack_event_callback());

    assert!(verify_slack(
        &wh.secret,
        &wh.payload,
        wh.timestamp,
        wh.headers.get("X-Slack-Signature").expect("header")
    ));
}

#[test]
fn header_shapes_match_provider_patterns() {
    let fx = Factory::deterministic(Seed::from_env_value("webhook-headers").unwrap());
    let gh = fx.webhook_github("repo", WebhookPayloadSpec::github_push());
    let st = fx.webhook_stripe("billing", WebhookPayloadSpec::stripe_payment_succeeded());
    let sl = fx.webhook_slack("chatops", WebhookPayloadSpec::slack_event_callback());

    assert!(gh
        .headers
        .get("X-Hub-Signature-256")
        .expect("header")
        .starts_with("sha256="));
    assert!(st
        .headers
        .get("Stripe-Signature")
        .expect("header")
        .starts_with("t="));
    assert!(sl
        .headers
        .get("X-Slack-Signature")
        .expect("header")
        .starts_with("v0="));
    assert_eq!(
        sl.headers
            .get("X-Slack-Request-Timestamp")
            .expect("header"),
        &sl.timestamp.to_string()
    );
}

#[test]
fn near_miss_covers_stale_wrong_secret_and_tamper() {
    let fx = Factory::deterministic(Seed::from_env_value("webhook-near-miss").unwrap());
    let wh = fx.webhook_stripe("billing", WebhookPayloadSpec::stripe_payment_succeeded());
    let near = fx.webhook_near_miss(&wh);

    let stale_header = near.stale_headers.get("Stripe-Signature").expect("stale sig");
    assert!(verify_stripe(
        &wh.secret,
        &wh.payload,
        near.stale_timestamp,
        stale_header
    ));
    assert_ne!(near.stale_timestamp, wh.timestamp);

    let live_sig = wh.headers.get("Stripe-Signature").expect("live sig");
    assert!(!verify_stripe(&near.wrong_secret, &wh.payload, wh.timestamp, live_sig));

    let tampered = near
        .tampered_headers
        .get("Stripe-Signature")
        .expect("tampered sig");
    assert!(!verify_stripe(&wh.secret, &near.tampered_payload, wh.timestamp, live_sig));
    assert!(verify_stripe(&wh.secret, &near.tampered_payload, wh.timestamp, tampered));
}

#[test]
fn deterministic_generation_is_order_independent() {
    let seed = Seed::from_env_value("webhook-order-independent").unwrap();

    let a_fx = Factory::deterministic(seed);
    let a1 = a_fx.webhook_github("one", WebhookPayloadSpec::github_push());
    let a2 = a_fx.webhook_stripe("two", WebhookPayloadSpec::stripe_payment_succeeded());

    let b_fx = Factory::deterministic(seed);
    let b2 = b_fx.webhook_stripe("two", WebhookPayloadSpec::stripe_payment_succeeded());
    let b1 = b_fx.webhook_github("one", WebhookPayloadSpec::github_push());

    assert_eq!(a1.secret, b1.secret);
    assert_eq!(a1.payload, b1.payload);
    assert_eq!(a2.secret, b2.secret);
    assert_eq!(a2.payload, b2.payload);
}
