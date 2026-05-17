use uselesskey::{Factory, NearMissScenario, WebhookFactoryExt, WebhookPayloadSpec};

#[test]
fn webhook_fixtures_exercise_positive_and_negative_paths() {
    let fx = Factory::deterministic_from_str("external-webhook-verifier");
    let fixture = fx.webhook_stripe("payment", WebhookPayloadSpec::Canonical);

    assert!(fixture.headers.contains_key("Stripe-Signature"));
    assert!(fixture.payload.contains("checkout.session.completed"));
    assert!(!format!("{fixture:?}").contains(&fixture.secret));

    let stale = fixture.near_miss_stale_timestamp(300);
    assert_eq!(stale.scenario, NearMissScenario::StaleTimestamp);
    assert!(stale.timestamp < fixture.timestamp);

    let wrong_secret = fixture.near_miss_wrong_secret();
    assert_eq!(wrong_secret.scenario, NearMissScenario::WrongSecret);
    assert_ne!(wrong_secret.secret, fixture.secret);
    assert!(!format!("{wrong_secret:?}").contains(&wrong_secret.secret));

    let tampered = fixture.near_miss_tampered_payload();
    assert_eq!(tampered.scenario, NearMissScenario::TamperedPayload);
    assert_ne!(tampered.payload, fixture.payload);
}
