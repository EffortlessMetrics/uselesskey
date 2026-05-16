//! Tests covering spec builders, phase accessors, error variants, and
//! issuer-URL modes on `uselesskey-test-server`.

use uselesskey_core::{Factory, Seed};
use uselesskey_ecdsa::EcdsaSpec;
use uselesskey_ed25519::Ed25519Spec;
use uselesskey_rsa::RsaSpec;
use uselesskey_test_server::{
    CachePolicySpec, Error, IssuerUrlMode, JwkFixtureSpec, JwksPhase, JwksRotation, JwksSpec,
    OidcServerSpec, OidcTestServer, RsaJwkKeySpec,
};
use uselesskey_test_support::{TestResult, ensure, ensure_eq, require_ok, require_some};

fn deterministic_factory(label: &str) -> TestResult<Factory> {
    let seed = require_ok(
        Seed::from_env_value(label),
        format!("{label} must parse as a deterministic seed"),
    )?;
    Ok(Factory::deterministic(seed))
}

fn http_client() -> TestResult<reqwest::Client> {
    require_ok(
        reqwest::Client::builder().no_proxy().build(),
        "build http client",
    )
}

#[test]
fn cache_policy_no_store_returns_zero_max_age_and_no_etag() -> TestResult<()> {
    let policy = CachePolicySpec::no_store();
    ensure_eq!(policy.max_age_seconds, 0);
    ensure!(!policy.emit_etag, "no_store must not emit etag");
    Ok(())
}

#[test]
fn jwks_spec_single_rsa_contains_single_rsa_key() -> TestResult<()> {
    let spec = JwksSpec::single_rsa("issuer-rsa", RsaSpec::rs256());
    ensure_eq!(spec.keys.len(), 1);
    match require_some(spec.keys.first(), "expected one key")? {
        JwkFixtureSpec::Rsa { label, spec } => {
            ensure_eq!(label.as_str(), "issuer-rsa");
            ensure_eq!(*spec, RsaSpec::rs256());
        }
        other => {
            return Err(uselesskey_test_support::TestError(format!(
                "expected RSA key, got {other:?}"
            )));
        }
    }
    Ok(())
}

#[test]
fn jwks_spec_single_ecdsa_contains_single_ecdsa_key() -> TestResult<()> {
    let spec = JwksSpec::single_ecdsa("issuer-ecdsa", EcdsaSpec::Es256);
    ensure_eq!(spec.keys.len(), 1);
    match require_some(spec.keys.first(), "expected one key")? {
        JwkFixtureSpec::Ecdsa { label, spec } => {
            ensure_eq!(label.as_str(), "issuer-ecdsa");
            ensure_eq!(*spec, EcdsaSpec::Es256);
        }
        other => {
            return Err(uselesskey_test_support::TestError(format!(
                "expected ECDSA key, got {other:?}"
            )));
        }
    }
    Ok(())
}

#[test]
fn jwks_spec_single_ed25519_contains_single_ed25519_key() -> TestResult<()> {
    let spec = JwksSpec::single_ed25519("issuer-ed25519", Ed25519Spec::new());
    ensure_eq!(spec.keys.len(), 1);
    match require_some(spec.keys.first(), "expected one key")? {
        JwkFixtureSpec::Ed25519 { label, spec } => {
            ensure_eq!(label.as_str(), "issuer-ed25519");
            ensure_eq!(*spec, Ed25519Spec::new());
        }
        other => {
            return Err(uselesskey_test_support::TestError(format!(
                "expected Ed25519 key, got {other:?}"
            )));
        }
    }
    Ok(())
}

#[test]
fn oidc_server_spec_localhost_static_defaults() -> TestResult<()> {
    let jwks_spec = JwksSpec::single_rsa("issuer", RsaSpec::rs256());
    let spec = OidcServerSpec::localhost_static(jwks_spec.clone());

    ensure_eq!(spec.issuer_url_mode, IssuerUrlMode::RandomPortLocalhost);
    ensure!(spec.serve_discovery, "discovery must be enabled by default");
    ensure!(spec.serve_jwks, "jwks must be enabled by default");
    ensure!(
        spec.cache_headers.is_none(),
        "cache headers must default to None"
    );
    match spec.jwks_rotation {
        JwksRotation::Static(inner) => ensure_eq!(inner, jwks_spec),
        other => {
            return Err(uselesskey_test_support::TestError(format!(
                "expected static rotation, got {other:?}"
            )));
        }
    }
    Ok(())
}

#[test]
fn rsa_jwk_key_spec_into_jwk_fixture_spec_round_trips() -> TestResult<()> {
    let original = RsaJwkKeySpec::new("issuer-rsa", RsaSpec::rs256());
    let converted: JwkFixtureSpec = original.clone().into();
    match converted {
        JwkFixtureSpec::Rsa { label, spec } => {
            ensure_eq!(label, original.label);
            ensure_eq!(spec, original.spec);
        }
        other => {
            return Err(uselesskey_test_support::TestError(format!(
                "expected RSA variant after conversion, got {other:?}"
            )));
        }
    }
    Ok(())
}

#[test]
fn error_display_messages_match_variants() -> TestResult<()> {
    let start_err = Error::Start(std::io::Error::other("nope"));
    ensure!(
        start_err
            .to_string()
            .starts_with("failed to bind or start server: "),
        "Start display prefix: {start_err}"
    );

    let empty_err = Error::EmptyPhaseSequence;
    ensure_eq!(empty_err.to_string(), "at least one jwks phase is required");

    let unknown_err = Error::UnknownPhase("missing".to_string());
    ensure_eq!(unknown_err.to_string(), "unknown jwks phase: missing");

    // Sanity check that Debug is implemented and surfaces variant names.
    ensure!(format!("{start_err:?}").contains("Start"));
    ensure!(format!("{empty_err:?}").contains("EmptyPhaseSequence"));
    ensure!(format!("{unknown_err:?}").contains("UnknownPhase"));
    Ok(())
}

#[tokio::test]
async fn empty_phase_sequence_returns_error() -> TestResult<()> {
    let spec = OidcServerSpec {
        issuer_url_mode: IssuerUrlMode::RandomPortLocalhost,
        jwks_rotation: JwksRotation::Sequence(vec![]),
        cache_headers: None,
        serve_discovery: true,
        serve_jwks: true,
    };

    let result = OidcTestServer::start(deterministic_factory("phase-empty-err")?, spec).await;
    match result {
        Err(Error::EmptyPhaseSequence) => Ok(()),
        Err(other) => Err(uselesskey_test_support::TestError(format!(
            "expected EmptyPhaseSequence, got {other:?}"
        ))),
        Ok(_) => Err(uselesskey_test_support::TestError(
            "expected error, got Ok".into(),
        )),
    }
}

#[tokio::test]
async fn active_phase_name_reflects_initial_and_switched_phase() -> TestResult<()> {
    let spec = OidcServerSpec {
        issuer_url_mode: IssuerUrlMode::RandomPortLocalhost,
        jwks_rotation: JwksRotation::Sequence(vec![
            JwksPhase::new(
                "primary",
                JwksSpec::single_rsa("issuer-primary", RsaSpec::rs256()),
            ),
            JwksPhase::new(
                "rotated",
                JwksSpec::single_rsa("issuer-rotated", RsaSpec::rs256()),
            ),
        ]),
        cache_headers: None,
        serve_discovery: true,
        serve_jwks: true,
    };

    let server = require_ok(
        OidcTestServer::start(deterministic_factory("active-phase-name")?, spec).await,
        "start server",
    )?;

    ensure_eq!(
        server.active_phase_name(),
        "primary",
        "initial active phase should be the first one"
    );

    require_ok(server.with_phase("rotated"), "switch to rotated")?;
    ensure_eq!(server.active_phase_name(), "rotated");

    require_ok(server.with_phase("primary"), "switch back to primary")?;
    ensure_eq!(server.active_phase_name(), "primary");

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn active_phase_name_is_static_for_static_rotation() -> TestResult<()> {
    let spec =
        OidcServerSpec::localhost_static(JwksSpec::single_rsa("issuer-static", RsaSpec::rs256()));

    let server = require_ok(
        OidcTestServer::start(deterministic_factory("active-phase-static")?, spec).await,
        "start server",
    )?;

    ensure_eq!(server.active_phase_name(), "static");

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn with_phase_returns_unknown_phase_error_for_unknown_name() -> TestResult<()> {
    let spec = OidcServerSpec {
        issuer_url_mode: IssuerUrlMode::RandomPortLocalhost,
        jwks_rotation: JwksRotation::Sequence(vec![JwksPhase::new(
            "only",
            JwksSpec::single_rsa("issuer-only", RsaSpec::rs256()),
        )]),
        cache_headers: None,
        serve_discovery: true,
        serve_jwks: true,
    };

    let server = require_ok(
        OidcTestServer::start(deterministic_factory("with-phase-unknown")?, spec).await,
        "start server",
    )?;

    let result = server.with_phase("not-there");
    match result {
        Err(Error::UnknownPhase(name)) => ensure_eq!(name, "not-there"),
        Err(other) => {
            server.shutdown().await;
            return Err(uselesskey_test_support::TestError(format!(
                "expected UnknownPhase, got {other:?}"
            )));
        }
        Ok(()) => {
            server.shutdown().await;
            return Err(uselesskey_test_support::TestError(
                "expected error, got Ok".into(),
            ));
        }
    }

    // After an unknown phase, the active phase must remain unchanged.
    ensure_eq!(server.active_phase_name(), "only");

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn fixed_issuer_url_mode_is_reflected_in_discovery_document() -> TestResult<()> {
    let fixed = "https://issuer.example.test".to_string();
    let spec = OidcServerSpec {
        issuer_url_mode: IssuerUrlMode::Fixed(fixed.clone()),
        jwks_rotation: JwksRotation::Static(JwksSpec::single_rsa(
            "fixed-issuer-key",
            RsaSpec::rs256(),
        )),
        cache_headers: None,
        serve_discovery: true,
        serve_jwks: true,
    };

    let server = require_ok(
        OidcTestServer::start(deterministic_factory("fixed-issuer-mode")?, spec).await,
        "start server",
    )?;

    let response = require_ok(
        http_client()?.get(server.discovery_url()).send().await,
        "discovery response",
    )?;
    let document: serde_json::Value = require_ok(response.json().await, "discovery json")?;

    ensure_eq!(
        document["issuer"].as_str(),
        Some(fixed.as_str()),
        "discovery should advertise the fixed issuer URL"
    );
    // jwks_uri should still point at the live bound base URL, not the fixed
    // issuer URL (it's distinct from the issuer advertisement).
    ensure_eq!(
        document["jwks_uri"].as_str(),
        Some(server.jwks_url().as_str())
    );

    server.shutdown().await;
    Ok(())
}
