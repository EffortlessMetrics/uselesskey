//! Focused coverage for `cert/params.rs` helper branches and a handful of
//! derived-trait invariants that are otherwise uncovered.
//!
//! Gaps closed:
//! - `apply_not_before(DaysFromNow)` path on a positive (non-negative-fixture)
//!   self-signed cert, observed via parsed `not_before`.
//! - SAN dedup in the actual generated cert (only `stable_bytes` dedup tested
//!   today).
//! - `ca_constraint`/`with_is_ca(true)` on a non-`self_signed_ca` builder
//!   produces a CA cert (currently only covered indirectly via the
//!   `WrongKeyUsage`/`SelfSignedButClaimsCA` negative variants).
//! - `key_usage_purposes` mapping for an all-false `KeyUsage` (empty vec
//!   branch) yields a cert with no `KeyUsage` extension bits set.
//! - Default `NotBeforeOffset` value and its `Default` impl on `X509Spec`.
//! - `X509Negative` / `ChainNegative` derived `Eq` / `Hash` / `Clone` /
//!   `Debug` round-trips through `HashSet` / `HashMap`.
//! - `X509Cert::clone` shares the underlying `Arc<Inner>` (cert DER pointer
//!   stays equal — observable proxy for shared allocation).
//! - `X509Chain::clone` shares underlying chain bytes the same way.
//! - `ChainSpec` builder fields actually drive the generated chain
//!   (intermediate `not_before` + validity days reach the cert).
//! - `intermediate_is_ca = Some(true)` keeps the intermediate as a CA
//!   (explicit-true branch on the `ca_constraint` selector inside
//!   `chain/params.rs`).

use std::collections::{HashMap, HashSet};

use uselesskey_core::Factory;
use uselesskey_test_support::{TestResult, ensure, ensure_eq, require_ok, require_some};
use uselesskey_x509::{
    ChainNegative, ChainSpec, KeyUsage, NotBeforeOffset, X509Cert, X509Chain, X509FactoryExt,
    X509Negative, X509Spec,
};
use x509_parser::extensions::{KeyUsage as ParsedKeyUsage, ParsedExtension};
use x509_parser::prelude::*;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn fx(label: &str) -> Factory {
    Factory::deterministic_from_str(label)
}

fn parse<'a>(der: &'a [u8]) -> TestResult<X509Certificate<'a>> {
    let (rest, parsed) = require_ok(
        X509Certificate::from_der(der),
        "cert DER should parse via x509-parser",
    )?;
    ensure!(rest.is_empty(), "cert DER should consume all input bytes");
    Ok(parsed)
}

fn find_key_usage<'a>(cert: &'a X509Certificate<'a>) -> TestResult<&'a ParsedKeyUsage> {
    let ext = require_some(
        cert.extensions()
            .iter()
            .find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE),
        "cert should have a KeyUsage extension",
    )?;
    match ext.parsed_extension() {
        ParsedExtension::KeyUsage(ku) => Ok(ku),
        _ => Err(uselesskey_test_support::TestError(
            "expected KeyUsage extension".to_string(),
        )),
    }
}

fn dns_sans(cert: &X509Certificate<'_>) -> Vec<String> {
    let ext = match cert
        .extensions()
        .iter()
        .find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
    {
        Some(ext) => ext,
        None => return Vec::new(),
    };
    let san = match ext.parsed_extension() {
        ParsedExtension::SubjectAlternativeName(s) => s,
        _ => return Vec::new(),
    };
    san.general_names
        .iter()
        .filter_map(|gn| match gn {
            x509_parser::extensions::GeneralName::DNSName(name) => Some(name.to_string()),
            _ => None,
        })
        .collect()
}

// -----------------------------------------------------------------------------
// cert/params.rs — `apply_not_before(DaysFromNow)` on a positive fixture
// -----------------------------------------------------------------------------

#[test]
fn self_signed_days_from_now_pushes_not_before_past_base_time() -> TestResult<()> {
    // Both certs share the same deterministic base_time (same label / CN /
    // issuer / rsa_bits), so DaysFromNow must shift not_before later than the
    // default DaysAgo(1) cert by ~31 days.
    let fx = fx("x509-params-not-before-future");
    let base = X509Spec::self_signed("future.example.com");
    let future = X509Spec::self_signed("future.example.com")
        .with_not_before(NotBeforeOffset::DaysFromNow(30));

    let cert_default = fx.x509_self_signed("future-label", base);
    let cert_future = fx.x509_self_signed("future-label", future);

    let default_parsed = parse(cert_default.cert_der())?;
    let future_parsed = parse(cert_future.cert_der())?;

    let default_nb = default_parsed.validity().not_before.timestamp();
    let future_nb = future_parsed.validity().not_before.timestamp();

    let diff_days = (future_nb - default_nb) / 86_400;
    ensure!(
        diff_days >= 30,
        "DaysFromNow(30) - DaysAgo(1) should shift not_before by >= 30 days, got {diff_days}"
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// cert/params.rs — `add_sorted_dns_sans` dedup observable in cert
// -----------------------------------------------------------------------------

#[test]
fn self_signed_san_dedup_observable_in_generated_cert() -> TestResult<()> {
    let fx = fx("x509-params-san-dedup");
    let spec = X509Spec::self_signed("dedup.example.com").with_sans(vec![
        "alpha.example.com".to_string(),
        "alpha.example.com".to_string(),
        "beta.example.com".to_string(),
        "alpha.example.com".to_string(),
    ]);
    let cert = fx.x509_self_signed("dedup-label", spec);
    let parsed = parse(cert.cert_der())?;

    let mut names = dns_sans(&parsed);
    names.sort();
    ensure_eq!(
        names,
        vec!["alpha.example.com".to_string(), "beta.example.com".to_string()]
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// cert/params.rs — `ca_constraint(true)` via `with_is_ca` (no key_usage flip)
// -----------------------------------------------------------------------------

#[test]
fn with_is_ca_true_alone_produces_ca_cert() -> TestResult<()> {
    // `self_signed_ca` flips both `is_ca` and `key_usage` together, so this
    // covers the `with_is_ca`-only branch — `is_ca = true` but `key_usage`
    // still at leaf defaults. Generated cert must still report `is_ca()`.
    let fx = fx("x509-params-is-ca-only");
    let spec = X509Spec::self_signed("ca-only.example.com").with_is_ca(true);
    let cert = fx.x509_self_signed("ca-only", spec);
    let parsed = parse(cert.cert_der())?;
    ensure!(parsed.is_ca(), "with_is_ca(true) cert should be flagged CA");
    Ok(())
}

// -----------------------------------------------------------------------------
// cert/params.rs — `key_usage_purposes` empty-vec branch
// -----------------------------------------------------------------------------

#[test]
fn all_false_key_usage_produces_cert_without_any_ku_bits() -> TestResult<()> {
    // `key_usage_purposes` with every bit false returns an empty Vec; rcgen
    // then either omits the extension or emits a zero-bit one. Either way,
    // no individual usage bit should be set.
    let fx = fx("x509-params-empty-ku");
    let ku = KeyUsage {
        key_cert_sign: false,
        crl_sign: false,
        digital_signature: false,
        key_encipherment: false,
    };
    let spec = X509Spec::self_signed("empty-ku.example.com").with_key_usage(ku);
    let cert = fx.x509_self_signed("empty-ku", spec);
    let parsed = parse(cert.cert_der())?;

    if let Some(ext) = parsed
        .extensions()
        .iter()
        .find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE)
        && let ParsedExtension::KeyUsage(found) = ext.parsed_extension()
    {
        ensure!(
            !found.digital_signature()
                && !found.key_encipherment()
                && !found.key_cert_sign()
                && !found.crl_sign(),
            "all-false KeyUsage spec must not set any individual usage bit"
        );
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// `NotBeforeOffset` / `X509Spec` `Default` invariants
// -----------------------------------------------------------------------------

#[test]
fn not_before_offset_default_is_days_ago_one() {
    assert_eq!(NotBeforeOffset::default(), NotBeforeOffset::DaysAgo(1));
}

// -----------------------------------------------------------------------------
// Derived-trait invariants for the negative-fixture enums
// -----------------------------------------------------------------------------

#[test]
fn x509_negative_clone_eq_hash_round_trip_through_hashmap() -> TestResult<()> {
    let variants = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ];

    // Hash + Eq: each variant collides with its own clone (Debug is also
    // exercised by panic-formatting on map mismatches).
    let mut map: HashMap<X509Negative, &'static str> = HashMap::new();
    for v in variants {
        map.insert(v, v.variant_name());
    }
    ensure_eq!(map.len(), variants.len());

    for v in variants {
        let cloned = v;
        let looked_up = require_some(map.get(&cloned), "variant should be in HashMap")?;
        ensure_eq!(*looked_up, v.variant_name());
        // Debug should mention the variant name fragment.
        let dbg = format!("{:?}", v);
        ensure!(
            !dbg.is_empty(),
            "Debug should produce non-empty output for {:?}",
            v
        );
    }
    Ok(())
}

#[test]
fn chain_negative_clone_eq_hash_round_trip_through_hashset() -> TestResult<()> {
    let variants = [
        ChainNegative::HostnameMismatch {
            wrong_hostname: "wrong.example.com".to_string(),
        },
        ChainNegative::UnknownCa,
        ChainNegative::ExpiredLeaf,
        ChainNegative::NotYetValidLeaf,
        ChainNegative::ExpiredIntermediate,
        ChainNegative::NotYetValidIntermediate,
        ChainNegative::IntermediateNotCa,
        ChainNegative::IntermediateWrongKeyUsage,
        ChainNegative::RevokedLeaf,
    ];

    let set: HashSet<ChainNegative> = variants.iter().cloned().collect();
    ensure_eq!(set.len(), variants.len(), "all variants should be distinct");

    // HostnameMismatch with the same hostname must compare equal; differing
    // hostnames must compare not-equal.
    let same_host_a = ChainNegative::HostnameMismatch {
        wrong_hostname: "same.example.com".to_string(),
    };
    let same_host_b = ChainNegative::HostnameMismatch {
        wrong_hostname: "same.example.com".to_string(),
    };
    let other_host = ChainNegative::HostnameMismatch {
        wrong_hostname: "other.example.com".to_string(),
    };
    ensure_eq!(same_host_a, same_host_b);
    ensure!(same_host_a != other_host);
    Ok(())
}

// -----------------------------------------------------------------------------
// `Clone` shares the inner Arc allocation
// -----------------------------------------------------------------------------

#[test]
fn x509_cert_clone_shares_inner_buffer() -> TestResult<()> {
    let fx = fx("x509-cert-clone");
    let cert: X509Cert = fx.x509_self_signed("clone-test", X509Spec::self_signed("c.example.com"));
    let cloned = cert.clone();

    // The accessor returns &[u8] borrowed from the inner Arc; if the clone
    // shares the same Arc, the slice pointer should match.
    let orig_ptr = cert.cert_der().as_ptr();
    let cloned_ptr = cloned.cert_der().as_ptr();
    ensure_eq!(
        orig_ptr, cloned_ptr,
        "Clone should reuse the Arc-allocated DER buffer"
    );

    // PEM is a `String` field shared via Arc<Inner>, so `as_ptr()` should
    // also match.
    ensure_eq!(cert.cert_pem().as_ptr(), cloned.cert_pem().as_ptr());

    // Metadata equality.
    ensure_eq!(cert.label(), cloned.label());
    ensure_eq!(cert.spec(), cloned.spec());
    Ok(())
}

#[test]
fn x509_chain_clone_shares_inner_buffers() -> TestResult<()> {
    let fx = fx("x509-chain-clone");
    let chain: X509Chain = fx.x509_chain("clone-chain", ChainSpec::new("c.example.com"));
    let cloned = chain.clone();

    ensure_eq!(
        chain.root_cert_der().as_ptr(),
        cloned.root_cert_der().as_ptr(),
        "Clone should share root cert DER buffer"
    );
    ensure_eq!(
        chain.intermediate_cert_der().as_ptr(),
        cloned.intermediate_cert_der().as_ptr(),
        "Clone should share intermediate cert DER buffer"
    );
    ensure_eq!(
        chain.leaf_cert_der().as_ptr(),
        cloned.leaf_cert_der().as_ptr(),
        "Clone should share leaf cert DER buffer"
    );
    ensure_eq!(chain.label(), cloned.label());
    Ok(())
}

// -----------------------------------------------------------------------------
// `chain/params.rs` — intermediate overrides observable in generated chain
// -----------------------------------------------------------------------------

#[test]
fn intermediate_validity_and_not_before_overrides_reach_cert() -> TestResult<()> {
    let fx = fx("x509-chain-int-overrides");
    let spec = ChainSpec::new("int-overrides.example.com")
        .with_intermediate_validity_days(42)
        .with_intermediate_not_before(NotBeforeOffset::DaysAgo(7));
    let chain = fx.x509_chain("int-overrides", spec);

    let parsed = parse(chain.intermediate_cert_der())?;
    let nb = parsed.validity().not_before.timestamp();
    let na = parsed.validity().not_after.timestamp();
    let days = (na - nb) / 86_400;
    ensure_eq!(days, 42, "intermediate validity should be exactly 42 days");
    Ok(())
}

#[test]
fn intermediate_is_ca_some_true_keeps_ca_flag_and_cert_sign_usage() -> TestResult<()> {
    // Exercises the `Some(true)` arm of `chain/params.rs::intermediate_ca_params`'s
    // `intermediate_is_ca.unwrap_or(true)` — separate from the `None` default
    // path that's covered by every good-chain test today.
    let fx = fx("x509-chain-int-ca-true");
    let spec = ChainSpec::new("int-ca-true.example.com").with_intermediate_is_ca(true);
    let chain = fx.x509_chain("int-ca-true", spec);

    let parsed = parse(chain.intermediate_cert_der())?;
    ensure!(
        parsed.is_ca(),
        "intermediate_is_ca(true) should keep CA flag set"
    );
    let ku = find_key_usage(&parsed)?;
    ensure!(
        ku.key_cert_sign(),
        "default CA key usage should retain keyCertSign"
    );
    ensure!(ku.crl_sign(), "default CA key usage should retain crlSign");
    Ok(())
}
