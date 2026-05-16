//! Coverage for previously-untested PGP surfaces:
//!
//! - `write_private_key_armored` / `write_public_key_armored` tempfile sinks
//!   (Result-returning paths and the bytes they write).
//! - `CorruptPem` variants beyond `BadBase64` / `BadHeader` applied through
//!   `private_key_armored_corrupt` (only 2 of the 5 strategies were exercised).
//! - `private_key_armored_corrupt_deterministic` and
//!   `private_key_binary_corrupt_deterministic` produce shape-distinct outputs
//!   when the variant string changes (existing tests only checked stability for
//!   one variant string).
//! - `private_key_binary_truncated` boundary lengths (0, larger than input).
//! - Mismatched-public-key cache identity (repeated calls hit the same cache
//!   slot) and per-label isolation, including for RSA specs that other tests
//!   only touch in the positive direction.
//! - `Clone` on `PgpKeyPair` shares the underlying inner state by Arc, so
//!   accessor pointers are identical without re-deriving.

use std::collections::HashSet;
use std::io::Cursor;

use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};
use pgp::types::KeyDetails;
use uselesskey_core::Factory;
use uselesskey_core::negative::CorruptPem;
use uselesskey_pgp::{PgpFactoryExt, PgpSpec};

// -----------------------------------------------------------------------------
// Tempfile writers
// -----------------------------------------------------------------------------

#[test]
fn write_private_key_armored_round_trips_through_tempfile() {
    let fx = Factory::deterministic_from_str("pgp-write-private");
    let key = fx.pgp("writer-priv", PgpSpec::ed25519());

    let temp_res = key.write_private_key_armored();
    assert!(
        temp_res.is_ok(),
        "write_private_key_armored failed: {:?}",
        temp_res.as_ref().err()
    );
    let Ok(temp) = temp_res else { return };

    let path = temp.path();
    assert!(path.exists(), "tempfile must exist on disk");
    assert_eq!(
        path.extension().and_then(|s| s.to_str()),
        Some("asc"),
        "private key tempfile extension must be .asc"
    );

    let contents_res = temp.read_to_string();
    assert!(
        contents_res.is_ok(),
        "read_to_string failed: {:?}",
        contents_res.as_ref().err()
    );
    let Ok(contents) = contents_res else { return };

    assert_eq!(contents, key.private_key_armored());
    assert!(contents.contains("BEGIN PGP PRIVATE KEY BLOCK"));
}

#[test]
fn write_public_key_armored_round_trips_through_tempfile() {
    let fx = Factory::deterministic_from_str("pgp-write-public");
    let key = fx.pgp("writer-pub", PgpSpec::ed25519());

    let temp_res = key.write_public_key_armored();
    assert!(
        temp_res.is_ok(),
        "write_public_key_armored failed: {:?}",
        temp_res.as_ref().err()
    );
    let Ok(temp) = temp_res else { return };

    assert_eq!(
        temp.path().extension().and_then(|s| s.to_str()),
        Some("asc"),
        "public key tempfile extension must be .asc"
    );

    let contents_res = temp.read_to_string();
    assert!(
        contents_res.is_ok(),
        "read_to_string failed: {:?}",
        contents_res.as_ref().err()
    );
    let Ok(contents) = contents_res else { return };

    assert_eq!(contents, key.public_key_armored());
    assert!(contents.contains("BEGIN PGP PUBLIC KEY BLOCK"));
}

#[test]
fn write_private_and_public_tempfiles_have_distinct_paths() {
    let fx = Factory::deterministic_from_str("pgp-write-distinct");
    let key = fx.pgp("writer-distinct", PgpSpec::ed25519());

    let priv_res = key.write_private_key_armored();
    let pub_res = key.write_public_key_armored();
    assert!(priv_res.is_ok(), "private writer must succeed");
    assert!(pub_res.is_ok(), "public writer must succeed");

    let (Ok(priv_temp), Ok(pub_temp)) = (priv_res, pub_res) else {
        return;
    };

    assert_ne!(
        priv_temp.path(),
        pub_temp.path(),
        "separate writers must produce separate paths"
    );
}

// -----------------------------------------------------------------------------
// Untested CorruptPem strategies via the PGP wrapper
// -----------------------------------------------------------------------------

#[test]
fn corrupt_pem_bad_footer_replaces_end_marker() {
    let fx = Factory::deterministic_from_str("pgp-corrupt-footer");
    let key = fx.pgp("issuer", PgpSpec::ed25519());

    let corrupted = key.private_key_armored_corrupt(CorruptPem::BadFooter);
    assert!(corrupted.contains("-----END CORRUPTED KEY-----"));
    assert!(!corrupted.contains("END PGP PRIVATE KEY BLOCK"));
    assert!(SignedSecretKey::from_armor_single(Cursor::new(&corrupted)).is_err());
}

#[test]
fn corrupt_pem_truncate_caps_length_and_breaks_parser() {
    let fx = Factory::deterministic_from_str("pgp-corrupt-trunc");
    let key = fx.pgp("issuer", PgpSpec::ed25519());

    let budget = 64usize;
    let corrupted = key.private_key_armored_corrupt(CorruptPem::Truncate { bytes: budget });

    assert!(
        corrupted.len() <= budget,
        "truncate must respect byte budget"
    );
    assert_ne!(corrupted, key.private_key_armored());
    assert!(SignedSecretKey::from_armor_single(Cursor::new(&corrupted)).is_err());
}

#[test]
fn corrupt_pem_extra_blank_line_keeps_header_and_alters_body() {
    let fx = Factory::deterministic_from_str("pgp-corrupt-blank");
    let key = fx.pgp("issuer", PgpSpec::ed25519());

    let corrupted = key.private_key_armored_corrupt(CorruptPem::ExtraBlankLine);
    let original = key.private_key_armored();

    // Header is preserved and a blank line is injected right after it.
    assert!(corrupted.contains("BEGIN PGP PRIVATE KEY BLOCK"));
    assert_ne!(corrupted, original);
    assert!(
        corrupted.len() > original.len(),
        "blank-line injection must add at least one newline"
    );
}

// -----------------------------------------------------------------------------
// Deterministic corruption: variant string controls the shape
// -----------------------------------------------------------------------------

#[test]
fn deterministic_armored_corruption_varies_by_variant_string() {
    let fx = Factory::deterministic_from_str("pgp-det-armor-variants");
    let key = fx.pgp("issuer", PgpSpec::ed25519());

    // Use enough distinct variant strings that we land on at least two of the
    // five `corrupt_pem_deterministic` arms.
    let variants = [
        "corrupt:alpha",
        "corrupt:beta",
        "corrupt:gamma",
        "corrupt:delta",
        "corrupt:epsilon",
        "corrupt:zeta",
        "corrupt:eta",
        "corrupt:theta",
    ];

    let mut outputs = HashSet::new();
    for v in variants {
        outputs.insert(key.private_key_armored_corrupt_deterministic(v));
    }

    assert!(
        outputs.len() >= 2,
        "different variant strings must yield at least 2 distinct corruptions, got {}",
        outputs.len()
    );

    for out in &outputs {
        assert_ne!(
            out,
            key.private_key_armored(),
            "deterministic corruption must differ from the original"
        );
    }
}

#[test]
fn deterministic_binary_corruption_varies_by_variant_string() {
    let fx = Factory::deterministic_from_str("pgp-det-binary-variants");
    let key = fx.pgp("issuer", PgpSpec::ed25519());

    // Use enough variants to land on at least two of the three
    // `corrupt_der_deterministic` arms (truncate / flip / flip+truncate).
    let variants = [
        "corrupt:bin-a",
        "corrupt:bin-b",
        "corrupt:bin-c",
        "corrupt:bin-d",
        "corrupt:bin-e",
        "corrupt:bin-f",
    ];
    let mut outputs = HashSet::new();
    for v in variants {
        outputs.insert(key.private_key_binary_corrupt_deterministic(v));
    }

    assert!(
        outputs.len() >= 2,
        "different variant strings should yield distinct binary corruptions, got {}",
        outputs.len()
    );

    let original = key.private_key_binary();
    for out in &outputs {
        assert_ne!(
            out.as_slice(),
            original,
            "deterministic binary corruption must differ from the original"
        );
        assert!(
            out.len() <= original.len(),
            "corruption truncates or flips in-place; never grows the buffer"
        );
    }
}

// -----------------------------------------------------------------------------
// Truncation boundaries
// -----------------------------------------------------------------------------

#[test]
fn binary_truncated_to_zero_is_empty() {
    let fx = Factory::deterministic_from_str("pgp-trunc-zero");
    let key = fx.pgp("issuer", PgpSpec::ed25519());

    let truncated = key.private_key_binary_truncated(0);
    assert!(
        truncated.is_empty(),
        "len=0 truncation must yield empty bytes"
    );
    assert!(SignedSecretKey::from_bytes(Cursor::new(&truncated)).is_err());
}

#[test]
fn binary_truncated_above_input_length_returns_full_bytes() {
    let fx = Factory::deterministic_from_str("pgp-trunc-over");
    let key = fx.pgp("issuer", PgpSpec::ed25519());

    let original = key.private_key_binary();
    // Asking for a length beyond the input must yield the full input
    // verbatim (the helper saturates, it does not pad).
    let truncated = key.private_key_binary_truncated(original.len() + 1024);
    assert_eq!(truncated.as_slice(), original);
}

// -----------------------------------------------------------------------------
// Mismatch identity and per-label isolation
// -----------------------------------------------------------------------------

#[test]
fn mismatch_public_key_is_cached_per_identity() {
    let fx = Factory::deterministic_from_str("pgp-mismatch-cache");
    let key = fx.pgp("issuer", PgpSpec::ed25519());

    // Two calls must hit the cache and return byte-identical mismatches.
    let a = key.mismatched_public_key_binary();
    let b = key.mismatched_public_key_binary();
    assert_eq!(a, b, "mismatch variant must be cache-stable per call");

    let arm_a = key.mismatched_public_key_armored();
    let arm_b = key.mismatched_public_key_armored();
    assert_eq!(
        arm_a, arm_b,
        "mismatched armor must be cache-stable per call"
    );
}

#[test]
fn mismatch_differs_per_label() {
    let fx = Factory::deterministic_from_str("pgp-mismatch-per-label");

    let key_a = fx.pgp("alpha", PgpSpec::ed25519());
    let key_b = fx.pgp("beta", PgpSpec::ed25519());

    let m_a = key_a.mismatched_public_key_binary();
    let m_b = key_b.mismatched_public_key_binary();
    assert_ne!(m_a, m_b, "mismatch is derived per-label and must differ");
}

#[test]
fn mismatch_for_rsa_2048_parses_and_differs() {
    let fx = Factory::deterministic_from_str("pgp-mismatch-rsa");
    let key = fx.pgp("issuer", PgpSpec::rsa_2048());

    let mismatch = key.mismatched_public_key_binary();
    assert_ne!(mismatch, key.public_key_binary());

    // Parsing succeeds: the mismatch is a valid PGP public key, just one
    // that doesn't pair with this private key.
    let parsed_res = SignedPublicKey::from_bytes(Cursor::new(&mismatch));
    assert!(
        parsed_res.is_ok(),
        "mismatched RSA public binary must parse: {:?}",
        parsed_res.as_ref().err()
    );
    if let Ok(parsed) = parsed_res {
        assert_ne!(parsed.fingerprint().to_string(), key.fingerprint());
    }
}

// -----------------------------------------------------------------------------
// Clone semantics
// -----------------------------------------------------------------------------

#[test]
fn clone_shares_inner_state_without_redrive() {
    let fx = Factory::deterministic_from_str("pgp-clone-shared");
    let original = fx.pgp("issuer", PgpSpec::ed25519());
    let cloned = original.clone();

    // Accessor strings should refer to the same buffer (Arc-shared inner).
    let priv_orig_ptr = original.private_key_armored().as_ptr();
    let priv_clone_ptr = cloned.private_key_armored().as_ptr();
    assert_eq!(
        priv_orig_ptr, priv_clone_ptr,
        "cloned PgpKeyPair must share the Arc'd private armor buffer"
    );

    let pub_orig_ptr = original.public_key_binary().as_ptr();
    let pub_clone_ptr = cloned.public_key_binary().as_ptr();
    assert_eq!(
        pub_orig_ptr, pub_clone_ptr,
        "cloned PgpKeyPair must share the Arc'd public binary buffer"
    );

    assert_eq!(original.fingerprint(), cloned.fingerprint());
    assert_eq!(original.label(), cloned.label());
    assert_eq!(original.spec(), cloned.spec());
}
