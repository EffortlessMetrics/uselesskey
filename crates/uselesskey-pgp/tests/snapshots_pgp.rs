//! Insta snapshot tests for uselesskey-pgp.
//!
//! These tests snapshot key metadata produced by deterministic keys
//! to detect unintended changes in armored format, fingerprint shape,
//! algorithm, and negative-fixture behaviour. Actual key material is
//! never snapshotted.

mod testutil;

use serde::Serialize;
use testutil::fx;
use uselesskey_core::negative::CorruptPem;
use uselesskey_pgp::{PgpFactoryExt, PgpSpec};

// =========================================================================
// Snapshot structs
// =========================================================================

#[derive(Serialize)]
struct ArmoredShape {
    spec: &'static str,
    private_has_begin: bool,
    private_has_end: bool,
    private_line_count: usize,
    private_armor_len: usize,
    public_has_begin: bool,
    public_has_end: bool,
    public_line_count: usize,
    public_armor_len: usize,
}

#[derive(Serialize)]
struct FingerprintShape {
    spec: &'static str,
    fingerprint_len: usize,
    fingerprint_is_hex: bool,
}

#[derive(Serialize)]
struct BinaryLengths {
    spec: &'static str,
    private_binary_len: usize,
    public_binary_len: usize,
}

#[derive(Serialize)]
struct UserIdShape {
    user_id_contains_label: bool,
    user_id_contains_domain: bool,
    user_id_len: usize,
}

#[derive(Serialize)]
struct LabelDivergence {
    fingerprints_differ: bool,
    private_armor_differs: bool,
    public_armor_differs: bool,
    private_binary_differs: bool,
    public_binary_differs: bool,
}

#[derive(Serialize)]
struct SpecDivergence {
    ed25519_vs_rsa2048_fingerprint_differs: bool,
    ed25519_vs_rsa3072_fingerprint_differs: bool,
    rsa2048_vs_rsa3072_fingerprint_differs: bool,
}

#[derive(Serialize)]
struct MismatchShape {
    good_public_binary_len: usize,
    mismatched_public_binary_len: usize,
    binary_keys_differ: bool,
    armored_keys_differ: bool,
}

#[derive(Serialize)]
struct CorruptPemShape {
    variant: &'static str,
    has_begin_line: bool,
    has_end_line: bool,
    differs_from_original: bool,
}

#[derive(Serialize)]
struct TruncatedBinaryShape {
    requested_len: usize,
    actual_len: usize,
    shorter_than_original: bool,
}

#[derive(Serialize)]
struct DeterministicCorruptionShape {
    armor_differs_from_good: bool,
    armor_starts_with_dash: bool,
    armor_stable: bool,
    binary_differs_from_good: bool,
    binary_same_len_as_good: bool,
    binary_stable: bool,
}

#[derive(Serialize)]
struct DeterminismShape {
    fingerprints_match: bool,
    private_armor_matches: bool,
    public_armor_matches: bool,
    private_binary_matches: bool,
    public_binary_matches: bool,
}

#[derive(Serialize)]
struct DebugSafety {
    contains_struct_name: bool,
    contains_label: bool,
    contains_private_armor_header: bool,
    contains_public_armor_header: bool,
    uses_non_exhaustive: bool,
}

#[derive(Serialize)]
struct TempfileShape {
    private_tempfile_matches_armor: bool,
    public_tempfile_matches_armor: bool,
}

// =========================================================================
// Armored output shape — Ed25519
// =========================================================================

#[test]
fn snapshot_armored_shape_ed25519() {
    let fx = fx();
    let key = fx.pgp("snap-armor-ed", PgpSpec::ed25519());

    let result = ArmoredShape {
        spec: "ed25519",
        private_has_begin: key
            .private_key_armored()
            .contains("BEGIN PGP PRIVATE KEY BLOCK"),
        private_has_end: key
            .private_key_armored()
            .contains("END PGP PRIVATE KEY BLOCK"),
        private_line_count: key.private_key_armored().lines().count(),
        private_armor_len: key.private_key_armored().len(),
        public_has_begin: key
            .public_key_armored()
            .contains("BEGIN PGP PUBLIC KEY BLOCK"),
        public_has_end: key
            .public_key_armored()
            .contains("END PGP PUBLIC KEY BLOCK"),
        public_line_count: key.public_key_armored().lines().count(),
        public_armor_len: key.public_key_armored().len(),
    };

    insta::assert_yaml_snapshot!("armored_shape_ed25519", result);
}

// =========================================================================
// Armored output shape — RSA 2048
// =========================================================================

#[test]
fn snapshot_armored_shape_rsa2048() {
    let fx = fx();
    let key = fx.pgp("snap-armor-rsa2", PgpSpec::rsa_2048());

    let result = ArmoredShape {
        spec: "rsa2048",
        private_has_begin: key
            .private_key_armored()
            .contains("BEGIN PGP PRIVATE KEY BLOCK"),
        private_has_end: key
            .private_key_armored()
            .contains("END PGP PRIVATE KEY BLOCK"),
        private_line_count: key.private_key_armored().lines().count(),
        private_armor_len: key.private_key_armored().len(),
        public_has_begin: key
            .public_key_armored()
            .contains("BEGIN PGP PUBLIC KEY BLOCK"),
        public_has_end: key
            .public_key_armored()
            .contains("END PGP PUBLIC KEY BLOCK"),
        public_line_count: key.public_key_armored().lines().count(),
        public_armor_len: key.public_key_armored().len(),
    };

    insta::assert_yaml_snapshot!("armored_shape_rsa2048", result);
}

// =========================================================================
// Fingerprint shape
// =========================================================================

#[test]
fn snapshot_fingerprint_shape_ed25519() {
    let fx = fx();
    let key = fx.pgp("snap-fp-ed", PgpSpec::ed25519());
    let fp = key.fingerprint();

    let result = FingerprintShape {
        spec: "ed25519",
        fingerprint_len: fp.len(),
        fingerprint_is_hex: fp.chars().all(|c| c.is_ascii_hexdigit() || c == ' '),
    };

    insta::assert_yaml_snapshot!("fingerprint_shape_ed25519", result);
}

#[test]
fn snapshot_fingerprint_shape_rsa2048() {
    let fx = fx();
    let key = fx.pgp("snap-fp-rsa2", PgpSpec::rsa_2048());
    let fp = key.fingerprint();

    let result = FingerprintShape {
        spec: "rsa2048",
        fingerprint_len: fp.len(),
        fingerprint_is_hex: fp.chars().all(|c| c.is_ascii_hexdigit() || c == ' '),
    };

    insta::assert_yaml_snapshot!("fingerprint_shape_rsa2048", result);
}

// =========================================================================
// Binary lengths
// =========================================================================

#[test]
fn snapshot_binary_lengths() {
    let fx = fx();

    let entries: Vec<BinaryLengths> = [
        ("ed25519", PgpSpec::ed25519()),
        ("rsa2048", PgpSpec::rsa_2048()),
    ]
    .into_iter()
    .map(|(name, spec)| {
        let key = fx.pgp("snap-binlen", spec);
        BinaryLengths {
            spec: name,
            private_binary_len: key.private_key_binary().len(),
            public_binary_len: key.public_key_binary().len(),
        }
    })
    .collect();

    insta::assert_yaml_snapshot!("binary_lengths", entries);
}

// =========================================================================
// User ID shape
// =========================================================================

#[test]
fn snapshot_user_id_shape() {
    let fx = fx();
    let key = fx.pgp("my-service", PgpSpec::ed25519());

    let result = UserIdShape {
        user_id_contains_label: key.user_id().contains("my-service"),
        user_id_contains_domain: key.user_id().contains("@uselesskey.test"),
        user_id_len: key.user_id().len(),
    };

    insta::assert_yaml_snapshot!("user_id_shape", result);
}

// =========================================================================
// Label divergence
// =========================================================================

#[test]
fn snapshot_label_divergence() {
    let fx = fx();
    let a = fx.pgp("label-a", PgpSpec::ed25519());
    let b = fx.pgp("label-b", PgpSpec::ed25519());

    let result = LabelDivergence {
        fingerprints_differ: a.fingerprint() != b.fingerprint(),
        private_armor_differs: a.private_key_armored() != b.private_key_armored(),
        public_armor_differs: a.public_key_armored() != b.public_key_armored(),
        private_binary_differs: a.private_key_binary() != b.private_key_binary(),
        public_binary_differs: a.public_key_binary() != b.public_key_binary(),
    };

    insta::assert_yaml_snapshot!("label_divergence", result);
}

// =========================================================================
// Spec divergence
// =========================================================================

#[test]
fn snapshot_spec_divergence() {
    let fx = fx();
    let ed = fx.pgp("spec-div", PgpSpec::ed25519());
    let rsa2 = fx.pgp("spec-div", PgpSpec::rsa_2048());
    let rsa3 = fx.pgp("spec-div", PgpSpec::rsa_3072());

    let result = SpecDivergence {
        ed25519_vs_rsa2048_fingerprint_differs: ed.fingerprint() != rsa2.fingerprint(),
        ed25519_vs_rsa3072_fingerprint_differs: ed.fingerprint() != rsa3.fingerprint(),
        rsa2048_vs_rsa3072_fingerprint_differs: rsa2.fingerprint() != rsa3.fingerprint(),
    };

    insta::assert_yaml_snapshot!("spec_divergence", result);
}

// =========================================================================
// Mismatch shape
// =========================================================================

#[test]
fn snapshot_mismatch_shape() {
    let fx = fx();
    let key = fx.pgp("snap-mismatch", PgpSpec::ed25519());
    let good_bin = key.public_key_binary();
    let mismatch_bin = key.mismatched_public_key_binary();
    let good_arm = key.public_key_armored();
    let mismatch_arm = key.mismatched_public_key_armored();

    let result = MismatchShape {
        good_public_binary_len: good_bin.len(),
        mismatched_public_binary_len: mismatch_bin.len(),
        binary_keys_differ: good_bin != mismatch_bin.as_slice(),
        armored_keys_differ: good_arm != mismatch_arm,
    };

    insta::assert_yaml_snapshot!("mismatch_shape", result);
}

// =========================================================================
// Corrupt PEM variants
// =========================================================================

#[test]
fn snapshot_corrupt_pem_variants() {
    let fx = fx();
    let key = fx.pgp("snap-corrupt", PgpSpec::ed25519());
    let original = key.private_key_armored();

    let variants: Vec<(&str, CorruptPem)> = vec![
        ("BadHeader", CorruptPem::BadHeader),
        ("BadFooter", CorruptPem::BadFooter),
        ("BadBase64", CorruptPem::BadBase64),
        ("ExtraBlankLine", CorruptPem::ExtraBlankLine),
    ];

    let entries: Vec<CorruptPemShape> = variants
        .into_iter()
        .map(|(name, how)| {
            let corrupt = key.private_key_armored_corrupt(how);
            CorruptPemShape {
                variant: name,
                has_begin_line: corrupt.contains("-----BEGIN"),
                has_end_line: corrupt.contains("-----END"),
                differs_from_original: corrupt != original,
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("corrupt_pem_variants", entries);
}

// =========================================================================
// Truncated binary
// =========================================================================

#[test]
fn snapshot_truncated_binary() {
    let fx = fx();
    let key = fx.pgp("snap-truncated", PgpSpec::ed25519());
    let original_len = key.private_key_binary().len();

    let lengths: Vec<usize> = vec![0, 1, 10, 32];

    let entries: Vec<TruncatedBinaryShape> = lengths
        .into_iter()
        .map(|len| {
            let truncated = key.private_key_binary_truncated(len);
            TruncatedBinaryShape {
                requested_len: len,
                actual_len: truncated.len(),
                shorter_than_original: truncated.len() < original_len,
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("truncated_binary", entries);
}

// =========================================================================
// Deterministic corruption
// =========================================================================

#[test]
fn snapshot_deterministic_corruption() {
    let fx = fx();
    let key = fx.pgp("snap-det-corrupt", PgpSpec::ed25519());
    let good_armor = key.private_key_armored();
    let good_binary = key.private_key_binary();

    let armor_a = key.private_key_armored_corrupt_deterministic("corrupt:v1");
    let armor_b = key.private_key_armored_corrupt_deterministic("corrupt:v1");
    let binary_a = key.private_key_binary_corrupt_deterministic("corrupt:v1");
    let binary_b = key.private_key_binary_corrupt_deterministic("corrupt:v1");

    let result = DeterministicCorruptionShape {
        armor_differs_from_good: armor_a != good_armor,
        armor_starts_with_dash: armor_a.starts_with('-'),
        armor_stable: armor_a == armor_b,
        binary_differs_from_good: binary_a != good_binary,
        binary_same_len_as_good: binary_a.len() == good_binary.len(),
        binary_stable: binary_a == binary_b,
    };

    insta::assert_yaml_snapshot!("deterministic_corruption", result);
}

// =========================================================================
// Determinism (same seed → same output)
// =========================================================================

#[test]
fn snapshot_determinism() {
    use uselesskey_core::{Factory, Seed};

    let seed1 = Seed::from_env_value("pgp-snap-det").unwrap();
    let seed2 = Seed::from_env_value("pgp-snap-det").unwrap();
    let fx1 = Factory::deterministic(seed1);
    let fx2 = Factory::deterministic(seed2);

    let k1 = fx1.pgp("det-check", PgpSpec::ed25519());
    let k2 = fx2.pgp("det-check", PgpSpec::ed25519());

    let result = DeterminismShape {
        fingerprints_match: k1.fingerprint() == k2.fingerprint(),
        private_armor_matches: k1.private_key_armored() == k2.private_key_armored(),
        public_armor_matches: k1.public_key_armored() == k2.public_key_armored(),
        private_binary_matches: k1.private_key_binary() == k2.private_key_binary(),
        public_binary_matches: k1.public_key_binary() == k2.public_key_binary(),
    };

    insta::assert_yaml_snapshot!("determinism", result);
}

// =========================================================================
// Debug safety
// =========================================================================

#[test]
fn snapshot_debug_safety() {
    let fx = fx();
    let key = fx.pgp("debug-snap", PgpSpec::ed25519());
    let dbg = format!("{key:?}");

    let result = DebugSafety {
        contains_struct_name: dbg.contains("PgpKeyPair"),
        contains_label: dbg.contains("debug-snap"),
        contains_private_armor_header: dbg.contains("BEGIN PGP PRIVATE KEY BLOCK"),
        contains_public_armor_header: dbg.contains("BEGIN PGP PUBLIC KEY BLOCK"),
        uses_non_exhaustive: dbg.contains(".."),
    };

    insta::assert_yaml_snapshot!("debug_safety", result);
}

// =========================================================================
// Tempfile shape
// =========================================================================

#[test]
fn snapshot_tempfile_shape() {
    let fx = fx();
    let key = fx.pgp("snap-tempfile", PgpSpec::ed25519());

    let priv_tf = key.write_private_key_armored().expect("private tempfile");
    let pub_tf = key.write_public_key_armored().expect("public tempfile");

    let priv_contents = std::fs::read_to_string(priv_tf.path()).expect("read private");
    let pub_contents = std::fs::read_to_string(pub_tf.path()).expect("read public");

    let result = TempfileShape {
        private_tempfile_matches_armor: priv_contents == key.private_key_armored(),
        public_tempfile_matches_armor: pub_contents == key.public_key_armored(),
    };

    insta::assert_yaml_snapshot!("tempfile_shape", result);
}
