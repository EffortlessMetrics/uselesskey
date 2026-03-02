//! Insta snapshot tests for uselesskey-pgp.
//!
//! These tests snapshot PGP key metadata produced by deterministic fixtures
//! to detect unintended changes in output shape.
//! CRITICAL: No actual key bytes appear in snapshots — all crypto material is redacted.

mod testutil;

use serde::Serialize;
use testutil::fx;
use uselesskey_pgp::{PgpFactoryExt, PgpSpec};

// =========================================================================
// Ed25519 PGP snapshots
// =========================================================================

mod ed25519_snapshots {
    use super::*;

    #[derive(Serialize)]
    struct PgpKeySnapshot {
        spec: &'static str,
        user_id: String,
        fingerprint_len: usize,
        private_armor_has_begin: bool,
        private_armor_has_end: bool,
        public_armor_has_begin: bool,
        public_armor_has_end: bool,
        private_binary_len: usize,
        public_binary_len: usize,
        private_armor: String,
        public_armor: String,
        fingerprint: String,
    }

    #[test]
    fn snapshot_pgp_ed25519_key_metadata() {
        let fx = fx();
        let key = fx.pgp("snapshot-ed25519", PgpSpec::ed25519());

        let result = PgpKeySnapshot {
            spec: "ed25519",
            user_id: key.user_id().to_string(),
            fingerprint_len: key.fingerprint().len(),
            private_armor_has_begin: key
                .private_key_armored()
                .contains("BEGIN PGP PRIVATE KEY BLOCK"),
            private_armor_has_end: key
                .private_key_armored()
                .contains("END PGP PRIVATE KEY BLOCK"),
            public_armor_has_begin: key
                .public_key_armored()
                .contains("BEGIN PGP PUBLIC KEY BLOCK"),
            public_armor_has_end: key
                .public_key_armored()
                .contains("END PGP PUBLIC KEY BLOCK"),
            private_binary_len: key.private_key_binary().len(),
            public_binary_len: key.public_key_binary().len(),
            private_armor: key.private_key_armored().to_string(),
            public_armor: key.public_key_armored().to_string(),
            fingerprint: key.fingerprint().to_string(),
        };

        insta::assert_yaml_snapshot!("pgp_ed25519_key_metadata", result, {
            ".private_armor" => "[REDACTED]",
            ".public_armor" => "[REDACTED]",
            ".fingerprint" => "[REDACTED]",
        });
    }
}

// =========================================================================
// RSA 2048 PGP snapshots
// =========================================================================

mod rsa_2048_snapshots {
    use super::*;

    #[derive(Serialize)]
    struct PgpKeySnapshot {
        spec: &'static str,
        user_id: String,
        fingerprint_len: usize,
        private_armor_has_begin: bool,
        public_armor_has_begin: bool,
        private_binary_len: usize,
        public_binary_len: usize,
        private_armor: String,
        public_armor: String,
        fingerprint: String,
    }

    #[test]
    fn snapshot_pgp_rsa_2048_key_metadata() {
        let fx = fx();
        let key = fx.pgp("snapshot-rsa-2048", PgpSpec::rsa_2048());

        let result = PgpKeySnapshot {
            spec: "rsa2048",
            user_id: key.user_id().to_string(),
            fingerprint_len: key.fingerprint().len(),
            private_armor_has_begin: key
                .private_key_armored()
                .contains("BEGIN PGP PRIVATE KEY BLOCK"),
            public_armor_has_begin: key
                .public_key_armored()
                .contains("BEGIN PGP PUBLIC KEY BLOCK"),
            private_binary_len: key.private_key_binary().len(),
            public_binary_len: key.public_key_binary().len(),
            private_armor: key.private_key_armored().to_string(),
            public_armor: key.public_key_armored().to_string(),
            fingerprint: key.fingerprint().to_string(),
        };

        insta::assert_yaml_snapshot!("pgp_rsa_2048_key_metadata", result, {
            ".private_armor" => "[REDACTED]",
            ".public_armor" => "[REDACTED]",
            ".fingerprint" => "[REDACTED]",
        });
    }
}

// =========================================================================
// RSA 3072 PGP snapshots
// =========================================================================

mod rsa_3072_snapshots {
    use super::*;

    #[derive(Serialize)]
    struct PgpKeySnapshot {
        spec: &'static str,
        user_id: String,
        fingerprint_len: usize,
        private_binary_len: usize,
        public_binary_len: usize,
        private_armor: String,
        fingerprint: String,
    }

    #[test]
    fn snapshot_pgp_rsa_3072_key_metadata() {
        let fx = fx();
        let key = fx.pgp("snapshot-rsa-3072", PgpSpec::rsa_3072());

        let result = PgpKeySnapshot {
            spec: "rsa3072",
            user_id: key.user_id().to_string(),
            fingerprint_len: key.fingerprint().len(),
            private_binary_len: key.private_key_binary().len(),
            public_binary_len: key.public_key_binary().len(),
            private_armor: key.private_key_armored().to_string(),
            fingerprint: key.fingerprint().to_string(),
        };

        insta::assert_yaml_snapshot!("pgp_rsa_3072_key_metadata", result, {
            ".private_armor" => "[REDACTED]",
            ".fingerprint" => "[REDACTED]",
        });
    }
}

// =========================================================================
// User ID sanitization snapshots
// =========================================================================

mod user_id_snapshots {
    use super::*;

    #[test]
    fn snapshot_pgp_user_id_formats() {
        let fx = fx();

        #[derive(Serialize)]
        struct UserIdEntry {
            label: String,
            user_id: String,
        }

        let cases: Vec<UserIdEntry> = ["simple-label", "Test User!@#", "ALL CAPS", "with spaces"]
            .into_iter()
            .map(|label| {
                let key = fx.pgp(label, PgpSpec::ed25519());
                UserIdEntry {
                    label: label.to_string(),
                    user_id: key.user_id().to_string(),
                }
            })
            .collect();

        insta::assert_yaml_snapshot!("pgp_user_id_formats", cases);
    }
}

// =========================================================================
// Negative fixture snapshots
// =========================================================================

mod negative_snapshots {
    use super::*;

    #[test]
    fn snapshot_pgp_mismatch_metadata() {
        let fx = fx();
        let key = fx.pgp("snapshot-mismatch", PgpSpec::ed25519());

        #[derive(Serialize)]
        struct MismatchSnapshot {
            original_public_binary_len: usize,
            mismatched_public_binary_len: usize,
            keys_differ: bool,
            mismatched_armor_has_begin: bool,
        }

        let mismatch_bin = key.mismatched_public_key_binary();
        let mismatch_arm = key.mismatched_public_key_armored();

        let result = MismatchSnapshot {
            original_public_binary_len: key.public_key_binary().len(),
            mismatched_public_binary_len: mismatch_bin.len(),
            keys_differ: mismatch_bin != key.public_key_binary(),
            mismatched_armor_has_begin: mismatch_arm.contains("BEGIN PGP PUBLIC KEY BLOCK"),
        };

        insta::assert_yaml_snapshot!("pgp_mismatch_metadata", result);
    }

    #[test]
    fn snapshot_pgp_truncated_binary() {
        let fx = fx();
        let key = fx.pgp("snapshot-truncated", PgpSpec::ed25519());

        #[derive(Serialize)]
        struct TruncatedSnapshot {
            original_len: usize,
            truncated_len: usize,
        }

        let result = TruncatedSnapshot {
            original_len: key.private_key_binary().len(),
            truncated_len: key.private_key_binary_truncated(32).len(),
        };

        insta::assert_yaml_snapshot!("pgp_truncated_binary", result);
    }

    #[test]
    fn snapshot_pgp_corrupt_armor() {
        let fx = fx();
        let key = fx.pgp("snapshot-corrupt", PgpSpec::ed25519());

        #[derive(Serialize)]
        struct CorruptArmorSnapshot {
            original_starts_with_dash: bool,
            corrupt_differs_from_original: bool,
            corrupt_deterministic_is_stable: bool,
        }

        let det_a = key.private_key_armored_corrupt_deterministic("corrupt:snap-v1");
        let det_b = key.private_key_armored_corrupt_deterministic("corrupt:snap-v1");

        let result = CorruptArmorSnapshot {
            original_starts_with_dash: key.private_key_armored().starts_with('-'),
            corrupt_differs_from_original: det_a != key.private_key_armored(),
            corrupt_deterministic_is_stable: det_a == det_b,
        };

        insta::assert_yaml_snapshot!("pgp_corrupt_armor", result);
    }
}

// =========================================================================
// All specs comparison snapshot
// =========================================================================

mod all_specs_snapshots {
    use super::*;

    #[test]
    fn snapshot_pgp_all_specs_comparison() {
        let fx = fx();

        #[derive(Serialize)]
        struct SpecInfo {
            spec_name: &'static str,
            private_binary_len: usize,
            public_binary_len: usize,
            fingerprint_len: usize,
        }

        let cases: Vec<SpecInfo> = [
            ("ed25519", PgpSpec::ed25519()),
            ("rsa2048", PgpSpec::rsa_2048()),
            ("rsa3072", PgpSpec::rsa_3072()),
        ]
        .into_iter()
        .map(|(name, spec)| {
            let key = fx.pgp(format!("snapshot-all-{name}"), spec);
            SpecInfo {
                spec_name: name,
                private_binary_len: key.private_key_binary().len(),
                public_binary_len: key.public_key_binary().len(),
                fingerprint_len: key.fingerprint().len(),
            }
        })
        .collect();

        insta::assert_yaml_snapshot!("pgp_all_specs_comparison", cases);
    }
}
