//! Insta snapshot tests for uselesskey-core-seed.
//!
//! Snapshot seed derivation metadata — debug redaction, parsing behavior.
//! No actual seed bytes are captured.

use serde::Serialize;
use uselesskey_core_seed::Seed;

#[test]
fn snapshot_seed_debug_redaction() {
    #[derive(Serialize)]
    struct SeedDebug {
        debug_output: String,
        contains_redacted: bool,
        does_not_contain_bytes: bool,
    }

    let seed = Seed::new([0xABu8; 32]);
    let dbg = format!("{:?}", seed);

    let result = SeedDebug {
        debug_output: dbg.clone(),
        contains_redacted: dbg.contains("redacted"),
        does_not_contain_bytes: !dbg.contains("AB") && !dbg.contains("ab"),
    };

    insta::assert_yaml_snapshot!("seed_debug_redaction", result);
}

#[test]
fn snapshot_seed_from_env_formats() {
    #[derive(Serialize)]
    struct EnvParseResult {
        input_description: &'static str,
        parsed_ok: bool,
        seed_len: usize,
    }

    let results: Vec<EnvParseResult> = vec![
        {
            let seed = Seed::from_env_value("my-test-seed").unwrap();
            EnvParseResult {
                input_description: "plain string (hashed via BLAKE3)",
                parsed_ok: true,
                seed_len: seed.bytes().len(),
            }
        },
        {
            let hex = "0".repeat(64);
            let seed = Seed::from_env_value(&hex).unwrap();
            EnvParseResult {
                input_description: "64-char hex string",
                parsed_ok: true,
                seed_len: seed.bytes().len(),
            }
        },
        {
            let hex = format!("0x{}", "FF".repeat(32));
            let seed = Seed::from_env_value(&hex).unwrap();
            EnvParseResult {
                input_description: "0x-prefixed hex string",
                parsed_ok: true,
                seed_len: seed.bytes().len(),
            }
        },
        {
            let seed = Seed::from_env_value("  whitespace-padded  ").unwrap();
            EnvParseResult {
                input_description: "whitespace-padded string",
                parsed_ok: true,
                seed_len: seed.bytes().len(),
            }
        },
    ];

    insta::assert_yaml_snapshot!("seed_env_parse_formats", results);
}

#[test]
fn snapshot_seed_determinism() {
    #[derive(Serialize)]
    struct SeedDeterminism {
        same_string_matches: bool,
        different_string_differs: bool,
        byte_count: usize,
    }

    let a = Seed::from_env_value("deterministic").unwrap();
    let b = Seed::from_env_value("deterministic").unwrap();
    let c = Seed::from_env_value("different").unwrap();

    let result = SeedDeterminism {
        same_string_matches: a.bytes() == b.bytes(),
        different_string_differs: a.bytes() != c.bytes(),
        byte_count: a.bytes().len(),
    };

    insta::assert_yaml_snapshot!("seed_determinism", result);
}
