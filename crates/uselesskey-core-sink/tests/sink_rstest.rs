//! Parameterized and edge-case tests for `uselesskey-core-sink` using rstest.
//!
//! Covers: parameterized creation/read-back, path properties, repeated reads,
//! external filesystem access, file metadata, and edge cases not exercised
//! by existing test files.

use std::collections::HashSet;
use std::path::PathBuf;

use rstest::rstest;
use uselesskey_core_sink::TempArtifact;

// ── Parameterized round-trip: various byte payloads ─────────────────

#[rstest]
#[case::empty(&[])]
#[case::single_byte(&[0x42])]
#[case::null_byte(&[0x00])]
#[case::all_zeros(&[0u8; 64])]
#[case::all_ones(&[0xFF; 64])]
#[case::der_header(&[0x30, 0x82, 0x01, 0x22])]
#[case::mixed_with_nulls(&[0x00, 0x01, 0x00, 0xFF, 0x00, 0xFE])]
fn bytes_round_trip_parameterized(#[case] data: &[u8]) {
    let temp = TempArtifact::new_bytes("uk-rs-", ".bin", data).unwrap();
    assert_eq!(temp.read_to_bytes().unwrap(), data);
}

// ── Parameterized round-trip: various string payloads ───────────────

#[rstest]
#[case::empty("")]
#[case::single_char("x")]
#[case::newline_only("\n")]
#[case::crlf("\r\n")]
#[case::pem_header("-----BEGIN PRIVATE KEY-----\n")]
#[case::pem_full("-----BEGIN PUBLIC KEY-----\nABCDEF==\n-----END PUBLIC KEY-----\n")]
#[case::unicode("🔑 clé — キー")]
#[case::whitespace_only("   \t\t\n\n  ")]
#[case::long_line(&"A".repeat(4096))]
fn string_round_trip_parameterized(#[case] text: &str) {
    let temp = TempArtifact::new_string("uk-rs-", ".txt", text).unwrap();
    assert_eq!(temp.read_to_string().unwrap(), text);
}

// ── Parameterized suffix verification ───────────────────────────────

#[rstest]
#[case::pem(".pem", "pem")]
#[case::der(".der", "der")]
#[case::txt(".txt", "txt")]
#[case::bin(".bin", "bin")]
#[case::crt(".crt", "crt")]
fn suffix_produces_expected_extension(#[case] suffix: &str, #[case] expected_ext: &str) {
    let temp = TempArtifact::new_bytes("uk-rs-", suffix, &[0x01]).unwrap();
    assert_eq!(
        temp.path().extension().and_then(|e| e.to_str()).unwrap(),
        expected_ext,
    );
}

// ── Path properties ─────────────────────────────────────────────────

#[test]
fn path_is_absolute() {
    let temp = TempArtifact::new_string("uk-abs-", ".pem", "data").unwrap();
    assert!(
        temp.path().is_absolute(),
        "tempfile path should be absolute: {:?}",
        temp.path()
    );
}

#[test]
fn path_parent_directory_exists() {
    let temp = TempArtifact::new_string("uk-dir-", ".pem", "data").unwrap();
    let parent = temp.path().parent().expect("path should have parent");
    assert!(parent.is_dir());
}

#[test]
fn path_is_stable_across_calls() {
    let temp = TempArtifact::new_string("uk-stable-", ".pem", "data").unwrap();
    let p1 = temp.path().to_path_buf();
    let p2 = temp.path().to_path_buf();
    assert_eq!(p1, p2, "path() must return the same value on every call");
}

// ── Repeated reads return identical content ─────────────────────────

#[test]
fn repeated_reads_are_idempotent() {
    let data = b"idempotent-content-check";
    let temp = TempArtifact::new_bytes("uk-idem-", ".bin", data).unwrap();

    for _ in 0..5 {
        assert_eq!(temp.read_to_bytes().unwrap(), data);
    }
}

#[test]
fn repeated_string_reads_are_idempotent() {
    let text = "repeat-read-test-ñ-ü-é";
    let temp = TempArtifact::new_string("uk-idem-", ".txt", text).unwrap();

    for _ in 0..5 {
        assert_eq!(temp.read_to_string().unwrap(), text);
    }
}

// ── External filesystem access (std::fs) matches API ────────────────

#[test]
fn std_fs_read_matches_read_to_bytes() {
    let data = vec![0xCA, 0xFE, 0xBA, 0xBE];
    let temp = TempArtifact::new_bytes("uk-fsrd-", ".bin", &data).unwrap();

    let via_api = temp.read_to_bytes().unwrap();
    let via_fs = std::fs::read(temp.path()).unwrap();
    assert_eq!(via_api, via_fs);
}

#[test]
fn std_fs_read_to_string_matches_api() {
    let text = "filesystem-vs-api-check";
    let temp = TempArtifact::new_string("uk-fsrd-", ".txt", text).unwrap();

    let via_api = temp.read_to_string().unwrap();
    let via_fs = std::fs::read_to_string(temp.path()).unwrap();
    assert_eq!(via_api, via_fs);
}

// ── File metadata ───────────────────────────────────────────────────

#[rstest]
#[case::empty(0, &[])]
#[case::small(5, &[1, 2, 3, 4, 5])]
#[case::medium(256, &[0xAB; 256])]
fn file_size_matches_written_content(#[case] expected_len: usize, #[case] data: &[u8]) {
    let temp = TempArtifact::new_bytes("uk-meta-", ".bin", data).unwrap();
    let metadata = std::fs::metadata(temp.path()).unwrap();
    assert_eq!(metadata.len() as usize, expected_len);
    assert!(metadata.is_file());
}

#[test]
fn file_is_not_a_directory() {
    let temp = TempArtifact::new_string("uk-meta-", ".pem", "data").unwrap();
    let metadata = std::fs::metadata(temp.path()).unwrap();
    assert!(metadata.is_file());
    assert!(!metadata.is_dir());
}

// ── Drop cleanup ────────────────────────────────────────────────────

#[test]
fn explicit_drop_cleans_up_file() {
    let temp = TempArtifact::new_string("uk-edrop-", ".pem", "explicit-drop").unwrap();
    let path = temp.path().to_path_buf();
    assert!(path.exists());

    drop(temp);

    // Retry for filesystem latency on Windows
    for _ in 0..10 {
        if !path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(!path.exists(), "file should be deleted after explicit drop");
}

#[test]
fn batch_drop_cleans_up_all_files() {
    let mut paths = Vec::new();
    let mut artifacts = Vec::new();

    for i in 0..10 {
        let content = format!("batch-item-{i}");
        let temp = TempArtifact::new_string("uk-batch-", ".tmp", &content).unwrap();
        paths.push(temp.path().to_path_buf());
        artifacts.push(temp);
    }

    for p in &paths {
        assert!(p.exists(), "all files should exist before drop");
    }

    drop(artifacts);

    std::thread::sleep(std::time::Duration::from_millis(100));
    for p in &paths {
        assert!(!p.exists(), "all files should be cleaned up: {p:?}");
    }
}

// ── Multiple simultaneous tempfiles ─────────────────────────────────

#[test]
fn many_simultaneous_artifacts_all_unique_and_readable() {
    let count = 50;
    let artifacts: Vec<_> = (0..count)
        .map(|i| {
            let content = format!("simultaneous-artifact-{i:04}");
            TempArtifact::new_string("uk-sim-", ".pem", &content).unwrap()
        })
        .collect();

    // All paths are unique
    let paths: HashSet<PathBuf> = artifacts.iter().map(|a| a.path().to_path_buf()).collect();
    assert_eq!(paths.len(), count, "all paths must be unique");

    // Each artifact reads back its own content
    for (i, artifact) in artifacts.iter().enumerate() {
        let expected = format!("simultaneous-artifact-{i:04}");
        assert_eq!(artifact.read_to_string().unwrap(), expected);
    }
}

#[test]
fn mixed_bytes_and_string_artifacts_coexist() {
    let pem = TempArtifact::new_string(
        "uk-mix-",
        ".pem",
        "-----BEGIN KEY-----\nDATA\n-----END KEY-----\n",
    )
    .unwrap();
    let der = TempArtifact::new_bytes("uk-mix-", ".der", &[0x30, 0x82]).unwrap();
    let txt = TempArtifact::new_string("uk-mix-", ".txt", "plain text").unwrap();
    let bin = TempArtifact::new_bytes("uk-mix-", ".bin", &[0x00; 128]).unwrap();

    // All exist
    assert!(pem.path().exists());
    assert!(der.path().exists());
    assert!(txt.path().exists());
    assert!(bin.path().exists());

    // All distinct
    let path_array = [pem.path(), der.path(), txt.path(), bin.path()];
    let paths: HashSet<_> = path_array.iter().collect();
    assert_eq!(paths.len(), 4);

    // Content correct
    assert!(pem.read_to_string().unwrap().contains("BEGIN KEY"));
    assert_eq!(der.read_to_bytes().unwrap(), vec![0x30, 0x82]);
    assert_eq!(txt.read_to_string().unwrap(), "plain text");
    assert_eq!(bin.read_to_bytes().unwrap().len(), 128);
}

// ── Large content edge case ─────────────────────────────────────────

#[test]
fn large_binary_content_1mb() {
    let data: Vec<u8> = (0..1_000_000u32).map(|i| (i % 256) as u8).collect();
    let temp = TempArtifact::new_bytes("uk-1mb-", ".bin", &data).unwrap();

    let read_back = temp.read_to_bytes().unwrap();
    assert_eq!(read_back.len(), 1_000_000);
    assert_eq!(read_back, data);
}

#[test]
fn large_string_content() {
    let line = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n";
    let text: String = line.repeat(10_000);
    let temp = TempArtifact::new_string("uk-lstr-", ".txt", &text).unwrap();

    let read_back = temp.read_to_string().unwrap();
    assert_eq!(read_back.len(), text.len());
    assert_eq!(read_back, text);
}

// ── new_string delegates to new_bytes correctly ─────────────────────

#[test]
fn new_string_and_new_bytes_produce_same_content() {
    let text = "identical content check";
    let from_string = TempArtifact::new_string("uk-eq-", ".txt", text).unwrap();
    let from_bytes = TempArtifact::new_bytes("uk-eq-", ".txt", text.as_bytes()).unwrap();

    assert_eq!(
        from_string.read_to_bytes().unwrap(),
        from_bytes.read_to_bytes().unwrap(),
    );
}

// ── Debug safety ────────────────────────────────────────────────────

#[rstest]
#[case::secret_string("TOP-SECRET-KEY-MATERIAL")]
#[case::pem_content("-----BEGIN RSA PRIVATE KEY-----")]
#[case::base64_blob("MIIBVQIBADANBgkqhkiG9w0BAQEFAA==")]
fn debug_never_leaks_content(#[case] content: &str) {
    let temp = TempArtifact::new_string("uk-dbg-", ".pem", content).unwrap();
    let dbg = format!("{temp:?}");
    assert!(dbg.contains("TempArtifact"), "should contain type name");
    assert!(dbg.contains("path"), "should mention path field");
    assert!(
        !dbg.contains(content),
        "Debug must not leak file content: {dbg}"
    );
}
