use uselesskey_core_sink::TempArtifact;

// ── tempfile creation and read-back ──────────────────────────────────

#[test]
fn new_bytes_round_trip() {
    let data = vec![0x30, 0x82, 0x01, 0x22, 0xFF];
    let temp = TempArtifact::new_bytes("uk-test-", ".der", &data).unwrap();

    let read_back = temp.read_to_bytes().unwrap();
    assert_eq!(read_back, data);
}

#[test]
fn new_string_round_trip() {
    let pem = "-----BEGIN PRIVATE KEY-----\nMIIBVQ==\n-----END PRIVATE KEY-----\n";
    let temp = TempArtifact::new_string("uk-test-", ".pem", pem).unwrap();

    let read_back = temp.read_to_string().unwrap();
    assert_eq!(read_back, pem);
}

#[test]
fn empty_content_round_trip() {
    let temp = TempArtifact::new_bytes("uk-test-", ".bin", &[]).unwrap();
    let read_back = temp.read_to_bytes().unwrap();
    assert!(read_back.is_empty());
}

// ── PEM content written correctly ────────────────────────────────────

#[test]
fn pem_content_preserves_structure() {
    let pem = "-----BEGIN PUBLIC KEY-----\nABCDEF==\n-----END PUBLIC KEY-----\n";
    let temp = TempArtifact::new_string("uk-pem-", ".pem", pem).unwrap();

    let content = temp.read_to_string().unwrap();
    assert!(content.starts_with("-----BEGIN PUBLIC KEY-----"));
    assert!(content.contains("ABCDEF=="));
    assert!(content.ends_with("-----END PUBLIC KEY-----\n"));
}

#[test]
fn pem_file_has_correct_extension() {
    let temp = TempArtifact::new_string(
        "uk-test-",
        ".pem",
        "-----BEGIN KEY-----\n-----END KEY-----\n",
    )
    .unwrap();
    assert_eq!(temp.path().extension().unwrap(), "pem");
}

#[test]
fn der_file_has_correct_extension() {
    let temp = TempArtifact::new_bytes("uk-test-", ".der", &[0x30]).unwrap();
    assert_eq!(temp.path().extension().unwrap(), "der");
}

// ── path is valid while alive ────────────────────────────────────────

#[test]
fn path_exists_while_artifact_alive() {
    let temp = TempArtifact::new_string("uk-test-", ".txt", "alive").unwrap();
    assert!(temp.path().exists());
    assert!(temp.path().is_file());
}

// ── file cleanup on drop ─────────────────────────────────────────────

#[test]
fn file_deleted_on_drop() {
    let path = {
        let temp = TempArtifact::new_string("uk-test-", ".txt", "drop-me").unwrap();
        let p = temp.path().to_path_buf();
        assert!(p.exists());
        p
    };
    // After drop, file should be removed
    // Small retry for filesystem latency on Windows
    for _ in 0..10 {
        if !path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(!path.exists(), "tempfile should be deleted on drop");
}

// ── Debug does not leak content ──────────────────────────────────────

#[test]
fn debug_contains_type_name_but_not_content() {
    let temp = TempArtifact::new_string("uk-test-", ".pem", "SECRET_MATERIAL").unwrap();
    let dbg = format!("{temp:?}");
    assert!(dbg.contains("TempArtifact"));
    assert!(!dbg.contains("SECRET_MATERIAL"));
}

// ── read_to_string handles non-utf8 ─────────────────────────────────

#[test]
fn read_to_string_replaces_invalid_utf8() {
    let bytes = [0xFF, 0xFE, 0xFD];
    let temp = TempArtifact::new_bytes("uk-test-", ".bin", &bytes).unwrap();
    let s = temp.read_to_string().unwrap();
    assert!(s.contains('\u{FFFD}'));
}

// ── large content round trip ─────────────────────────────────────────

#[test]
fn large_content_round_trip() {
    let data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    let temp = TempArtifact::new_bytes("uk-large-", ".bin", &data).unwrap();
    let read_back = temp.read_to_bytes().unwrap();
    assert_eq!(read_back, data);
}

// ── multiple artifacts coexist ───────────────────────────────────────

#[test]
fn multiple_artifacts_have_distinct_paths() {
    let a = TempArtifact::new_string("uk-a-", ".pem", "artifact-a").unwrap();
    let b = TempArtifact::new_string("uk-b-", ".pem", "artifact-b").unwrap();

    assert_ne!(a.path(), b.path());
    assert_eq!(a.read_to_string().unwrap(), "artifact-a");
    assert_eq!(b.read_to_string().unwrap(), "artifact-b");
}

// ── Debug safety with binary content ─────────────────────────────────

#[test]
fn debug_does_not_leak_binary_content() {
    let secret = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let temp = TempArtifact::new_bytes("uk-test-", ".bin", &secret).unwrap();
    let dbg = format!("{temp:?}");
    assert!(dbg.contains("TempArtifact"));
    // Debug should only show path, not file content
    assert!(!dbg.contains("DEAD"));
    assert!(!dbg.contains("BEEF"));
}

// ── null bytes in binary content ─────────────────────────────────────

#[test]
fn binary_content_with_null_bytes() {
    let data = vec![0x00, 0x01, 0x00, 0xFF, 0x00];
    let temp = TempArtifact::new_bytes("uk-null-", ".bin", &data).unwrap();
    assert_eq!(temp.read_to_bytes().unwrap(), data);
}

// ── write operations ─────────────────────────────────────────────────

#[test]
fn new_bytes_creates_readable_file() {
    let data = b"test data for write op";
    let temp = TempArtifact::new_bytes("uk-write-", ".dat", data).unwrap();
    let content = std::fs::read(temp.path()).unwrap();
    assert_eq!(content, data);
}

#[test]
fn new_string_creates_readable_file() {
    let text = "hello from new_string";
    let temp = TempArtifact::new_string("uk-write-", ".txt", text).unwrap();
    let content = std::fs::read_to_string(temp.path()).unwrap();
    assert_eq!(content, text);
}

// ── Debug shows path but uses finish_non_exhaustive ──────────────────

#[test]
fn debug_shows_path_field() {
    let temp = TempArtifact::new_string("uk-test-", ".txt", "data").unwrap();
    let dbg = format!("{temp:?}");
    assert!(dbg.contains("path"));
    // finish_non_exhaustive appends ".."
    assert!(dbg.contains(".."));
}
