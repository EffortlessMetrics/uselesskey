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
