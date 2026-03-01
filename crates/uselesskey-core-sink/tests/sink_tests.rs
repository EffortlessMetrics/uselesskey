#![forbid(unsafe_code)]

use std::fs;

use uselesskey_core_sink::TempArtifact;

// ── Basic functionality ──────────────────────────────────────────────

#[test]
fn new_bytes_creates_readable_file() {
    let data = b"hello bytes";
    let temp = TempArtifact::new_bytes("test-", ".bin", data).unwrap();
    let read_back = fs::read(temp.path()).unwrap();
    assert_eq!(read_back, data);
}

#[test]
fn new_string_creates_readable_file() {
    let text = "hello string";
    let temp = TempArtifact::new_string("test-", ".txt", text).unwrap();
    let read_back = fs::read_to_string(temp.path()).unwrap();
    assert_eq!(read_back, text);
}

#[test]
fn path_returns_valid_path() {
    let temp = TempArtifact::new_string("test-", ".pem", "content").unwrap();
    let p = temp.path();
    assert!(p.exists(), "path() should point to an existing file");
    assert!(
        p.is_file(),
        "path() should point to a file, not a directory"
    );
}

#[test]
fn file_has_correct_suffix() {
    let temp = TempArtifact::new_string("pfx-", ".pem", "x").unwrap();
    let name = temp
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert!(
        name.ends_with(".pem"),
        "filename {name:?} should end with .pem"
    );
}

#[test]
fn file_has_correct_prefix() {
    let temp = TempArtifact::new_string("mypfx-", ".txt", "x").unwrap();
    let name = temp
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert!(
        name.starts_with("mypfx-"),
        "filename {name:?} should start with mypfx-"
    );
}

// ── Roundtrip tests ──────────────────────────────────────────────────

#[test]
fn bytes_roundtrip() {
    let data: Vec<u8> = (0u8..=255).collect();
    let temp = TempArtifact::new_bytes("rt-", ".bin", &data).unwrap();
    assert_eq!(temp.read_to_bytes().unwrap(), data);
}

#[test]
fn string_roundtrip() {
    let text = "The quick brown 🦊 jumps over the lazy 🐶";
    let temp = TempArtifact::new_string("rt-", ".txt", text).unwrap();
    assert_eq!(temp.read_to_string().unwrap(), text);
}

#[test]
fn bytes_to_string_roundtrip() {
    let utf8 = "valid UTF-8 content ✓";
    let temp = TempArtifact::new_bytes("rt-", ".txt", utf8.as_bytes()).unwrap();
    assert_eq!(temp.read_to_string().unwrap(), utf8);
}

// ── Debug safety ─────────────────────────────────────────────────────

#[test]
fn debug_does_not_leak_content() {
    let secret = "-----BEGIN RSA PRIVATE KEY-----\nSuperSecret\n-----END RSA PRIVATE KEY-----";
    let temp = TempArtifact::new_string("key-", ".pem", secret).unwrap();
    let dbg = format!("{temp:?}");
    assert!(
        !dbg.contains("SuperSecret"),
        "Debug output must not contain file contents: {dbg}"
    );
    assert!(
        !dbg.contains("BEGIN RSA"),
        "Debug output must not contain PEM markers: {dbg}"
    );
    assert!(
        dbg.contains("TempArtifact"),
        "Debug output should contain the type name"
    );
}

// ── Edge cases ───────────────────────────────────────────────────────

#[test]
fn empty_bytes() {
    let temp = TempArtifact::new_bytes("empty-", ".bin", &[]).unwrap();
    let read_back = temp.read_to_bytes().unwrap();
    assert!(read_back.is_empty());
}

#[test]
fn empty_string() {
    let temp = TempArtifact::new_string("empty-", ".txt", "").unwrap();
    let read_back = temp.read_to_string().unwrap();
    assert!(read_back.is_empty());
}

#[test]
fn large_content() {
    let data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    let temp = TempArtifact::new_bytes("large-", ".bin", &data).unwrap();
    assert_eq!(temp.read_to_bytes().unwrap(), data);
}

// ── Property tests (proptest) ────────────────────────────────────────

mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn any_bytes_roundtrip(data: Vec<u8>) {
            let temp = TempArtifact::new_bytes("prop-", ".bin", &data).unwrap();
            let read_back = temp.read_to_bytes().unwrap();
            prop_assert_eq!(read_back, data);
        }

        #[test]
        fn any_utf8_string_roundtrip(s: String) {
            let temp = TempArtifact::new_string("prop-", ".txt", &s).unwrap();
            let read_back = temp.read_to_string().unwrap();
            prop_assert_eq!(read_back, s);
        }
    }
}
