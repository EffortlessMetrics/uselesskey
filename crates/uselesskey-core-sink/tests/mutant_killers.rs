//! Mutant-killing tests for TempArtifact sink.

use uselesskey_core_sink::TempArtifact;

#[test]
fn new_bytes_returns_exact_content() {
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let temp = TempArtifact::new_bytes("uk-mk-", ".bin", &data).unwrap();
    let read_back = temp.read_to_bytes().unwrap();
    assert_eq!(read_back, data);
}

#[test]
fn new_string_returns_exact_content() {
    let text = "-----BEGIN TEST-----\nDATA\n-----END TEST-----\n";
    let temp = TempArtifact::new_string("uk-mk-", ".pem", text).unwrap();
    let read_back = temp.read_to_string().unwrap();
    assert_eq!(read_back, text);
}

#[test]
fn path_exists_while_alive() {
    let temp = TempArtifact::new_string("uk-mk-", ".txt", "hello").unwrap();
    assert!(temp.path().exists());
    assert!(temp.path().is_file());
}

#[test]
fn suffix_appears_in_path() {
    let temp = TempArtifact::new_string("uk-mk-", ".pem", "data").unwrap();
    let path_str = temp.path().to_string_lossy();
    assert!(
        path_str.ends_with(".pem"),
        "path should end with .pem: {path_str}"
    );
}

#[test]
fn read_to_string_lossy_handles_invalid_utf8() {
    let bytes = vec![0xFF, 0xFE, b'A', b'B'];
    let temp = TempArtifact::new_bytes("uk-mk-", ".bin", &bytes).unwrap();
    let s = temp.read_to_string().unwrap();
    assert!(
        s.contains('\u{FFFD}'),
        "invalid UTF-8 should become replacement char"
    );
    assert!(s.contains("AB"));
}

#[test]
fn empty_content_round_trips() {
    let temp = TempArtifact::new_bytes("uk-mk-", ".bin", &[]).unwrap();
    let read_back = temp.read_to_bytes().unwrap();
    assert!(read_back.is_empty());
}

#[test]
fn debug_format_contains_type_and_path() {
    let temp = TempArtifact::new_string("uk-mk-", ".txt", "dbg").unwrap();
    let dbg = format!("{temp:?}");
    assert!(dbg.contains("TempArtifact"));
    assert!(dbg.contains("path"));
}
