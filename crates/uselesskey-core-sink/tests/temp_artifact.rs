use std::fs;
use uselesskey_core_sink::TempArtifact;

// ---------------------------------------------------------------------------
// 1. Tempfile creation and writing
// ---------------------------------------------------------------------------

#[test]
fn new_bytes_creates_readable_file() {
    let data = b"binary payload";
    let temp = TempArtifact::new_bytes("sink-", ".bin", data).unwrap();
    assert!(temp.path().exists());
    assert!(temp.path().is_file());
}

#[test]
fn new_string_creates_readable_file() {
    let temp = TempArtifact::new_string("sink-", ".txt", "hello").unwrap();
    assert!(temp.path().exists());
    assert!(temp.path().is_file());
}

#[test]
fn empty_content_creates_zero_length_file() {
    let temp = TempArtifact::new_bytes("sink-", ".bin", &[]).unwrap();
    assert!(temp.path().exists());
    let meta = fs::metadata(temp.path()).unwrap();
    assert_eq!(meta.len(), 0);
}

// ---------------------------------------------------------------------------
// 2. PEM file writing with correct extensions
// ---------------------------------------------------------------------------

#[test]
fn pem_suffix_applied() {
    let pem = "-----BEGIN PRIVATE KEY-----\nMIIBVQ==\n-----END PRIVATE KEY-----\n";
    let temp = TempArtifact::new_string("key-", ".pem", pem).unwrap();
    assert_eq!(temp.path().extension().unwrap(), "pem");
}

#[test]
fn compound_pem_suffix_preserved() {
    let pem = "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----\n";
    let temp = TempArtifact::new_string("uselesskey-", ".pkcs8.pem", pem).unwrap();
    let name = temp.path().file_name().unwrap().to_string_lossy();
    assert!(
        name.ends_with(".pkcs8.pem"),
        "expected .pkcs8.pem suffix, got {name}"
    );
}

#[test]
fn spki_pem_suffix_preserved() {
    let pem = "-----BEGIN PUBLIC KEY-----\ndata\n-----END PUBLIC KEY-----\n";
    let temp = TempArtifact::new_string("uselesskey-", ".spki.pem", pem).unwrap();
    let name = temp.path().file_name().unwrap().to_string_lossy();
    assert!(
        name.ends_with(".spki.pem"),
        "expected .spki.pem suffix, got {name}"
    );
}

// ---------------------------------------------------------------------------
// 3. DER file writing
// ---------------------------------------------------------------------------

#[test]
fn der_suffix_applied() {
    let der_bytes = vec![0x30, 0x82, 0x01, 0x22];
    let temp = TempArtifact::new_bytes("key-", ".der", &der_bytes).unwrap();
    assert_eq!(temp.path().extension().unwrap(), "der");
}

#[test]
fn der_binary_content_preserved() {
    let der_bytes: Vec<u8> = (0u8..=255).collect();
    let temp = TempArtifact::new_bytes("sink-", ".der", &der_bytes).unwrap();
    let read_back = temp.read_to_bytes().unwrap();
    assert_eq!(read_back, der_bytes);
}

// ---------------------------------------------------------------------------
// 4. File content verification (round-trip)
// ---------------------------------------------------------------------------

#[test]
fn bytes_round_trip() {
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let temp = TempArtifact::new_bytes("sink-", ".bin", &data).unwrap();
    assert_eq!(temp.read_to_bytes().unwrap(), data);
}

#[test]
fn string_round_trip() {
    let text = "PEM content\nwith newlines\n";
    let temp = TempArtifact::new_string("sink-", ".pem", text).unwrap();
    assert_eq!(temp.read_to_string().unwrap(), text);
}

#[test]
fn large_payload_round_trip() {
    let data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    let temp = TempArtifact::new_bytes("sink-", ".bin", &data).unwrap();
    assert_eq!(temp.read_to_bytes().unwrap(), data);
}

#[test]
fn read_to_string_lossy_on_invalid_utf8() {
    let bytes = [0x80, 0x81, 0x82];
    let temp = TempArtifact::new_bytes("sink-", ".bin", &bytes).unwrap();
    let s = temp.read_to_string().unwrap();
    assert!(s.contains('\u{FFFD}'), "invalid UTF-8 should be replaced");
}

#[test]
fn read_via_fs_matches_api() {
    let text = "verify via fs::read";
    let temp = TempArtifact::new_string("sink-", ".txt", text).unwrap();
    let fs_content = fs::read_to_string(temp.path()).unwrap();
    assert_eq!(fs_content, text);
}

// ---------------------------------------------------------------------------
// 5. Cleanup behavior (tempfile deleted on drop)
// ---------------------------------------------------------------------------

#[test]
fn file_deleted_on_drop() {
    let path = {
        let temp = TempArtifact::new_string("sink-", ".txt", "drop me").unwrap();
        let p = temp.path().to_path_buf();
        assert!(p.exists());
        p
    };
    // After drop, the file should be gone (or removed shortly).
    for _ in 0..10 {
        if !path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(!path.exists(), "tempfile must be cleaned up on drop");
}

#[test]
fn multiple_drops_independent() {
    let path1;
    let path2;
    {
        let t1 = TempArtifact::new_string("sink-", ".a", "one").unwrap();
        let t2 = TempArtifact::new_string("sink-", ".b", "two").unwrap();
        path1 = t1.path().to_path_buf();
        path2 = t2.path().to_path_buf();
        assert!(path1.exists());
        assert!(path2.exists());
    }
    for _ in 0..10 {
        if !path1.exists() && !path2.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(!path1.exists());
    assert!(!path2.exists());
}

// ---------------------------------------------------------------------------
// 6. Multiple sinks from same data
// ---------------------------------------------------------------------------

#[test]
fn two_sinks_same_content_get_different_paths() {
    let data = b"shared payload";
    let t1 = TempArtifact::new_bytes("sink-", ".bin", data).unwrap();
    let t2 = TempArtifact::new_bytes("sink-", ".bin", data).unwrap();
    assert_ne!(t1.path(), t2.path(), "each sink should be a unique file");
}

#[test]
fn two_sinks_same_content_both_readable() {
    let data = b"shared payload";
    let t1 = TempArtifact::new_bytes("sink-", ".bin", data).unwrap();
    let t2 = TempArtifact::new_bytes("sink-", ".bin", data).unwrap();
    assert_eq!(t1.read_to_bytes().unwrap(), data.to_vec());
    assert_eq!(t2.read_to_bytes().unwrap(), data.to_vec());
}

#[test]
fn same_data_different_suffixes() {
    let data = "same content";
    let pem = TempArtifact::new_string("sink-", ".pem", data).unwrap();
    let der = TempArtifact::new_string("sink-", ".der", data).unwrap();
    assert_eq!(pem.path().extension().unwrap(), "pem");
    assert_eq!(der.path().extension().unwrap(), "der");
    assert_eq!(pem.read_to_string().unwrap(), data);
    assert_eq!(der.read_to_string().unwrap(), data);
}

// ---------------------------------------------------------------------------
// Misc: Debug, prefix in filename
// ---------------------------------------------------------------------------

#[test]
fn debug_does_not_leak_content() {
    let secret = "super-secret-key-material";
    let temp = TempArtifact::new_string("sink-", ".pem", secret).unwrap();
    let dbg = format!("{temp:?}");
    assert!(dbg.contains("TempArtifact"));
    assert!(!dbg.contains(secret), "Debug must not leak file content");
}

#[test]
fn prefix_appears_in_filename() {
    let temp = TempArtifact::new_string("myprefix-", ".txt", "x").unwrap();
    let name = temp.path().file_name().unwrap().to_string_lossy();
    assert!(
        name.starts_with("myprefix-"),
        "filename should start with prefix, got {name}"
    );
}
