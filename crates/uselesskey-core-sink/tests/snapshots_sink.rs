//! Insta snapshot tests for uselesskey-core-sink.
//!
//! Snapshot TempArtifact output shapes: file extensions, content lengths,
//! debug format, cleanup behavior. No key material is captured.

use serde::Serialize;
use uselesskey_core_sink::TempArtifact;

#[derive(Serialize)]
struct TempArtifactShape {
    description: &'static str,
    suffix: &'static str,
    content_len: usize,
    path_exists: bool,
    has_expected_extension: bool,
    debug_contains_type_name: bool,
}

#[test]
fn snapshot_sink_pem_string() {
    let content = "-----BEGIN TEST KEY-----\nABCD\n-----END TEST KEY-----\n";
    let temp = TempArtifact::new_string("uk-snap-", ".pem", content).unwrap();

    let read_back = temp.read_to_string().unwrap();
    let dbg = format!("{:?}", temp);
    let ext = temp
        .path()
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    let result = TempArtifactShape {
        description: "PEM string artifact",
        suffix: ".pem",
        content_len: read_back.len(),
        path_exists: temp.path().exists(),
        has_expected_extension: ext == "pem",
        debug_contains_type_name: dbg.contains("TempArtifact"),
    };

    insta::assert_yaml_snapshot!("sink_pem_string", result);
}

#[test]
fn snapshot_sink_der_bytes() {
    let bytes = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20];
    let temp = TempArtifact::new_bytes("uk-snap-", ".der", &bytes).unwrap();

    let read_back = temp.read_to_bytes().unwrap();
    let dbg = format!("{:?}", temp);
    let ext = temp
        .path()
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    let result = TempArtifactShape {
        description: "DER bytes artifact",
        suffix: ".der",
        content_len: read_back.len(),
        path_exists: temp.path().exists(),
        has_expected_extension: ext == "der",
        debug_contains_type_name: dbg.contains("TempArtifact"),
    };

    insta::assert_yaml_snapshot!("sink_der_bytes", result);
}

#[test]
fn snapshot_sink_txt_artifact() {
    let temp = TempArtifact::new_string("uk-snap-", ".txt", "hello world").unwrap();

    let read_back = temp.read_to_string().unwrap();
    let dbg = format!("{:?}", temp);
    let ext = temp
        .path()
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    let result = TempArtifactShape {
        description: "plain text artifact",
        suffix: ".txt",
        content_len: read_back.len(),
        path_exists: temp.path().exists(),
        has_expected_extension: ext == "txt",
        debug_contains_type_name: dbg.contains("TempArtifact"),
    };

    insta::assert_yaml_snapshot!("sink_txt_artifact", result);
}

#[test]
fn snapshot_sink_cleanup_on_drop() {
    #[derive(Serialize)]
    struct CleanupShape {
        exists_before_drop: bool,
        exists_after_drop: bool,
    }

    let path = {
        let temp = TempArtifact::new_string("uk-snap-", ".tmp", "drop-test").unwrap();
        let p = temp.path().to_path_buf();
        assert!(p.exists());
        let result_before = p.exists();
        drop(temp);
        let result_after = p.exists();
        (result_before, result_after, p)
    };

    // Give OS time to clean up
    if path.2.exists() {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let result = CleanupShape {
        exists_before_drop: path.0,
        exists_after_drop: path.2.exists(),
    };

    insta::assert_yaml_snapshot!("sink_cleanup_on_drop", result);
}

#[test]
fn snapshot_sink_round_trip_fidelity() {
    #[derive(Serialize)]
    struct RoundTripShape {
        bytes_match: bool,
        string_match: bool,
        byte_len: usize,
        string_len: usize,
    }

    let bytes_data = vec![1u8, 2, 3, 4, 5, 0xFF];
    let string_data = "round-trip-test-content";

    let temp_bytes = TempArtifact::new_bytes("uk-snap-", ".bin", &bytes_data).unwrap();
    let temp_str = TempArtifact::new_string("uk-snap-", ".txt", string_data).unwrap();

    let rb = temp_bytes.read_to_bytes().unwrap();
    let rs = temp_str.read_to_string().unwrap();

    let result = RoundTripShape {
        bytes_match: rb == bytes_data,
        string_match: rs == string_data,
        byte_len: rb.len(),
        string_len: rs.len(),
    };

    insta::assert_yaml_snapshot!("sink_round_trip_fidelity", result);
}
