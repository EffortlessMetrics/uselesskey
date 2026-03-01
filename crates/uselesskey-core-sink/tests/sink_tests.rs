//! Integration tests for `uselesskey-core-sink`.

use std::collections::HashSet;
use std::sync::Arc;
use std::thread;

use uselesskey_core_sink::TempArtifact;

#[test]
fn concurrent_read_same_artifact() {
    let data = b"shared-secret-material-for-threads";
    let artifact = Arc::new(TempArtifact::new_bytes("uk-", ".bin", data).unwrap());

    let handles: Vec<_> = (0..5)
        .map(|_| {
            let a = Arc::clone(&artifact);
            thread::spawn(move || a.read_to_bytes().unwrap())
        })
        .collect();

    for h in handles {
        assert_eq!(h.join().unwrap(), data.to_vec());
    }
}

#[test]
fn large_file_handling() {
    let data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    let artifact = TempArtifact::new_bytes("uk-large-", ".bin", &data).unwrap();

    let read_back = artifact.read_to_bytes().unwrap();
    assert_eq!(read_back.len(), 1_000_000);
    assert_eq!(read_back, data);
}

#[test]
fn prefix_and_suffix_in_path() {
    let artifact = TempArtifact::new_string("test-", ".pem", "content").unwrap();
    let path = artifact.path();
    let file_name = path.file_name().unwrap().to_str().unwrap();

    assert!(
        file_name.starts_with("test-"),
        "file name {file_name:?} should start with \"test-\""
    );
    assert!(
        file_name.ends_with(".pem"),
        "file name {file_name:?} should end with \".pem\""
    );
}

#[test]
fn empty_content_works() {
    let artifact = TempArtifact::new_bytes("uk-empty-", ".bin", b"").unwrap();

    assert!(artifact.path().exists());
    assert_eq!(artifact.read_to_bytes().unwrap(), Vec::<u8>::new());
    assert_eq!(artifact.read_to_string().unwrap(), "");
}

#[test]
fn multiple_artifacts_coexist() {
    let artifacts: Vec<_> = (0..10)
        .map(|i| {
            let content = format!("artifact-{i}");
            TempArtifact::new_string("uk-multi-", ".txt", &content).unwrap()
        })
        .collect();

    let paths: HashSet<_> = artifacts.iter().map(|a| a.path().to_path_buf()).collect();
    assert_eq!(paths.len(), 10, "all artifacts must have unique paths");

    for (i, artifact) in artifacts.iter().enumerate() {
        let expected = format!("artifact-{i}");
        assert_eq!(artifact.read_to_string().unwrap(), expected);
    }
}

#[test]
fn debug_does_not_leak_content() {
    let secret = "super-secret-key-material-that-must-not-appear";
    let artifact = TempArtifact::new_string("uk-dbg-", ".pem", secret).unwrap();

    let debug_output = format!("{artifact:?}");
    assert!(
        !debug_output.contains(secret),
        "Debug output must not contain file content"
    );
    assert!(
        debug_output.contains("TempArtifact"),
        "Debug output should contain the type name"
    );
}
