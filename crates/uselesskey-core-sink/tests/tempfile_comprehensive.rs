//! Comprehensive tests for tempfile/sink functionality.
//!
//! Covers: concurrent writes, cleanup on drop, path uniqueness,
//! file permissions, and various content shapes.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use uselesskey_core_sink::TempArtifact;

// ── Concurrent tempfile writes from multiple threads ─────────────────

#[test]
fn concurrent_tempfile_writes_produce_distinct_files() {
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let content = format!("thread-{i}-content");
                let temp =
                    TempArtifact::new_string("uk-conc-", ".pem", &content).expect("create temp");
                let path = temp.path().to_path_buf();
                let read_back = temp.read_to_string().expect("read back");
                assert_eq!(read_back, content);
                (path, temp)
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let paths: HashSet<_> = results.iter().map(|(p, _)| p.clone()).collect();

    // All paths must be unique
    assert_eq!(
        paths.len(),
        8,
        "all concurrent tempfiles must have unique paths"
    );

    // All files still exist while we hold the TempArtifacts
    for (path, _artifact) in &results {
        assert!(path.exists(), "file should exist while artifact is alive");
    }
}

#[test]
fn concurrent_bytes_writes_are_independent() {
    let handles: Vec<_> = (0..4)
        .map(|i| {
            thread::spawn(move || {
                let data: Vec<u8> = (0..100).map(|b| ((b + i) % 256) as u8).collect();
                let temp = TempArtifact::new_bytes("uk-cbin-", ".der", &data).expect("create temp");
                let read_back = temp.read_to_bytes().expect("read back");
                assert_eq!(read_back, data);
                temp
            })
        })
        .collect();

    let artifacts: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let paths: HashSet<_> = artifacts.iter().map(|a| a.path().to_path_buf()).collect();
    assert_eq!(paths.len(), 4);
}

// ── Tempfiles cleaned up when TempArtifact dropped ──────────────────

#[test]
fn multiple_tempfiles_cleaned_up_on_drop() {
    let paths: Vec<PathBuf> = {
        let artifacts: Vec<_> = (0..5)
            .map(|i| {
                let content = format!("drop-test-{i}");
                TempArtifact::new_string("uk-drop-", ".tmp", &content).unwrap()
            })
            .collect();

        let paths: Vec<_> = artifacts.iter().map(|a| a.path().to_path_buf()).collect();
        for p in &paths {
            assert!(p.exists(), "file must exist before drop");
        }
        paths
        // artifacts dropped here
    };

    // Allow filesystem latency
    thread::sleep(std::time::Duration::from_millis(50));

    for p in &paths {
        assert!(!p.exists(), "file should be cleaned up after drop: {p:?}");
    }
}

#[test]
fn drop_in_thread_cleans_up() {
    let path = thread::spawn(|| {
        let temp = TempArtifact::new_string("uk-tdrop-", ".txt", "thread-drop").unwrap();
        let p = temp.path().to_path_buf();
        assert!(p.exists());
        p
        // temp dropped at end of closure
    })
    .join()
    .unwrap();

    thread::sleep(std::time::Duration::from_millis(50));
    assert!(
        !path.exists(),
        "tempfile should be cleaned up after thread exits"
    );
}

// ── Tempfile paths are unique across invocations ────────────────────

#[test]
fn paths_unique_same_prefix_suffix() {
    let mut paths = HashSet::new();
    for _ in 0..20 {
        let temp = TempArtifact::new_string("uk-uniq-", ".pem", "data").unwrap();
        let inserted = paths.insert(temp.path().to_path_buf());
        assert!(inserted, "path should be unique across invocations");
    }
    assert_eq!(paths.len(), 20);
}

#[test]
fn paths_unique_empty_prefix() {
    let a = TempArtifact::new_string("", ".pem", "a").unwrap();
    let b = TempArtifact::new_string("", ".pem", "b").unwrap();
    assert_ne!(a.path(), b.path());
}

// ── Write multiple fixtures simultaneously ──────────────────────────

#[test]
fn multiple_fixtures_coexist_with_different_extensions() {
    let pem = TempArtifact::new_string(
        "uk-multi-",
        ".pem",
        "-----BEGIN PRIVATE KEY-----\nDATA\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();
    let der = TempArtifact::new_bytes("uk-multi-", ".der", &[0x30, 0x82, 0x01]).unwrap();
    let crt = TempArtifact::new_string(
        "uk-multi-",
        ".crt.pem",
        "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n",
    )
    .unwrap();

    assert!(pem.path().exists());
    assert!(der.path().exists());
    assert!(crt.path().exists());

    assert_eq!(pem.path().extension().unwrap(), "pem");
    assert_eq!(der.path().extension().unwrap(), "der");
    assert_eq!(crt.path().extension().unwrap(), "pem");

    // Verify contents are independent
    assert!(pem.read_to_string().unwrap().contains("PRIVATE KEY"));
    assert_eq!(der.read_to_bytes().unwrap(), vec![0x30, 0x82, 0x01]);
    assert!(crt.read_to_string().unwrap().contains("CERTIFICATE"));
}

// ── File permissions (Unix only) ────────────────────────────────────

#[cfg(unix)]
mod unix_permissions {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn tempfile_is_owner_only_readable() {
        let temp = TempArtifact::new_string("uk-perm-", ".pem", "secret-key-data").unwrap();
        let metadata = std::fs::metadata(temp.path()).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "tempfile should be owner-read/write only (0600), got {mode:o}"
        );
    }

    #[test]
    fn tempfile_not_world_readable() {
        let temp = TempArtifact::new_bytes("uk-perm-", ".der", &[0x30, 0x82]).unwrap();
        let metadata = std::fs::metadata(temp.path()).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode & 0o004, 0, "tempfile must not be world-readable");
        assert_eq!(mode & 0o040, 0, "tempfile must not be group-readable");
    }

    #[test]
    fn permissions_apply_to_bytes_and_string_variants() {
        let string_temp = TempArtifact::new_string("uk-ps-", ".pem", "pem-content").unwrap();
        let bytes_temp = TempArtifact::new_bytes("uk-pb-", ".der", &[0x01, 0x02]).unwrap();

        for temp in [&string_temp, &bytes_temp] {
            let meta = std::fs::metadata(temp.path()).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}

// ── Windows: verify file is not read-only ────────────────────────────

#[cfg(windows)]
#[test]
fn tempfile_is_not_readonly_on_windows() {
    let temp = TempArtifact::new_string("uk-winperm-", ".pem", "data").unwrap();
    let metadata = std::fs::metadata(temp.path()).unwrap();
    assert!(
        !metadata.permissions().readonly(),
        "tempfile should be writable on Windows"
    );
}

// ── PEM and DER content verification ────────────────────────────────

#[test]
fn write_pem_read_back_preserves_newlines() {
    let pem =
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\nbase64data==\n-----END RSA PRIVATE KEY-----\n";
    let temp = TempArtifact::new_string("uk-pem-nl-", ".pem", pem).unwrap();

    let content = temp.read_to_string().unwrap();
    assert_eq!(content, pem);
    assert_eq!(
        content.matches('\n').count(),
        pem.matches('\n').count(),
        "newline count must be preserved"
    );
}

#[test]
fn write_der_read_back_preserves_exact_bytes() {
    // Simulate a DER-encoded structure
    let der = vec![
        0x30, 0x82, 0x02, 0x22, // SEQUENCE header
        0x02, 0x01, 0x00, // INTEGER version
        0x30, 0x0D, // SEQUENCE AlgorithmIdentifier
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, // OID rsaEncryption
        0x05, 0x00, // NULL
    ];
    let temp = TempArtifact::new_bytes("uk-der-", ".der", &der).unwrap();

    let read_back = temp.read_to_bytes().unwrap();
    assert_eq!(read_back, der, "DER bytes must be preserved exactly");
}

// ── Edge cases ──────────────────────────────────────────────────────

#[test]
fn single_byte_content() {
    let temp = TempArtifact::new_bytes("uk-1b-", ".bin", &[0x42]).unwrap();
    assert_eq!(temp.read_to_bytes().unwrap(), vec![0x42]);
}

#[test]
fn unicode_string_content() {
    let text = "🔑 key fixture — ñoño — 日本語";
    let temp = TempArtifact::new_string("uk-utf8-", ".txt", text).unwrap();
    assert_eq!(temp.read_to_string().unwrap(), text);
}

#[test]
fn prefix_appears_in_path() {
    let temp = TempArtifact::new_string("uselesskey-myprefix-", ".pem", "data").unwrap();
    let filename = temp
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert!(
        filename.contains("uselesskey-myprefix-"),
        "filename should contain the prefix: {filename}"
    );
}

#[test]
fn suffix_appears_in_path() {
    let temp = TempArtifact::new_string("uk-", ".pkcs8.pem", "data").unwrap();
    let filename = temp
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert!(
        filename.ends_with(".pkcs8.pem"),
        "filename should end with the suffix: {filename}"
    );
}

// ── proptest: arbitrary content round-trips ─────────────────────────

mod property {
    use proptest::prelude::*;

    use uselesskey_core_sink::TempArtifact;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

        #[test]
        fn arbitrary_bytes_round_trip(data in prop::collection::vec(any::<u8>(), 0..4096)) {
            let temp = TempArtifact::new_bytes("uk-prop-", ".bin", &data).unwrap();
            let read_back = temp.read_to_bytes().unwrap();
            prop_assert_eq!(read_back, data);
        }

        #[test]
        fn arbitrary_string_round_trip(text in "[\\w\\s\\p{L}]{0,2048}") {
            let temp = TempArtifact::new_string("uk-prop-", ".txt", &text).unwrap();
            let read_back = temp.read_to_string().unwrap();
            prop_assert_eq!(read_back, text);
        }

        #[test]
        fn paths_always_unique(n in 2usize..10) {
            let artifacts: Vec<_> = (0..n)
                .map(|_| TempArtifact::new_string("uk-puniq-", ".pem", "x").unwrap())
                .collect();
            let paths: std::collections::HashSet<_> =
                artifacts.iter().map(|a| a.path().to_path_buf()).collect();
            prop_assert_eq!(paths.len(), n);
        }
    }
}
