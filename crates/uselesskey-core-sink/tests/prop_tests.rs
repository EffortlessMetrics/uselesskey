//! Property-based tests for `uselesskey-core-sink`.

use proptest::prelude::*;
use uselesskey_core_sink::TempArtifact;

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn bytes_round_trip(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let temp = TempArtifact::new_bytes("uk-prop-", ".bin", &data).unwrap();
        let read_back = temp.read_to_bytes().unwrap();
        prop_assert_eq!(read_back, data);
    }

    #[test]
    fn string_round_trip(text in "[a-zA-Z0-9 \n\t!@#$%^&*()]{0,512}") {
        let temp = TempArtifact::new_string("uk-prop-", ".txt", &text).unwrap();
        let read_back = temp.read_to_string().unwrap();
        prop_assert_eq!(read_back, text);
    }

    #[test]
    fn path_exists_while_alive(data in proptest::collection::vec(any::<u8>(), 0..256)) {
        let temp = TempArtifact::new_bytes("uk-prop-", ".bin", &data).unwrap();
        prop_assert!(temp.path().exists());
        prop_assert!(temp.path().is_file());
    }

    #[test]
    fn suffix_preserved_in_path(
        suffix in "\\.[a-z]{1,4}",
        data in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        let temp = TempArtifact::new_bytes("uk-prop-", &suffix, &data).unwrap();
        let ext = temp.path().extension().and_then(|e| e.to_str()).unwrap_or("");
        // suffix is ".xyz", extension is "xyz"
        prop_assert_eq!(format!(".{ext}"), suffix);
    }

    #[test]
    fn debug_does_not_contain_written_content(
        content in "[A-Z]{16,64}",
    ) {
        let temp = TempArtifact::new_string("uk-prop-", ".txt", &content).unwrap();
        let dbg = format!("{temp:?}");
        prop_assert!(dbg.contains("TempArtifact"));
        prop_assert!(!dbg.contains(&content), "Debug must not leak file content");
    }

    #[test]
    fn read_to_string_never_panics_on_arbitrary_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let temp = TempArtifact::new_bytes("uk-prop-", ".bin", &data).unwrap();
        // Should not panic even for non-UTF-8 bytes
        let _ = temp.read_to_string().unwrap();
    }
}
