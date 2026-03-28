use std::collections::BTreeMap;
use std::path::Path;

use uselesskey_core_id::{ArtifactId, DerivationVersion};
use uselesskey_manifest::{
    BundleReceipt, FixtureReceipt, GeneratedAtMode, OutputFile, ReceiptRelationship, normalize_path,
};

#[test]
fn fixture_receipt_is_stable_for_same_inputs() {
    let id = ArtifactId::new(
        "uselesskey:rsa:keypair",
        "issuer",
        b"rs256",
        "good",
        DerivationVersion::V1,
    );

    let files = vec![
        OutputFile::from_bytes("pub", "out/pub.pem", "pem", b"public"),
        OutputFile::from_bytes("priv", "out/priv.pem", "pem", b"private"),
    ];

    let a = FixtureReceipt::from_artifact_id(&id, GeneratedAtMode::Deterministic).with_files(files.clone());
    let b = FixtureReceipt::from_artifact_id(&id, GeneratedAtMode::Deterministic).with_files(files);

    let a_json = a.to_canonical_json_vec().expect("serialize");
    let b_json = b.to_canonical_json_vec().expect("serialize");
    assert_eq!(a_json, b_json);
}

#[test]
fn fixture_receipt_orders_files_and_metadata_stably() {
    let id = ArtifactId::new(
        "uselesskey:rsa:keypair",
        "issuer",
        b"rs256",
        "good",
        DerivationVersion::V1,
    );

    let receipt = FixtureReceipt::from_artifact_id(&id, GeneratedAtMode::Random)
        .with_files(vec![
            OutputFile::from_bytes("z", "out/z.pem", "pem", b"z"),
            OutputFile::from_bytes("a", "out/a.pem", "pem", b"a"),
        ])
        .with_metadata("b", "2")
        .with_metadata("a", "1");

    assert_eq!(receipt.files[0].logical_name, "a");

    let keys = receipt.metadata.keys().cloned().collect::<Vec<_>>();
    assert_eq!(keys, vec!["a", "b"]);
}

#[test]
fn bundle_snapshot_single_and_multi() {
    let id_a = ArtifactId::new("d", "a", b"spec-a", "good", DerivationVersion::V1);
    let id_b = ArtifactId::new("d", "b", b"spec-b", "good", DerivationVersion::V1);

    let one = FixtureReceipt::from_artifact_id(&id_a, GeneratedAtMode::Deterministic).with_files(vec![
        OutputFile::from_bytes("key", "a/key.pem", "pem", b"aaa"),
    ]);
    let two = FixtureReceipt::from_artifact_id(&id_b, GeneratedAtMode::Deterministic).with_files(vec![
        OutputFile::from_bytes("key", "b/key.pem", "pem", b"bbb"),
    ]);

    let bundle = BundleReceipt::new("example")
        .with_receipts(vec![two.clone(), one.clone()])
        .with_relationships(vec![ReceiptRelationship {
            relation: "token_signed_by".to_string(),
            from: "token-a".to_string(),
            to: "key-a".to_string(),
        }]);

    insta::assert_snapshot!(
        "fixture_receipt_single",
        String::from_utf8(one.to_canonical_json_vec().expect("serialize")).expect("utf8")
    );
    insta::assert_snapshot!(
        "bundle_receipt",
        String::from_utf8(bundle.to_canonical_json_vec().expect("serialize")).expect("utf8")
    );
}

#[test]
fn round_trip_parse_works() {
    let id = ArtifactId::new("d", "label", b"spec", "good", DerivationVersion::V1);
    let receipt = FixtureReceipt::from_artifact_id(&id, GeneratedAtMode::Deterministic)
        .with_files(vec![OutputFile::from_bytes("f", "f.pem", "pem", b"abc")]);

    let bytes = receipt.to_canonical_json_vec().expect("serialize");
    let parsed: FixtureReceipt = serde_json::from_slice(&bytes).expect("parse");
    assert_eq!(receipt, parsed);
}

#[test]
fn path_normalization_is_portable() {
    let path = Path::new("foo\\bar\\baz.pem");
    assert_eq!(normalize_path(path), "foo/bar/baz.pem");

    let out = OutputFile::from_bytes("k", path, "pem", b"x");
    assert_eq!(out.path, "foo/bar/baz.pem");
}

#[test]
fn serde_accepts_explicit_maps() {
    let raw = serde_json::json!({
        "schema_version": 1,
        "uselesskey_version": "0.5.1",
        "domain": "d",
        "label": "l",
        "variant": "v",
        "spec_fingerprint": "00",
        "derivation_version": 1,
        "generated_at_mode": "random",
        "files": [],
        "metadata": BTreeMap::<String, String>::new()
    });

    let parsed: FixtureReceipt = serde_json::from_value(raw).expect("parse");
    assert_eq!(parsed.generated_at_mode, GeneratedAtMode::Random);
}
