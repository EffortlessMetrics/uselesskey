use super::super::{BundleArtifactRecord, BundleManifest};

pub(crate) fn render_bundle_inspection_summary(
    manifest: &BundleManifest,
    verified_file_count: usize,
) -> String {
    let artifact_count = if manifest.artifacts.is_empty() {
        verified_file_count
    } else {
        manifest.artifacts.len()
    };
    let scanner_safe = if manifest.artifacts.is_empty() {
        None
    } else {
        Some(
            manifest
                .artifacts
                .iter()
                .all(|artifact| artifact.scanner_safe),
        )
    };
    let runtime_material_count = if manifest.artifacts.is_empty() {
        None
    } else {
        Some(
            manifest
                .artifacts
                .iter()
                .filter(|artifact| !artifact.scanner_safe)
                .count(),
        )
    };
    let private_key_material = if manifest.artifacts.is_empty() {
        None
    } else {
        Some(
            manifest
                .artifacts
                .iter()
                .any(bundle_artifact_contains_private_key_material),
        )
    };
    let symmetric_secret_material = if manifest.artifacts.is_empty() {
        None
    } else {
        Some(
            manifest
                .artifacts
                .iter()
                .any(bundle_artifact_contains_symmetric_secret_material),
        )
    };
    let receipts = if manifest.receipts.is_empty() {
        "none".to_string()
    } else {
        manifest
            .receipts
            .iter()
            .map(|receipt| receipt.kind.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };

    format!(
        concat!(
            "Bundle profile: {}\n",
            "Artifacts: {}\n",
            "Verified files: {}\n",
            "Scanner-safe: {}\n",
            "Private key material: {}\n",
            "Symmetric secret material: {}\n",
            "Runtime material artifacts: {}\n",
            "Verification: ok\n",
            "Receipts: {}\n",
        ),
        manifest.profile,
        artifact_count,
        verified_file_count,
        yes_no_unknown(scanner_safe),
        yes_no_unknown(private_key_material),
        yes_no_unknown(symmetric_secret_material),
        count_or_unknown(runtime_material_count),
        receipts
    )
}

fn bundle_artifact_contains_private_key_material(artifact: &BundleArtifactRecord) -> bool {
    matches!(artifact.kind.as_str(), "rsa" | "ecdsa" | "ed25519")
        && matches!(artifact.format.as_str(), "pem" | "der")
        && !artifact.scanner_safe
}

fn bundle_artifact_contains_symmetric_secret_material(artifact: &BundleArtifactRecord) -> bool {
    matches!(artifact.kind.as_str(), "hmac" | "webhook") && !artifact.scanner_safe
}

fn yes_no_unknown(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

fn count_or_unknown(value: Option<usize>) -> String {
    value.map_or_else(|| "unknown".to_string(), |count| count.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_material_requires_private_key_format_and_non_scanner_safe_artifact() {
        assert!(bundle_artifact_contains_private_key_material(&record(
            "rsa", "pem", false,
        )));
        assert!(!bundle_artifact_contains_private_key_material(&record(
            "rsa", "jwk", false,
        )));
        assert!(!bundle_artifact_contains_private_key_material(&record(
            "token",
            "json-manifest",
            false,
        )));
        assert!(!bundle_artifact_contains_private_key_material(&record(
            "rsa", "pem", true,
        )));
    }

    #[test]
    fn symmetric_secret_material_requires_hmac_and_non_scanner_safe_artifact() {
        assert!(bundle_artifact_contains_symmetric_secret_material(&record(
            "hmac", "jwk", false,
        )));
        assert!(bundle_artifact_contains_symmetric_secret_material(&record(
            "webhook",
            "json-manifest",
            false,
        )));
        assert!(!bundle_artifact_contains_symmetric_secret_material(
            &record("token", "json-manifest", false,)
        ));
        assert!(!bundle_artifact_contains_symmetric_secret_material(
            &record("hmac", "jwk", true,)
        ));
    }

    #[test]
    fn summary_scalar_renderers_are_stable() {
        assert_eq!(yes_no_unknown(Some(true)), "yes");
        assert_eq!(yes_no_unknown(Some(false)), "no");
        assert_eq!(yes_no_unknown(None), "unknown");
        assert_eq!(count_or_unknown(Some(7)), "7");
        assert_eq!(count_or_unknown(None), "unknown");
    }

    fn record(kind: &str, format: &str, scanner_safe: bool) -> BundleArtifactRecord {
        BundleArtifactRecord {
            path: format!("{kind}.{format}"),
            kind: kind.to_string(),
            format: format.to_string(),
            profile: "test".to_string(),
            lanes: vec!["runtime".to_string(), "materialized".to_string()],
            scanner_safe,
            description: "test artifact".to_string(),
        }
    }
}
