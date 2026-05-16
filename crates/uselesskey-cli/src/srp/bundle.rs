use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uselesskey_cli::{ArtifactType as ExportArtifactType, ExportArtifact, ManifestArtifact};
use uselesskey_core::Factory;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
use uselesskey_jwk::NegativeJwks;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_token::{NegativeToken, TokenFactoryExt, TokenSpec};
use uselesskey_webhook::{WebhookFactoryExt, WebhookPayloadSpec};
use uselesskey_x509::{ChainNegative, ChainSpec, X509Chain, X509FactoryExt, X509Spec};

use super::artifact::{Artifact, artifact_bytes, format_extension};
use super::types::{BundleProfile, Format, Kind};

pub(crate) fn load_bundle_manifest(path: &Path) -> Result<BundleManifest> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let manifest: BundleManifest = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    if manifest.version != 1 {
        bail!("unsupported bundle manifest version {}", manifest.version);
    }
    Ok(manifest)
}

pub(crate) fn verify_bundle_manifest(
    bundle_dir: &Path,
    manifest: &BundleManifest,
) -> Result<Vec<String>> {
    let format = parse_manifest_format(&manifest.format)?;
    let profile = parse_manifest_profile(&manifest.profile)?;
    let fx = Factory::deterministic_from_str(&manifest.seed);
    let mut expected_files = Vec::new();
    let mut expected_artifacts = Vec::new();

    for entry in bundle_entries(profile) {
        let bundle_format = entry.preferred_format(format, profile);
        let artifact =
            generate_bundle_entry_artifact(&fx, entry, &manifest.label, bundle_format, profile)
                .with_context(|| format!("failed to regenerate {}", entry.name()))?;
        let file_name = entry.file_name(bundle_format, &artifact);
        let expected = artifact_bytes(&artifact)?;
        let path = bundle_dir.join(&file_name);
        let actual =
            fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        if actual != expected {
            bail!(
                "bundle verification failed: {} content mismatch",
                path.display()
            );
        }
        expected_files.push(file_name);
        expected_artifacts.push(bundle_artifact_record(
            entry,
            bundle_format,
            expected_files.last().expect("just pushed"),
            profile,
        ));
    }
    let fixture_files = expected_files.clone();
    let mut expected_receipts = Vec::new();
    if !manifest.receipts.is_empty() {
        expected_receipts = bundle_receipt_records(profile);
        for receipt in &expected_receipts {
            let expected = artifact_bytes(&generate_bundle_receipt_artifact(
                &receipt.kind,
                &manifest.seed,
                &manifest.label,
                format,
                profile,
                &fixture_files,
                &expected_artifacts,
            )?)?;
            let path = bundle_dir.join(&receipt.path);
            let actual =
                fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
            if actual != expected {
                bail!(
                    "bundle verification failed: {} receipt mismatch",
                    path.display()
                );
            }
            expected_files.push(receipt.path.clone());
        }
    }

    if manifest.files != expected_files {
        bail!(
            "bundle verification failed: manifest file list mismatch; expected {:?}, found {:?}",
            expected_files,
            manifest.files
        );
    }

    if !manifest.artifacts.is_empty() && manifest.artifacts != expected_artifacts {
        bail!(
            "bundle verification failed: artifact metadata mismatch; expected {:?}, found {:?}",
            expected_artifacts,
            manifest.artifacts
        );
    }

    if !manifest.artifacts.is_empty() && manifest.receipts.is_empty() {
        bail!("bundle verification failed: receipt metadata missing");
    }

    if !manifest.receipts.is_empty() && manifest.receipts != expected_receipts {
        bail!(
            "bundle verification failed: receipt metadata mismatch; expected {:?}, found {:?}",
            expected_receipts,
            manifest.receipts
        );
    }

    Ok(expected_files)
}

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
mod inspect_bundle_tests {
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

pub(crate) fn load_bundle_export_artifacts(bundle_dir: &Path) -> Result<Vec<ExportArtifact>> {
    let manifest_path = bundle_dir.join("manifest.json");
    let manifest = load_bundle_manifest(&manifest_path)
        .with_context(|| format!("invalid bundle manifest {}", manifest_path.display()))?;
    verify_bundle_manifest(bundle_dir, &manifest)
        .with_context(|| format!("failed to verify bundle {}", bundle_dir.display()))?;

    if manifest.artifacts.is_empty() {
        bail!(
            "bundle manifest {} does not contain artifact metadata; rerun `uselesskey bundle`",
            manifest_path.display()
        );
    }

    let mut artifacts = Vec::with_capacity(manifest.artifacts.len());
    for record in &manifest.artifacts {
        let path = bundle_dir.join(&record.path);
        let bytes =
            fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        let value = String::from_utf8(bytes).with_context(|| {
            format!(
                "bundle artifact {} is not UTF-8; export payloads require text artifacts",
                path.display()
            )
        })?;
        artifacts.push(ExportArtifact {
            key: record.path.clone(),
            value,
            manifest: ManifestArtifact {
                artifact_type: ExportArtifactType::Opaque,
                source_seed: Some(manifest.seed.clone()),
                source_label: manifest.label.clone(),
                output_paths: vec![record.path.clone()],
                fingerprints: Vec::new(),
                env_var_names: Vec::new(),
                external_key_ref: None,
            },
        });
    }

    Ok(artifacts)
}

fn parse_manifest_format(raw: &str) -> Result<Format> {
    match raw {
        "pem" => Ok(Format::Pem),
        "der" => Ok(Format::Der),
        "jwk" => Ok(Format::Jwk),
        "jwks" => Ok(Format::Jwks),
        "json-manifest" | "jsonmanifest" => Ok(Format::JsonManifest),
        "bundle-dir" | "bundledir" => Ok(Format::BundleDir),
        other => bail!("unsupported bundle manifest format `{other}`"),
    }
}

fn parse_manifest_profile(raw: &str) -> Result<BundleProfile> {
    match raw {
        "scanner-safe" | "scannersafe" => Ok(BundleProfile::ScannerSafe),
        "oidc" => Ok(BundleProfile::Oidc),
        "tls" => Ok(BundleProfile::Tls),
        "webhook" => Ok(BundleProfile::Webhook),
        "runtime" => Ok(BundleProfile::Runtime),
        other => bail!("unsupported bundle manifest profile `{other}`"),
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum BundleEntry {
    Standard {
        name: &'static str,
        kind: Kind,
    },
    OidcValidJwks,
    OidcNegativeJwks {
        name: &'static str,
        variant: NegativeJwks,
        description: &'static str,
    },
    OidcValidToken,
    OidcNegativeToken {
        name: &'static str,
        variant: NegativeToken,
        description: &'static str,
    },
    TlsValidLeaf,
    TlsValidChain,
    TlsNegativeChain {
        name: &'static str,
        variant: TlsChainNegativeKind,
        description: &'static str,
    },
    TlsEvidenceDoc,
    WebhookRequest {
        name: &'static str,
        variant: WebhookRequestKind,
        description: &'static str,
    },
    WebhookEvidenceDoc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TlsChainNegativeKind {
    ExpiredLeaf,
    NotYetValidLeaf,
    HostnameMismatch,
    UnknownCa,
}

impl TlsChainNegativeKind {
    fn to_chain_negative(self) -> ChainNegative {
        match self {
            Self::ExpiredLeaf => ChainNegative::ExpiredLeaf,
            Self::NotYetValidLeaf => ChainNegative::NotYetValidLeaf,
            Self::HostnameMismatch => ChainNegative::HostnameMismatch {
                wrong_hostname: TLS_WRONG_HOSTNAME.to_string(),
            },
            Self::UnknownCa => ChainNegative::UnknownCa,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WebhookRequestKind {
    Valid,
    TamperedBody,
    WrongSecret,
    StaleTimestamp,
    MissingSignature,
    MalformedSignature,
}

impl WebhookRequestKind {
    const fn rejection_class(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::TamperedBody => "tampered_body",
            Self::WrongSecret => "wrong_secret",
            Self::StaleTimestamp => "stale_timestamp",
            Self::MissingSignature => "missing_signature",
            Self::MalformedSignature => "malformed_signature",
        }
    }

    const fn expected_result(self) -> &'static str {
        match self {
            Self::Valid => "accept",
            Self::TamperedBody
            | Self::WrongSecret
            | Self::StaleTimestamp
            | Self::MissingSignature
            | Self::MalformedSignature => "reject",
        }
    }
}

/// Documented expected hostname for the TLS profile's valid leaf.
const TLS_EXPECTED_HOSTNAME: &str = "valid.tls.uselesskey.test";
/// Documented wrong hostname for the hostname-mismatch negative fixture.
const TLS_WRONG_HOSTNAME: &str = "wrong.tls.uselesskey.test";

impl BundleEntry {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Standard { name, .. } => name,
            Self::OidcValidJwks => "jwks/valid",
            Self::OidcNegativeJwks { name, .. } | Self::OidcNegativeToken { name, .. } => name,
            Self::OidcValidToken => "tokens/valid-rs256",
            Self::TlsValidLeaf => "certs/valid-leaf",
            Self::TlsValidChain => "certs/valid-chain",
            Self::TlsNegativeChain { name, .. } => name,
            Self::TlsEvidenceDoc => "evidence/tls-profile",
            Self::WebhookRequest { name, .. } => name,
            Self::WebhookEvidenceDoc => "evidence/webhook-profile",
        }
    }

    const fn kind(self) -> Kind {
        match self {
            Self::Standard { kind, .. } => kind,
            Self::OidcValidJwks | Self::OidcNegativeJwks { .. } => Kind::Jwks,
            Self::OidcValidToken | Self::OidcNegativeToken { .. } => Kind::Token,
            Self::TlsValidLeaf
            | Self::TlsValidChain
            | Self::TlsNegativeChain { .. }
            | Self::TlsEvidenceDoc => Kind::X509,
            Self::WebhookRequest { .. } | Self::WebhookEvidenceDoc => Kind::Hmac,
        }
    }

    const fn kind_name(self) -> &'static str {
        match self {
            Self::WebhookRequest { .. } | Self::WebhookEvidenceDoc => "webhook",
            _ => self.kind().manifest_name(),
        }
    }

    pub(crate) fn preferred_format(self, requested: Format, profile: BundleProfile) -> Format {
        match self {
            Self::Standard { kind, .. } => preferred_bundle_format(kind, requested, profile),
            Self::OidcValidJwks | Self::OidcNegativeJwks { .. } => Format::Jwks,
            Self::OidcValidToken | Self::OidcNegativeToken { .. } => Format::JsonManifest,
            Self::TlsValidLeaf | Self::TlsValidChain | Self::TlsNegativeChain { .. } => Format::Pem,
            Self::TlsEvidenceDoc => Format::Pem,
            Self::WebhookRequest { .. } | Self::WebhookEvidenceDoc => Format::JsonManifest,
        }
    }

    pub(crate) fn file_name(self, format: Format, artifact: &Artifact) -> String {
        match self {
            Self::Standard { name, .. } => {
                let ext = format_extension(format, artifact);
                format!("{name}.{ext}")
            }
            Self::TlsValidLeaf | Self::TlsValidChain | Self::TlsNegativeChain { .. } => {
                format!("{}.pem", self.name())
            }
            Self::TlsEvidenceDoc => format!("{}.md", self.name()),
            Self::WebhookEvidenceDoc => format!("{}.md", self.name()),
            _ => format!("{}.json", self.name()),
        }
    }

    fn description(self, profile: BundleProfile) -> &'static str {
        match self {
            Self::Standard { kind, .. } => bundle_artifact_description(kind, profile),
            Self::OidcValidJwks => "OIDC valid JWKS fixture",
            Self::OidcValidToken => "OIDC valid RS256 JWT-shaped token fixture",
            Self::OidcNegativeJwks { description, .. }
            | Self::OidcNegativeToken { description, .. } => description,
            Self::TlsValidLeaf => "TLS valid leaf certificate (PEM)",
            Self::TlsValidChain => "TLS valid full chain: leaf + intermediate + root (PEM)",
            Self::TlsNegativeChain { description, .. } => description,
            Self::TlsEvidenceDoc => "TLS profile per-fixture rejection-expectation evidence",
            Self::WebhookRequest { description, .. } => description,
            Self::WebhookEvidenceDoc => "Webhook profile verifier expectation evidence",
        }
    }
}

pub(crate) fn bundle_entries(profile: BundleProfile) -> Vec<BundleEntry> {
    if matches!(profile, BundleProfile::Oidc) {
        return vec![
            BundleEntry::OidcValidJwks,
            BundleEntry::OidcNegativeJwks {
                name: "jwks/negative-duplicate-kid",
                variant: NegativeJwks::DuplicateKid,
                description: "OIDC negative JWKS with duplicate kid values",
            },
            BundleEntry::OidcNegativeJwks {
                name: "jwks/negative-missing-kid",
                variant: NegativeJwks::MissingKid,
                description: "OIDC negative JWKS with missing kid",
            },
            BundleEntry::OidcValidToken,
            BundleEntry::OidcNegativeToken {
                name: "tokens/negative-alg-none",
                variant: NegativeToken::AlgNone,
                description: "OIDC negative token with alg none",
            },
            BundleEntry::OidcNegativeToken {
                name: "tokens/negative-bad-audience",
                variant: NegativeToken::BadAudience,
                description: "OIDC negative token with bad audience",
            },
        ];
    }

    if matches!(profile, BundleProfile::Tls) {
        return vec![
            BundleEntry::TlsValidLeaf,
            BundleEntry::TlsValidChain,
            BundleEntry::TlsNegativeChain {
                name: "certs/negative-expired-leaf",
                variant: TlsChainNegativeKind::ExpiredLeaf,
                description: "TLS negative chain with expired leaf (notAfter in past)",
            },
            BundleEntry::TlsNegativeChain {
                name: "certs/negative-not-yet-valid",
                variant: TlsChainNegativeKind::NotYetValidLeaf,
                description: "TLS negative chain with not-yet-valid leaf (notBefore in future)",
            },
            BundleEntry::TlsNegativeChain {
                name: "certs/negative-wrong-hostname",
                variant: TlsChainNegativeKind::HostnameMismatch,
                description: "TLS negative chain with leaf SAN/CN mismatch against expected hostname",
            },
            BundleEntry::TlsNegativeChain {
                name: "certs/negative-untrusted-root",
                variant: TlsChainNegativeKind::UnknownCa,
                description: "TLS negative chain anchored to an untrusted root CA",
            },
            BundleEntry::TlsEvidenceDoc,
        ];
    }

    if matches!(profile, BundleProfile::Webhook) {
        return vec![
            BundleEntry::WebhookRequest {
                name: "requests/valid",
                variant: WebhookRequestKind::Valid,
                description: "Webhook valid HMAC request",
            },
            BundleEntry::WebhookRequest {
                name: "requests/negative-tampered-body",
                variant: WebhookRequestKind::TamperedBody,
                description: "Webhook negative request with modified body",
            },
            BundleEntry::WebhookRequest {
                name: "requests/negative-wrong-secret",
                variant: WebhookRequestKind::WrongSecret,
                description: "Webhook negative request signed with the wrong secret",
            },
            BundleEntry::WebhookRequest {
                name: "requests/negative-stale-timestamp",
                variant: WebhookRequestKind::StaleTimestamp,
                description: "Webhook negative request outside timestamp tolerance",
            },
            BundleEntry::WebhookRequest {
                name: "requests/negative-missing-signature",
                variant: WebhookRequestKind::MissingSignature,
                description: "Webhook negative request missing the signature header",
            },
            BundleEntry::WebhookRequest {
                name: "requests/negative-malformed-signature",
                variant: WebhookRequestKind::MalformedSignature,
                description: "Webhook negative request with malformed signature",
            },
            BundleEntry::WebhookEvidenceDoc,
        ];
    }

    standard_bundle_entries()
        .into_iter()
        .map(|(name, kind)| BundleEntry::Standard { name, kind })
        .collect()
}

fn standard_bundle_entries() -> [(&'static str, Kind); 8] {
    [
        ("rsa", Kind::Rsa),
        ("ecdsa", Kind::Ecdsa),
        ("ed25519", Kind::Ed25519),
        ("hmac", Kind::Hmac),
        ("token", Kind::Token),
        ("x509", Kind::X509),
        ("jwk", Kind::Jwk),
        ("jwks", Kind::Jwks),
    ]
}

pub(crate) fn bundle_artifact_record(
    entry: BundleEntry,
    format: Format,
    path: &str,
    profile: BundleProfile,
) -> BundleArtifactRecord {
    BundleArtifactRecord {
        path: path.to_string(),
        kind: entry.kind_name().to_string(),
        format: format.manifest_name().to_string(),
        profile: profile.manifest_name().to_string(),
        lanes: vec!["runtime".to_string(), "materialized".to_string()],
        scanner_safe: bundle_entry_is_scanner_safe(entry, profile),
        description: entry.description(profile).to_string(),
    }
}

fn bundle_entry_is_scanner_safe(entry: BundleEntry, profile: BundleProfile) -> bool {
    match (profile, entry) {
        (BundleProfile::ScannerSafe | BundleProfile::Oidc | BundleProfile::Tls, _) => true,
        (BundleProfile::Webhook, BundleEntry::WebhookEvidenceDoc) => true,
        (BundleProfile::Webhook, BundleEntry::WebhookRequest { .. }) => false,
        (BundleProfile::Webhook, _) => false,
        (BundleProfile::Runtime, _) => matches!(entry.kind(), Kind::Jwk | Kind::Jwks | Kind::X509),
    }
}

fn bundle_artifact_description(kind: Kind, profile: BundleProfile) -> &'static str {
    match (profile, kind) {
        (BundleProfile::ScannerSafe, Kind::Hmac) => {
            "scanner-safe symmetric JWK shape with invalid material"
        }
        (BundleProfile::ScannerSafe, Kind::Token) => {
            "scanner-safe near-miss token shape for parser tests"
        }
        (BundleProfile::ScannerSafe, Kind::X509) => "public certificate fixture",
        (BundleProfile::ScannerSafe, _) => "public fixture material",
        (BundleProfile::Runtime, Kind::Jwk | Kind::Jwks | Kind::X509) => {
            "runtime-generated public fixture material"
        }
        (BundleProfile::Runtime, _) => "runtime-generated fixture material",
        (BundleProfile::Oidc, _) => "OIDC fixture material",
        (BundleProfile::Tls, _) => "TLS contract-pack fixture material",
        (BundleProfile::Webhook, _) => "Webhook contract-pack fixture material",
    }
}

pub(crate) fn bundle_receipt_records(profile: BundleProfile) -> Vec<BundleReceiptRecord> {
    vec![
        BundleReceiptRecord {
            path: "receipts/materialization.json".to_string(),
            kind: "materialization".to_string(),
            profile: profile.manifest_name().to_string(),
            description: "deterministic bundle materialization receipt".to_string(),
        },
        BundleReceiptRecord {
            path: "receipts/audit-surface.json".to_string(),
            kind: "audit-surface".to_string(),
            profile: profile.manifest_name().to_string(),
            description: "scanner-safety and lane metadata receipt".to_string(),
        },
    ]
}

pub(crate) fn generate_bundle_receipt_artifact(
    kind: &str,
    seed: &str,
    label: &str,
    format: Format,
    profile: BundleProfile,
    fixture_files: &[String],
    artifacts: &[BundleArtifactRecord],
) -> Result<Artifact> {
    match kind {
        "materialization" => Ok(Artifact::Json(json!({
            "receipt": "materialization",
            "version": 1,
            "profile": profile.manifest_name(),
            "seed": seed,
            "label": label,
            "format": format.manifest_name(),
            "artifact_count": artifacts.len(),
            "files": fixture_files,
            "lanes": bundle_lanes(artifacts),
            "artifacts": artifacts,
        }))),
        "audit-surface" => {
            let scanner_safe_count = artifacts
                .iter()
                .filter(|artifact| artifact.scanner_safe)
                .count();
            Ok(Artifact::Json(json!({
                "receipt": "audit-surface",
                "version": 1,
                "profile": profile.manifest_name(),
                "scanner_safe": scanner_safe_count == artifacts.len(),
                "artifact_count": artifacts.len(),
                "scanner_safe_count": scanner_safe_count,
                "runtime_material_count": artifacts.len() - scanner_safe_count,
                "lanes": bundle_lanes(artifacts),
                "artifacts": artifacts.iter().map(|artifact| {
                    json!({
                        "path": artifact.path,
                        "kind": artifact.kind,
                        "format": artifact.format,
                        "scanner_safe": artifact.scanner_safe,
                        "description": artifact.description,
                    })
                }).collect::<Vec<_>>(),
            })))
        }
        other => bail!("unsupported bundle receipt `{other}`"),
    }
}

fn bundle_lanes(artifacts: &[BundleArtifactRecord]) -> Vec<String> {
    let mut lanes = Vec::new();
    for artifact in artifacts {
        for lane in &artifact.lanes {
            if !lanes.contains(lane) {
                lanes.push(lane.clone());
            }
        }
    }
    lanes
}

fn preferred_bundle_format(kind: Kind, requested: Format, profile: BundleProfile) -> Format {
    if matches!(profile, BundleProfile::ScannerSafe) {
        return match kind {
            Kind::Token => Format::JsonManifest,
            Kind::X509 => Format::Pem,
            Kind::Jwks => Format::Jwks,
            Kind::Rsa | Kind::Ecdsa | Kind::Ed25519 | Kind::Hmac | Kind::Jwk => Format::Jwk,
        };
    }

    match (kind, requested) {
        (Kind::Token, _) => Format::JsonManifest,
        (Kind::X509, Format::Jwk | Format::Jwks) => Format::Pem,
        (Kind::Hmac, Format::Pem) => Format::Der,
        (Kind::Jwk, _) => Format::Jwk,
        (Kind::Jwks, _) => Format::Jwks,
        _ => requested,
    }
}

fn generate_bundle_artifact(
    fx: &Factory,
    kind: Kind,
    name: &str,
    label: &str,
    format: Format,
    profile: BundleProfile,
) -> Result<Artifact> {
    if matches!(profile, BundleProfile::ScannerSafe) {
        return generate_scanner_safe_bundle_artifact(fx, kind, name, label, format);
    }

    generate_artifact(fx, kind, label, format)
}

pub(crate) fn generate_bundle_entry_artifact(
    fx: &Factory,
    entry: BundleEntry,
    label: &str,
    format: Format,
    profile: BundleProfile,
) -> Result<Artifact> {
    match entry {
        BundleEntry::Standard { name, kind } => {
            generate_bundle_artifact(fx, kind, name, label, format, profile)
        }
        BundleEntry::OidcValidJwks => {
            if matches!(format, Format::Jwks) {
                Ok(Artifact::Json(
                    fx.rsa(label, RsaSpec::rs256()).public_jwks_json(),
                ))
            } else {
                unsupported(Kind::Jwks, format)
            }
        }
        BundleEntry::OidcNegativeJwks { variant, .. } => {
            if matches!(format, Format::Jwks) {
                Ok(Artifact::Json(
                    fx.rsa(label, RsaSpec::rs256())
                        .public_jwks()
                        .negative_value(variant),
                ))
            } else {
                unsupported(Kind::Jwks, format)
            }
        }
        BundleEntry::OidcValidToken => {
            let token = fx.token(label, TokenSpec::oauth_access_token());
            if matches!(format, Format::JsonManifest) {
                Ok(Artifact::Json(json!({
                    "kind": "token",
                    "label": label,
                    "profile": "oidc",
                    "alg": "RS256",
                    "value": token.value(),
                })))
            } else {
                unsupported(Kind::Token, format)
            }
        }
        BundleEntry::OidcNegativeToken { variant, .. } => {
            let token = fx.token(label, TokenSpec::oauth_access_token());
            if matches!(format, Format::JsonManifest) {
                Ok(Artifact::Json(json!({
                    "kind": "token",
                    "label": label,
                    "profile": "oidc",
                    "negative": variant.variant_name(),
                    "value": token.negative_value(variant),
                })))
            } else {
                unsupported(Kind::Token, format)
            }
        }
        BundleEntry::TlsValidLeaf => {
            let chain = tls_valid_chain(fx, label);
            Ok(Artifact::Text(chain.leaf_cert_pem().to_string()))
        }
        BundleEntry::TlsValidChain => {
            let chain = tls_valid_chain(fx, label);
            Ok(Artifact::Text(chain.full_chain_pem()))
        }
        BundleEntry::TlsNegativeChain { variant, .. } => {
            let valid = tls_valid_chain(fx, label);
            let negative = valid.negative(variant.to_chain_negative());
            Ok(Artifact::Text(negative.leaf_cert_pem().to_string()))
        }
        BundleEntry::TlsEvidenceDoc => Ok(Artifact::Text(render_tls_evidence_markdown())),
        BundleEntry::WebhookRequest { variant, .. } => {
            if matches!(format, Format::JsonManifest) {
                Ok(Artifact::Json(generate_webhook_request_fixture(
                    fx, label, variant,
                )))
            } else {
                unsupported(Kind::Hmac, format)
            }
        }
        BundleEntry::WebhookEvidenceDoc => Ok(Artifact::Text(render_webhook_evidence_markdown())),
    }
}

fn tls_valid_chain(fx: &Factory, label: &str) -> X509Chain {
    fx.x509_chain(label, ChainSpec::new(TLS_EXPECTED_HOSTNAME))
}

fn render_tls_evidence_markdown() -> String {
    let mut out = String::new();
    out.push_str("# TLS contract-pack profile evidence\n\n");
    out.push_str(
        "Per-fixture role and rejection-class expectations for the TLS contract\n\
         pack generated by `uselesskey bundle --profile tls`. See\n\
         `docs/release/v0.8.0-tls-profile-design.md` for the full design.\n\n",
    );
    out.push_str(&format!("Expected hostname: `{TLS_EXPECTED_HOSTNAME}`\n"));
    out.push_str(&format!(
        "Hostname-mismatch wrong hostname: `{TLS_WRONG_HOSTNAME}`\n\n",
    ));
    out.push_str("| File | Role | Failure class |\n");
    out.push_str("|---|---|---|\n");
    out.push_str("| `certs/valid-leaf.pem` | Valid leaf signed by the bundle's intermediate | (none - happy path) |\n");
    out.push_str("| `certs/valid-chain.pem` | Full chain: leaf + intermediate + root | (none - happy path) |\n");
    out.push_str(
        "| `certs/negative-expired-leaf.pem` | Leaf with notAfter in the past | expired |\n",
    );
    out.push_str("| `certs/negative-not-yet-valid.pem` | Leaf with notBefore in the future | not yet valid |\n");
    out.push_str("| `certs/negative-wrong-hostname.pem` | Leaf SAN/CN does not match expected hostname | hostname mismatch |\n");
    out.push_str("| `certs/negative-untrusted-root.pem` | Leaf chained to an untrusted root CA | unknown CA |\n");
    out
}

fn generate_webhook_request_fixture(
    fx: &Factory,
    label: &str,
    variant: WebhookRequestKind,
) -> serde_json::Value {
    let valid = fx.webhook_stripe(label, WebhookPayloadSpec::Canonical);
    let mut headers = valid.headers.clone();
    let mut body = valid.payload.clone();
    let mut timestamp = valid.timestamp;

    match variant {
        WebhookRequestKind::Valid => {}
        WebhookRequestKind::TamperedBody => {
            body.push('\n');
        }
        WebhookRequestKind::WrongSecret => {
            let wrong = valid.near_miss_wrong_secret();
            headers = wrong.headers;
            timestamp = wrong.timestamp;
        }
        WebhookRequestKind::StaleTimestamp => {
            let stale = valid.near_miss_stale_timestamp(300);
            headers = stale.headers;
            timestamp = stale.timestamp;
        }
        WebhookRequestKind::MissingSignature => {
            headers.remove("Stripe-Signature");
        }
        WebhookRequestKind::MalformedSignature => {
            headers.insert(
                "Stripe-Signature".to_string(),
                format!("t={timestamp},v1=not-a-hex-signature"),
            );
        }
    }

    json!({
        "method": "POST",
        "path": "/webhooks/uselesskey",
        "timestamp": timestamp,
        "body": body,
        "headers": headers,
        "expected_result": variant.expected_result(),
        "rejection_class": variant.rejection_class(),
        "profile": "webhook",
        "signature_profile": "stripe-shaped-hmac-sha256",
        "verifier_secret": valid.secret,
        "claim_boundary": "Deterministic HMAC verifier fixture; not provider compatibility or production secret management proof."
    })
}

fn render_webhook_evidence_markdown() -> String {
    let mut out = String::new();
    out.push_str("# Webhook contract-pack profile evidence\n\n");
    out.push_str(
        "Per-fixture verifier expectations for the webhook contract pack\n\
         generated by `uselesskey bundle --profile webhook`. The fixtures are\n\
         provider-shaped HMAC-SHA256 requests, not provider compatibility\n\
         claims.\n\n",
    );
    out.push_str("Verifier path: `POST /webhooks/uselesskey`\n");
    out.push_str("Timestamp tolerance used by proof: `300` seconds\n\n");
    out.push_str("| File | Expected result | Rejection class |\n");
    out.push_str("|---|---|---|\n");
    out.push_str("| `requests/valid.json` | accept | valid |\n");
    out.push_str("| `requests/negative-tampered-body.json` | reject | tampered_body |\n");
    out.push_str("| `requests/negative-wrong-secret.json` | reject | wrong_secret |\n");
    out.push_str("| `requests/negative-stale-timestamp.json` | reject | stale_timestamp |\n");
    out.push_str("| `requests/negative-missing-signature.json` | reject | missing_signature |\n");
    out.push_str(
        "| `requests/negative-malformed-signature.json` | reject | malformed_signature |\n\n",
    );
    out.push_str("Boundary: proves deterministic HMAC webhook verifier behavior for fixture requests; does not prove provider compatibility, replay protection completeness, transport security, or production secret management.\n");
    out
}

fn generate_scanner_safe_bundle_artifact(
    fx: &Factory,
    kind: Kind,
    name: &str,
    label: &str,
    format: Format,
) -> Result<Artifact> {
    match kind {
        Kind::Hmac => {
            if matches!(format, Format::Jwk) {
                Ok(Artifact::Json(json!({
                    "kty": "oct",
                    "use": "sig",
                    "alg": "HS256",
                    "kid": format!("{label}-{name}"),
                    "k": "not_base64url!*",
                })))
            } else {
                unsupported(kind, format)
            }
        }
        Kind::Token => {
            let token = fx.token(label, TokenSpec::api_key());
            if matches!(format, Format::JsonManifest) {
                Ok(Artifact::Json(json!({
                    "kind": "token",
                    "label": label,
                    "negative": NegativeToken::NearMissApiKey.variant_name(),
                    "value": token.negative_value(NegativeToken::NearMissApiKey),
                })))
            } else {
                unsupported(kind, format)
            }
        }
        _ => generate_artifact(fx, kind, label, format),
    }
}

pub(crate) fn generate_artifact(
    fx: &Factory,
    kind: Kind,
    label: &str,
    format: Format,
) -> Result<Artifact> {
    match kind {
        Kind::Rsa => {
            let kp = fx.rsa(label, RsaSpec::rs256());
            match format {
                Format::Pem => Ok(Artifact::Text(kp.private_key_pkcs8_pem().to_string())),
                Format::Der => Ok(Artifact::Binary(kp.private_key_pkcs8_der().to_vec())),
                Format::Jwk => Ok(Artifact::Json(kp.public_jwk_json())),
                Format::Jwks => Ok(Artifact::Json(kp.public_jwks_json())),
                _ => unsupported(kind, format),
            }
        }
        Kind::Ecdsa => {
            let kp = fx.ecdsa(label, EcdsaSpec::es256());
            match format {
                Format::Pem => Ok(Artifact::Text(kp.private_key_pkcs8_pem().to_string())),
                Format::Der => Ok(Artifact::Binary(kp.private_key_pkcs8_der().to_vec())),
                Format::Jwk => Ok(Artifact::Json(kp.public_jwk_json())),
                Format::Jwks => Ok(Artifact::Json(kp.public_jwks_json())),
                _ => unsupported(kind, format),
            }
        }
        Kind::Ed25519 => {
            let kp = fx.ed25519(label, Ed25519Spec::new());
            match format {
                Format::Pem => Ok(Artifact::Text(kp.private_key_pkcs8_pem().to_string())),
                Format::Der => Ok(Artifact::Binary(kp.private_key_pkcs8_der().to_vec())),
                Format::Jwk => Ok(Artifact::Json(kp.public_jwk_json())),
                Format::Jwks => Ok(Artifact::Json(kp.public_jwks_json())),
                _ => unsupported(kind, format),
            }
        }
        Kind::Hmac => {
            let sec = fx.hmac(label, HmacSpec::hs256());
            match format {
                Format::Der => Ok(Artifact::Binary(sec.secret_bytes().to_vec())),
                Format::Jwk => Ok(Artifact::Json(sec.jwk().to_value())),
                Format::Jwks => Ok(Artifact::Json(sec.jwks().to_value())),
                _ => unsupported(kind, format),
            }
        }
        Kind::Token => {
            let token = fx.token(label, TokenSpec::api_key());
            match format {
                Format::Pem => Ok(Artifact::Text(token.value().to_string())),
                Format::JsonManifest => Ok(Artifact::Json(
                    json!({"kind":"token","label":label,"value":token.value()}),
                )),
                _ => unsupported(kind, format),
            }
        }
        Kind::X509 => {
            let cert = fx.x509_self_signed(label, X509Spec::self_signed(label));
            match format {
                Format::Pem => Ok(Artifact::Text(cert.cert_pem().to_string())),
                Format::Der => Ok(Artifact::Binary(cert.cert_der().to_vec())),
                _ => unsupported(kind, format),
            }
        }
        Kind::Jwk => {
            let kp = fx.rsa(label, RsaSpec::rs256());
            if matches!(format, Format::Jwk) {
                Ok(Artifact::Json(kp.public_jwk_json()))
            } else {
                unsupported(kind, format)
            }
        }
        Kind::Jwks => {
            let kp = fx.rsa(label, RsaSpec::rs256());
            if matches!(format, Format::Jwks) {
                Ok(Artifact::Json(kp.public_jwks_json()))
            } else {
                unsupported(kind, format)
            }
        }
    }
}

fn unsupported(kind: Kind, format: Format) -> Result<Artifact> {
    bail!("unsupported format {format:?} for kind {kind:?}")
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct BundleManifest {
    pub(crate) version: u32,
    #[serde(default = "default_bundle_profile")]
    pub(crate) profile: String,
    pub(crate) seed: String,
    pub(crate) label: String,
    pub(crate) format: String,
    pub(crate) files: Vec<String>,
    #[serde(default)]
    pub(crate) artifacts: Vec<BundleArtifactRecord>,
    #[serde(default)]
    pub(crate) receipts: Vec<BundleReceiptRecord>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct BundleArtifactRecord {
    pub(crate) path: String,
    pub(crate) kind: String,
    pub(crate) format: String,
    pub(crate) profile: String,
    pub(crate) lanes: Vec<String>,
    pub(crate) scanner_safe: bool,
    pub(crate) description: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct BundleReceiptRecord {
    pub(crate) path: String,
    pub(crate) kind: String,
    pub(crate) profile: String,
    pub(crate) description: String,
}

fn default_bundle_profile() -> String {
    "runtime".to_string()
}
