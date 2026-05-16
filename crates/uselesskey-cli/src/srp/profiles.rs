use super::super::BundleProfile;

const DISCOVERABLE_PROFILES: [BundleProfile; 5] = [
    BundleProfile::ScannerSafe,
    BundleProfile::Tls,
    BundleProfile::Oidc,
    BundleProfile::Webhook,
    BundleProfile::Runtime,
];

#[derive(Clone, Copy)]
struct ProfileInfo {
    profile: BundleProfile,
    title: &'static str,
    purpose: &'static str,
    required_feature: &'static str,
    scanner_posture: &'static str,
    proof_command: &'static str,
    claim: Option<&'static str>,
    docs: &'static str,
    generates: &'static [&'static str],
    proves: &'static [&'static str],
    not_proves: &'static [&'static str],
}

fn profile_info(profile: BundleProfile) -> ProfileInfo {
    match profile {
        BundleProfile::ScannerSafe => ProfileInfo {
            profile,
            title: "Scanner-safe baseline bundle",
            purpose: "baseline scanner-safe fixtures, receipts, and export handoff metadata",
            required_feature: "uselesskey-cli default features",
            scanner_posture: "scanner-safe fixture material; generated exports still belong under target/",
            proof_command: "cargo xtask claim-proof --claim scanner-safe-fixtures",
            claim: Some("scanner-safe-fixtures"),
            docs: "docs/how-to/generate-scanner-safe-k8s-secret.md",
            generates: &[
                "RSA/ECDSA/Ed25519/HMAC public fixture shapes",
                "token and X.509 fixture shapes",
                "manifest.json",
                "receipts/materialization.json",
                "receipts/audit-surface.json",
            ],
            proves: &[
                "repo policy found no committed secret-shaped fixture blobs",
                "the bundle has a manifest and audit receipts",
                "scanner-safe badge drift checks still agree with policy",
            ],
            not_proves: &[
                "every derived encoded export is safe to commit",
                "production key management",
                "scanner evasion",
                "cryptographic assurance",
            ],
        },
        BundleProfile::Tls => ProfileInfo {
            profile,
            title: "TLS contract pack",
            purpose: "TLS chain and certificate rejection fixtures",
            required_feature: "uselesskey-cli default features",
            scanner_posture: "generated PEM payloads stay under target/; proof receipts are metadata",
            proof_command: "cargo xtask claim-proof --claim tls-contract-pack",
            claim: Some("tls-contract-pack"),
            docs: "docs/how-to/test-tls-chain-validation.md",
            generates: &[
                "certs/valid-leaf.pem",
                "certs/valid-chain.pem",
                "expired, not-yet-valid, wrong-hostname, and untrusted-root negatives",
                "evidence/tls-profile.md",
                "manifest and receipts",
            ],
            proves: &[
                "documented TLS fixture files are generated",
                "positive and negative certificate paths are present",
                "receipts and evidence docs are present",
            ],
            not_proves: &[
                "production PKI",
                "revocation, OCSP, certificate transparency, or mTLS",
                "browser trust-store behavior",
                "downstream verifier correctness",
            ],
        },
        BundleProfile::Oidc => ProfileInfo {
            profile,
            title: "OIDC/JWKS contract pack",
            purpose: "OIDC/JWKS validator fixtures and JWT-shaped negatives",
            required_feature: "uselesskey-cli default features",
            scanner_posture: "generated token/JWKS payloads stay under target/; proof receipts are metadata",
            proof_command: "cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc",
            claim: Some("oidc-jwks-contract-pack"),
            docs: "docs/how-to/test-oidc-jwks-validation.md",
            generates: &[
                "valid JWKS and RS256 JWT-shaped fixtures",
                "duplicate-kid and missing-kid JWKS negatives",
                "alg-none and bad-audience token negatives",
                "manifest and receipts",
            ],
            proves: &[
                "deterministic JWKS and JWT-shaped fixtures are generated",
                "documented validator negative inputs exist",
                "receipts and evidence docs are present",
            ],
            not_proves: &[
                "production signing-key custody",
                "full OpenID provider behavior",
                "issuer policy",
                "downstream validator correctness",
            ],
        },
        BundleProfile::Webhook => ProfileInfo {
            profile,
            title: "Webhook contract pack",
            purpose: "HMAC webhook signature positives and negatives",
            required_feature: "uselesskey-cli default features",
            scanner_posture: "generated request payloads stay under target/; proof receipts are metadata",
            proof_command: "cargo xtask claim-proof --claim webhook-contract-pack",
            claim: Some("webhook-contract-pack"),
            docs: "docs/how-to/test-webhook-signature-validation.md",
            generates: &[
                "requests/valid.json",
                "tampered-body, wrong-secret, stale-timestamp, missing-signature, and malformed-signature negatives",
                "evidence/webhook-profile.md",
                "manifest and receipts",
            ],
            proves: &[
                "deterministic HMAC verifier fixture behavior",
                "valid signature acceptance and documented rejection classes",
                "receipts and evidence docs are present",
            ],
            not_proves: &[
                "provider compatibility",
                "production secret management",
                "replay protection completeness",
                "delivery retries or transport security",
                "downstream verifier correctness",
            ],
        },
        BundleProfile::Runtime => ProfileInfo {
            profile,
            title: "Runtime bundle",
            purpose: "general runtime fixture bundle for local experimentation",
            required_feature: "uselesskey-cli default features",
            scanner_posture: "may include runtime fixture material; keep generated payloads under target/",
            proof_command: "uselesskey verify-bundle --path target/uselesskey-runtime",
            claim: None,
            docs: "README.md",
            generates: &[
                "general JWK/JWKS/X.509 fixture outputs",
                "manifest.json",
                "receipts/materialization.json",
                "receipts/audit-surface.json",
            ],
            proves: &[
                "the bundle can be regenerated and verified against its manifest",
                "local output shape is internally consistent",
            ],
            not_proves: &[
                "a public contract-pack claim",
                "scanner-safe commit posture",
                "production security behavior",
            ],
        },
    }
}

pub(crate) fn render_profiles(explain: bool) -> String {
    let mut out = String::new();
    out.push_str("Available uselesskey profiles\n\n");
    out.push_str("| Profile | Purpose | Proof |\n");
    out.push_str("|---|---|---|\n");
    for profile in DISCOVERABLE_PROFILES {
        let info = profile_info(profile);
        out.push_str(&format!(
            "| `{}` | {} | `{}` |\n",
            info.profile.manifest_name(),
            info.purpose,
            info.proof_command
        ));
    }
    out.push_str("\nUse `uselesskey profile <name> --explain` for generated files, boundaries, and copyable commands.\n");

    if explain {
        out.push('\n');
        for profile in DISCOVERABLE_PROFILES {
            out.push_str(&render_profile_explanation(profile));
            out.push('\n');
        }
    }

    out
}

pub(crate) fn render_profile_summary(profile: BundleProfile) -> String {
    let info = profile_info(profile);
    format!(
        concat!(
            "Profile: {}\n",
            "Title: {}\n",
            "Purpose: {}\n",
            "Generate: uselesskey bundle --profile {} --out {}\n",
            "Verify: uselesskey verify-bundle --path {}\n",
            "Proof: {}\n",
            "Explain: uselesskey profile {} --explain\n",
            "Bundle explain: uselesskey bundle --profile {} --explain\n",
        ),
        info.profile.manifest_name(),
        info.title,
        info.purpose,
        info.profile.manifest_name(),
        info.profile.output_dir_hint(),
        info.profile.output_dir_hint(),
        info.proof_command,
        info.profile.manifest_name(),
        info.profile.manifest_name(),
    )
}

pub(crate) fn render_profile_explanation(profile: BundleProfile) -> String {
    let info = profile_info(profile);
    let mut out = render_profile_summary(profile);
    out.push_str(&format!("Required feature: {}\n", info.required_feature));
    out.push_str(&format!(
        "Scanner/runtime posture: {}\n",
        info.scanner_posture
    ));
    if let Some(claim) = info.claim {
        out.push_str(&format!("Claim: {claim}\n"));
    }
    out.push_str(&format!("Docs: {}\n", info.docs));
    push_list(&mut out, "\nGenerates", info.generates);
    push_list(&mut out, "\nProves", info.proves);
    push_list(&mut out, "\nDoes not prove", info.not_proves);
    out
}

fn push_list(out: &mut String, title: &str, items: &[&str]) {
    out.push_str(title);
    out.push_str(":\n");
    for item in items {
        out.push_str("- ");
        out.push_str(item);
        out.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_list_includes_contract_pack_boundaries() {
        let rendered = render_profiles(false);

        assert!(rendered.contains("scanner-safe"));
        assert!(rendered.contains("tls"));
        assert!(rendered.contains("oidc"));
        assert!(rendered.contains("webhook"));
        assert!(rendered.contains("claim-proof --claim webhook-contract-pack"));
    }

    #[test]
    fn webhook_profile_explain_mentions_negative_classes_and_limits() {
        let rendered = render_profile_explanation(BundleProfile::Webhook);

        assert!(rendered.contains("requests/valid.json"));
        assert!(rendered.contains("wrong-secret"));
        assert!(rendered.contains("missing-signature"));
        assert!(rendered.contains("provider compatibility"));
        assert!(rendered.contains("production secret management"));
    }
}
