use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use uselesskey::jwk::JwksBuilder;
use uselesskey::{
    ChainSpec, Factory, RsaFactoryExt, RsaSpec, TokenFactoryExt, TokenSpec, X509FactoryExt,
};

const CORPUS_SEED: &str = "uselesskey-public-corpus-v1";

#[derive(Clone)]
pub struct CorpusCase {
    pub id: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub files: Vec<(String, Vec<u8>)>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileEntry {
    path: String,
    blake3: String,
    size_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct CaseEntry {
    id: String,
    category: String,
    description: String,
    files: Vec<FileEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    schema_version: u32,
    corpus_version: String,
    seed: String,
    case_count: usize,
    cases: Vec<CaseEntry>,
}

pub fn build() -> Result<()> {
    let version = workspace_package_version("uselesskey")?;
    let version_dir = version_dir_name(&version);
    let out_root = PathBuf::from("corpus").join(&version_dir);

    build_into(&out_root, &version, true)?;
    println!("built corpus at {}", out_root.display());
    Ok(())
}

pub fn verify() -> Result<()> {
    let version = workspace_package_version("uselesskey")?;
    let version_dir = version_dir_name(&version);
    let checked_in = PathBuf::from("corpus").join(&version_dir);

    if !checked_in.exists() {
        bail!(
            "{} does not exist; run `cargo xtask corpus build` first",
            checked_in.display()
        );
    }

    let temp = tempfile::tempdir().context("failed to create temporary corpus directory")?;
    let rebuilt = temp.path().join(&version_dir);
    build_into(&rebuilt, &version, false)?;

    compare_dirs(&checked_in, &rebuilt)?;
    println!("corpus verification passed for {}", checked_in.display());
    Ok(())
}

fn build_into(out_root: &Path, version: &str, write_root_readme: bool) -> Result<()> {
    if out_root.exists() {
        fs::remove_dir_all(out_root)
            .with_context(|| format!("failed to clear {}", out_root.display()))?;
    }
    fs::create_dir_all(out_root)
        .with_context(|| format!("failed to create {}", out_root.display()))?;

    let cases = corpus_cases();
    ensure_unique_case_ids(&cases)?;

    let mut manifest_cases = Vec::new();

    for case in &cases {
        let case_dir = out_root.join(case.category).join(case.id);
        fs::create_dir_all(&case_dir)
            .with_context(|| format!("failed to create {}", case_dir.display()))?;

        for (name, bytes) in &case.files {
            let path = case_dir.join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            fs::write(&path, bytes)
                .with_context(|| format!("failed to write {}", path.display()))?;
        }

        let mut file_entries = Vec::new();
        for (name, bytes) in &case.files {
            let rel = format!("{}/{}/{}", case.category, case.id, name);
            file_entries.push(FileEntry {
                path: rel,
                blake3: blake3_hex(bytes),
                size_bytes: bytes.len() as u64,
            });
        }
        file_entries.sort_by(|a, b| a.path.cmp(&b.path));

        let case_entry = CaseEntry {
            id: case.id.to_string(),
            category: case.category.to_string(),
            description: case.description.to_string(),
            files: file_entries,
        };

        let case_json = serde_json::to_vec_pretty(&case_entry).context("serialize case metadata")?;
        fs::write(case_dir.join("case.json"), case_json)
            .with_context(|| format!("failed to write {}/case.json", case_dir.display()))?;

        manifest_cases.push(case_entry);
    }

    manifest_cases.sort_by(|a, b| a.id.cmp(&b.id));

    let manifest = Manifest {
        schema_version: 1,
        corpus_version: version_dir_name(version),
        seed: CORPUS_SEED.to_string(),
        case_count: manifest_cases.len(),
        cases: manifest_cases,
    };

    let manifest_json =
        serde_json::to_vec_pretty(&manifest).context("failed to serialize manifest")?;
    fs::write(out_root.join("manifest.json"), manifest_json).with_context(|| {
        format!(
            "failed to write manifest {}",
            out_root.join("manifest.json").display()
        )
    })?;

    fs::write(out_root.join("README.md"), corpus_readme(version))
        .with_context(|| format!("failed to write {}/README.md", out_root.display()))?;

    if write_root_readme {
        fs::write(Path::new("corpus").join("README.md"), root_corpus_readme())
            .context("failed to write corpus/README.md")?;
    }

    Ok(())
}

fn corpus_cases() -> Vec<CorpusCase> {
    let fx = Factory::deterministic_from_str(CORPUS_SEED);

    let chain = fx.x509_chain("corpus-chain-default", ChainSpec::new("api.example.test"));
    let revoked_chain = chain.revoked_leaf();

    let rsa = fx.rsa("corpus-signing-rsa", RsaSpec::rs256());
    let rsa_next = fx.rsa("corpus-signing-rsa-next", RsaSpec::rs256());
    let jwks = JwksBuilder::new()
        .add_public(rsa.public_jwk())
        .add_public(rsa_next.public_jwk())
        .build();

    let oauth = fx.token("corpus-jwt-hs256", TokenSpec::oauth_access_token());
    let corrupt = fx
        .rsa("corpus-corrupt-rsa", RsaSpec::rs256())
        .private_key_pkcs8_pem_corrupt_deterministic("corrupt:truncated");

    vec![
        CorpusCase {
            id: "x509_chain_good_default",
            category: "x509",
            description: "Valid TLS-style chain with leaf/intermediate/root plus leaf key.",
            files: vec![
                (
                    "leaf_cert.pem".to_string(),
                    chain.leaf_cert_pem().as_bytes().to_vec(),
                ),
                (
                    "intermediate_cert.pem".to_string(),
                    chain.intermediate_cert_pem().as_bytes().to_vec(),
                ),
                (
                    "root_cert.pem".to_string(),
                    chain.root_cert_pem().as_bytes().to_vec(),
                ),
                (
                    "chain.pem".to_string(),
                    chain.chain_pem().as_bytes().to_vec(),
                ),
                (
                    "leaf_key.pk8.pem".to_string(),
                    chain.leaf_private_key_pkcs8_pem().as_bytes().to_vec(),
                ),
            ],
        },
        CorpusCase {
            id: "x509_chain_revoked_leaf",
            category: "x509",
            description: "Chain negative fixture where leaf is revoked and CRL is present.",
            files: vec![
                (
                    "leaf_cert.pem".to_string(),
                    revoked_chain.leaf_cert_pem().as_bytes().to_vec(),
                ),
                (
                    "intermediate_cert.pem".to_string(),
                    revoked_chain.intermediate_cert_pem().as_bytes().to_vec(),
                ),
                (
                    "root_cert.pem".to_string(),
                    revoked_chain.root_cert_pem().as_bytes().to_vec(),
                ),
                (
                    "leaf_revocation.crl.pem".to_string(),
                    revoked_chain
                        .crl_pem()
                        .unwrap_or_default()
                        .as_bytes()
                        .to_vec(),
                ),
            ],
        },
        CorpusCase {
            id: "jwk_set_rotated_phase_2",
            category: "jwks",
            description: "Two-key JWKS representing a rotation window with active and next keys.",
            files: vec![(
                "jwks.json".to_string(),
                serde_json::to_vec_pretty(&jwks.to_value()).expect("jwks serialize"),
            )],
        },
        CorpusCase {
            id: "jwt_hs256_basic",
            category: "tokens",
            description: "OAuth/JWT-shape HS256 access token fixture.",
            files: vec![
                ("token.txt".to_string(), oauth.value().as_bytes().to_vec()),
                (
                    "authorization_header.txt".to_string(),
                    oauth.authorization_header().as_bytes().to_vec(),
                ),
            ],
        },
        CorpusCase {
            id: "pem_corrupt_truncated",
            category: "negative",
            description: "Deterministic corrupted PKCS#8 PEM fixture for parser error-path tests.",
            files: vec![
                (
                    "private_key_corrupt.pem".to_string(),
                    corrupt.as_bytes().to_vec(),
                ),
                (
                    "reference_public_key.pem".to_string(),
                    rsa.public_key_spki_pem().as_bytes().to_vec(),
                ),
            ],
        },
    ]
}

fn ensure_unique_case_ids(cases: &[CorpusCase]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for case in cases {
        if !seen.insert(case.id) {
            bail!("duplicate case id detected: {}", case.id);
        }
    }
    Ok(())
}

fn compare_dirs(checked_in: &Path, rebuilt: &Path) -> Result<()> {
    let checked_files = collect_files(checked_in)?;
    let rebuilt_files = collect_files(rebuilt)?;

    if checked_files != rebuilt_files {
        bail!(
            "corpus file set differs between {} and {}",
            checked_in.display(),
            rebuilt.display()
        );
    }

    for rel in checked_files {
        let a = checked_in.join(&rel);
        let b = rebuilt.join(&rel);
        let a_bytes = fs::read(&a).with_context(|| format!("failed to read {}", a.display()))?;
        let b_bytes = fs::read(&b).with_context(|| format!("failed to read {}", b.display()))?;
        if a_bytes != b_bytes {
            bail!("corpus file differs: {}", rel.display());
        }
    }

    Ok(())
}

fn collect_files(root: &Path) -> Result<BTreeSet<PathBuf>> {
    let mut out = BTreeSet::new();
    collect_files_recursive(root, root, &mut out)?;
    Ok(out)
}

fn collect_files_recursive(root: &Path, dir: &Path, out: &mut BTreeSet<PathBuf>) -> Result<()> {
    for entry in
        fs::read_dir(dir).with_context(|| format!("failed to read directory {}", dir.display()))?
    {
        let entry = entry.with_context(|| format!("failed to read entry in {}", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        if file_type.is_dir() {
            collect_files_recursive(root, &path, out)?;
        } else if file_type.is_file() {
            let rel = path
                .strip_prefix(root)
                .with_context(|| format!("failed to strip prefix for {}", path.display()))?;
            out.insert(rel.to_path_buf());
        }
    }
    Ok(())
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn workspace_package_version(name: &str) -> Result<String> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .context("failed to run `cargo metadata` for workspace package version")?;

    if !output.status.success() {
        bail!(
            "`cargo metadata` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let meta: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("failed to parse cargo metadata JSON")?;

    let package = meta["packages"]
        .as_array()
        .context("missing packages in cargo metadata")?
        .iter()
        .find(|pkg| pkg["name"].as_str() == Some(name))
        .with_context(|| format!("package `{name}` not found in workspace metadata"))?;

    let version = package["version"]
        .as_str()
        .context("missing package version in cargo metadata")?;

    Ok(version.to_string())
}

fn version_dir_name(version: &str) -> String {
    format!("v{version}")
}

fn root_corpus_readme() -> String {
    r#"# uselesskey public corpus

This directory contains versioned, deterministic fixture packs generated by:

```bash
cargo xtask corpus build
```

Use:

```bash
cargo xtask corpus verify
```

to rebuild and verify byte-for-byte equality with the checked-in corpus.
"#
    .to_string()
}

fn corpus_readme(version: &str) -> String {
    format!(
        "# uselesskey public corpus {}\n\n",
        version_dir_name(version)
    ) + "This corpus is generated from explicit fixture specs (not scraped examples).\n\n"
        + "## Commands\n\n"
        + "```bash\n"
        + "cargo xtask corpus build\n"
        + "cargo xtask corpus verify\n"
        + "```\n\n"
        + "## Included families\n\n"
        + "- `x509/`\n- `jwks/`\n- `tokens/`\n- `negative/`\n\n"
        + "Each case directory includes `case.json` metadata and one or more fixture files.\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_case_ids_are_rejected() {
        let cases = vec![
            CorpusCase {
                id: "dup",
                category: "x509",
                description: "first",
                files: vec![],
            },
            CorpusCase {
                id: "dup",
                category: "jwks",
                description: "second",
                files: vec![],
            },
        ];
        let err = ensure_unique_case_ids(&cases).expect_err("should reject duplicate ids");
        assert!(err.to_string().contains("duplicate case id"));
    }

    #[test]
    fn default_corpus_has_unique_case_ids() {
        let cases = corpus_cases();
        ensure_unique_case_ids(&cases).expect("ids must be unique");
    }

    #[test]
    fn version_dir_prefixes_v() {
        assert_eq!(version_dir_name("0.5.1"), "v0.5.1");
    }

    #[test]
    fn build_writes_manifest_and_case_metadata() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("v0.5.1");
        build_into(&out, "0.5.1", false).expect("build should work");

        assert!(out.join("manifest.json").exists());
        assert!(out.join("README.md").exists());

        let manifest: Manifest = serde_json::from_slice(
            &fs::read(out.join("manifest.json")).expect("read manifest"),
        )
        .expect("parse manifest");
        assert_eq!(manifest.case_count, manifest.cases.len());
        assert!(!manifest.cases.is_empty());
    }

    #[test]
    fn compare_dirs_detects_changes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();

        fs::write(a.join("file.txt"), b"same").unwrap();
        fs::write(b.join("file.txt"), b"different").unwrap();

        let err = compare_dirs(&a, &b).expect_err("should detect differing file");
        assert!(err.to_string().contains("corpus file differs"));
    }

    #[test]
    fn collect_files_is_stable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("a.txt"), b"a").unwrap();
        fs::write(root.join("nested").join("b.txt"), b"b").unwrap();

        let files = collect_files(&root).expect("collect files");
        let expected = BTreeSet::from([
            PathBuf::from("a.txt"),
            PathBuf::from("nested").join("b.txt"),
        ]);
        assert_eq!(files, expected);
    }

    #[test]
    fn file_hash_uses_blake3() {
        let digest = blake3_hex(b"hello");
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn root_readme_mentions_verify_command() {
        let text = root_corpus_readme();
        assert!(text.contains("cargo xtask corpus verify"));
    }

    #[test]
    fn corpus_contains_named_minimum_cases() {
        let ids = corpus_cases()
            .into_iter()
            .map(|c| c.id.to_string())
            .collect::<BTreeSet<_>>();

        let expected = BTreeSet::from([
            "x509_chain_good_default".to_string(),
            "x509_chain_revoked_leaf".to_string(),
            "jwt_hs256_basic".to_string(),
            "jwk_set_rotated_phase_2".to_string(),
            "pem_corrupt_truncated".to_string(),
        ]);
        assert_eq!(ids, expected);
    }

    #[test]
    fn case_entry_paths_are_unique_per_case() {
        let cases = corpus_cases();
        for case in &cases {
            let mut seen = std::collections::BTreeMap::new();
            for (name, bytes) in &case.files {
                let prev = seen.insert(name.clone(), bytes.len());
                assert!(prev.is_none(), "duplicate file {} in case {}", name, case.id);
            }
        }
    }
}
