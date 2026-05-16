use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::verification_pack;

const USER_PATH_PROFILES: &[&str] = &["scanner-safe", "tls", "oidc", "webhook"];

pub fn run(root: &Path) -> Result<()> {
    let out_root = root.join("target/user-path-smoke");
    reset_target_output(root, &out_root)?;

    for profile in USER_PATH_PROFILES {
        let bundle_dir = out_root.join(profile);
        run_cli(
            root,
            &[
                "bundle",
                "--profile",
                profile,
                "--out",
                bundle_dir
                    .to_str()
                    .context("user-path-smoke output path is not UTF-8")?,
            ],
        )
        .with_context(|| format!("user-path-smoke bundle profile `{profile}` failed"))?;

        run_cli(
            root,
            &[
                "verify-bundle",
                "--path",
                bundle_dir
                    .to_str()
                    .context("user-path-smoke output path is not UTF-8")?,
            ],
        )
        .with_context(|| format!("user-path-smoke verify profile `{profile}` failed"))?;
    }

    verification_pack::run(
        root,
        &out_root.join("verification-webhook"),
        Some("webhook-contract-pack"),
    )
    .context("user-path-smoke webhook verification-pack failed")?;

    println!("user-path-smoke: wrote {}", out_root.display());
    Ok(())
}

fn run_cli(root: &Path, args: &[&str]) -> Result<()> {
    let status = Command::new("cargo")
        .args(["run", "--quiet", "-p", "uselesskey-cli", "--"])
        .args(args)
        .current_dir(root)
        .stdin(Stdio::null())
        .status()
        .context("failed to spawn uselesskey-cli via cargo run")?;
    if !status.success() {
        bail!("uselesskey-cli exited with {status}");
    }
    Ok(())
}

fn reset_target_output(root: &Path, out_root: &Path) -> Result<()> {
    ensure_target_child(root, out_root)?;
    if out_root.exists() {
        fs::remove_dir_all(out_root)
            .with_context(|| format!("failed to remove {}", out_root.display()))?;
    }
    fs::create_dir_all(out_root).with_context(|| format!("failed to create {}", out_root.display()))
}

fn ensure_target_child(root: &Path, path: &Path) -> Result<()> {
    let absolute = absolute_path(root, path);
    let target_root = absolute_path(root, &root.join("target"));
    if !absolute.starts_with(&target_root) {
        bail!(
            "user-path-smoke refuses to write outside target/: {}",
            path.display()
        );
    }
    Ok(())
}

fn absolute_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_path_smoke_profiles_are_bounded() {
        assert_eq!(
            USER_PATH_PROFILES,
            ["scanner-safe", "tls", "oidc", "webhook"]
        );
    }

    #[test]
    fn user_path_smoke_rejects_non_target_output() {
        let root = std::env::temp_dir().join("uselesskey-user-path-smoke-test");
        let outside = root
            .parent()
            .unwrap_or_else(|| Path::new("/"))
            .join("outside-user-path-smoke");
        let err = ensure_target_child(&root, &outside).unwrap_err();

        assert!(err.to_string().contains("outside target"));
    }

    #[test]
    fn user_path_smoke_accepts_target_output() {
        let root = std::env::temp_dir().join("uselesskey-user-path-smoke-test");

        ensure_target_child(&root, &root.join("target/user-path-smoke")).unwrap();
    }
}
