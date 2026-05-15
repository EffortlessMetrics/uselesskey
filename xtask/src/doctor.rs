use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::Result;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    status: &'static str,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    id: &'static str,
    label: &'static str,
    status: CheckStatus,
    message: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    details: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum CheckStatus {
    Ok,
    Warn,
    Missing,
    Failed,
    Skipped,
}

pub fn run(root: &Path, format: OutputFormat) -> Result<()> {
    let report = build_report(root);
    match format {
        OutputFormat::Human => print_human(&report),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }
    Ok(())
}

fn build_report(root: &Path) -> DoctorReport {
    let checks = vec![
        command_check(
            "rustc",
            "Rust compiler",
            "rustc",
            &["--version"],
            root,
            CheckStatus::Failed,
        ),
        command_check(
            "cargo",
            "Cargo",
            "cargo",
            &["--version"],
            root,
            CheckStatus::Failed,
        ),
        command_check(
            "rustc-nightly",
            "Nightly Rust toolchain",
            "rustc",
            &["+nightly", "--version"],
            root,
            CheckStatus::Warn,
        ),
        command_check(
            "cargo-fuzz",
            "cargo-fuzz",
            "cargo",
            &["fuzz", "--version"],
            root,
            CheckStatus::Warn,
        ),
        command_check(
            "cargo-mutants",
            "cargo-mutants",
            "cargo",
            &["mutants", "--version"],
            root,
            CheckStatus::Warn,
        ),
        command_check(
            "cargo-llvm-cov",
            "cargo-llvm-cov",
            "cargo",
            &["llvm-cov", "--version"],
            root,
            CheckStatus::Warn,
        ),
        command_check(
            "cargo-deny",
            "cargo-deny",
            "cargo",
            &["deny", "--version"],
            root,
            CheckStatus::Warn,
        ),
        command_check(
            "typos",
            "typos",
            "typos",
            &["--version"],
            root,
            CheckStatus::Warn,
        ),
        command_check(
            "gh",
            "GitHub CLI",
            "gh",
            &["--version"],
            root,
            CheckStatus::Warn,
        ),
        asan_runtime_check(),
        crates_io_auth_check(),
        dirty_tree_check(root),
        badge_drift_check(root),
    ];

    DoctorReport {
        status: overall_status(&checks),
        checks,
    }
}

fn print_human(report: &DoctorReport) {
    println!("doctor: {}", report.status);
    println!();
    println!("{:<24} {:<8} Message", "Check", "Status");
    println!("{:-<24} {:-<8} {:-<1}", "", "", "");
    for check in &report.checks {
        println!(
            "{:<24} {:<8} {}",
            check.id,
            check.status.as_str(),
            check.message
        );
    }
}

fn overall_status(checks: &[DoctorCheck]) -> &'static str {
    if checks
        .iter()
        .any(|check| check.status == CheckStatus::Failed)
    {
        "failed"
    } else if checks
        .iter()
        .any(|check| matches!(check.status, CheckStatus::Warn | CheckStatus::Missing))
    {
        "warn"
    } else {
        "ok"
    }
}

fn command_check(
    id: &'static str,
    label: &'static str,
    program: &str,
    args: &[&str],
    root: &Path,
    failure_status: CheckStatus,
) -> DoctorCheck {
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    match command.output() {
        Ok(output) if output.status.success() => {
            let mut details = BTreeMap::new();
            let version = first_output_line(&output.stdout, &output.stderr);
            if !version.is_empty() {
                details.insert("version".to_string(), version.clone());
            }
            DoctorCheck {
                id,
                label,
                status: CheckStatus::Ok,
                message: version_or("available", &version),
                details,
            }
        }
        Ok(output) => {
            let summary = first_output_line(&output.stderr, &output.stdout);
            DoctorCheck {
                id,
                label,
                status: failure_status,
                message: version_or("command returned a non-zero status", &summary),
                details: BTreeMap::new(),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => DoctorCheck {
            id,
            label,
            status: CheckStatus::Missing,
            message: format!("{program} not found on PATH"),
            details: BTreeMap::new(),
        },
        Err(error) => DoctorCheck {
            id,
            label,
            status: failure_status,
            message: error.to_string(),
            details: BTreeMap::new(),
        },
    }
}

fn first_output_line(primary: &[u8], secondary: &[u8]) -> String {
    let primary = String::from_utf8_lossy(primary);
    let secondary = String::from_utf8_lossy(secondary);
    primary
        .lines()
        .chain(secondary.lines())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("")
        .to_string()
}

fn version_or(default: &str, value: &str) -> String {
    if value.is_empty() {
        default.to_string()
    } else {
        value.to_string()
    }
}

fn asan_runtime_check() -> DoctorCheck {
    const DLL: &str = "clang_rt.asan_dynamic-x86_64.dll";
    if !cfg!(windows) {
        return DoctorCheck {
            id: "asan-runtime",
            label: "Windows ASAN runtime",
            status: CheckStatus::Skipped,
            message: "not required on this host".to_string(),
            details: BTreeMap::new(),
        };
    }

    match find_in_path(DLL) {
        Some(path) => {
            let mut details = BTreeMap::new();
            details.insert("path".to_string(), path.display().to_string());
            DoctorCheck {
                id: "asan-runtime",
                label: "Windows ASAN runtime",
                status: CheckStatus::Ok,
                message: format!("found {DLL}"),
                details,
            }
        }
        None => DoctorCheck {
            id: "asan-runtime",
            label: "Windows ASAN runtime",
            status: CheckStatus::Warn,
            message: format!(
                "{DLL} not found on PATH; fuzz targets may fail with STATUS_DLL_NOT_FOUND"
            ),
            details: BTreeMap::new(),
        },
    }
}

fn crates_io_auth_check() -> DoctorCheck {
    if env::var_os("CARGO_REGISTRY_TOKEN").is_some() {
        return DoctorCheck {
            id: "crates-io-auth",
            label: "crates.io auth",
            status: CheckStatus::Ok,
            message: "CARGO_REGISTRY_TOKEN is present".to_string(),
            details: BTreeMap::new(),
        };
    }

    let credentials = cargo_credentials_paths();
    if let Some(path) = credentials.iter().find(|path| path.exists()) {
        let mut details = BTreeMap::new();
        details.insert("path".to_string(), path.display().to_string());
        return DoctorCheck {
            id: "crates-io-auth",
            label: "crates.io auth",
            status: CheckStatus::Ok,
            message: "cargo credentials file is present".to_string(),
            details,
        };
    }

    DoctorCheck {
        id: "crates-io-auth",
        label: "crates.io auth",
        status: CheckStatus::Warn,
        message: "no crates.io token or cargo credentials file found".to_string(),
        details: BTreeMap::new(),
    }
}

fn dirty_tree_check(root: &Path) -> DoctorCheck {
    let output = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=normal"])
        .current_dir(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    match output {
        Ok(output) if output.status.success() => {
            let status = String::from_utf8_lossy(&output.stdout);
            let changed = status.lines().count();
            if changed == 0 {
                DoctorCheck {
                    id: "git-worktree",
                    label: "Git worktree",
                    status: CheckStatus::Ok,
                    message: "clean".to_string(),
                    details: BTreeMap::new(),
                }
            } else {
                let mut details = BTreeMap::new();
                if let Some(first) = status.lines().next() {
                    details.insert("first_entry".to_string(), first.to_string());
                }
                DoctorCheck {
                    id: "git-worktree",
                    label: "Git worktree",
                    status: CheckStatus::Warn,
                    message: format!("{changed} changed path(s)"),
                    details,
                }
            }
        }
        Ok(output) => DoctorCheck {
            id: "git-worktree",
            label: "Git worktree",
            status: CheckStatus::Warn,
            message: first_output_line(&output.stderr, &output.stdout),
            details: BTreeMap::new(),
        },
        Err(error) => DoctorCheck {
            id: "git-worktree",
            label: "Git worktree",
            status: CheckStatus::Warn,
            message: error.to_string(),
            details: BTreeMap::new(),
        },
    }
}

fn badge_drift_check(root: &Path) -> DoctorCheck {
    let output = Command::new("cargo")
        .args(["xtask", "badges", "--check"])
        .current_dir(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    match output {
        Ok(output) if output.status.success() => DoctorCheck {
            id: "badge-drift",
            label: "Generated badge endpoints",
            status: CheckStatus::Ok,
            message: "committed endpoints are current".to_string(),
            details: BTreeMap::new(),
        },
        Ok(output) => DoctorCheck {
            id: "badge-drift",
            label: "Generated badge endpoints",
            status: CheckStatus::Warn,
            message: version_or(
                "badge endpoint drift or proof dependency failure",
                &first_output_line(&output.stderr, &output.stdout),
            ),
            details: BTreeMap::new(),
        },
        Err(error) => DoctorCheck {
            id: "badge-drift",
            label: "Generated badge endpoints",
            status: CheckStatus::Warn,
            message: error.to_string(),
            details: BTreeMap::new(),
        },
    }
}

fn find_in_path(file_name: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|dir| dir.join(file_name))
            .find(|candidate| candidate.exists())
    })
}

fn cargo_credentials_paths() -> Vec<PathBuf> {
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|home| home.join(".cargo")));
    cargo_home
        .into_iter()
        .flat_map(|home| [home.join("credentials.toml"), home.join("credentials")])
        .collect()
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("USERPROFILE")
        .or_else(|| env::var_os("HOME"))
        .map(PathBuf::from)
}

impl CheckStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Missing => "missing",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(status: CheckStatus) -> DoctorCheck {
        DoctorCheck {
            id: "test",
            label: "test",
            status,
            message: String::new(),
            details: BTreeMap::new(),
        }
    }

    #[test]
    fn doctor_overall_status_prefers_failed() {
        assert_eq!(overall_status(&[check(CheckStatus::Ok)]), "ok");
        assert_eq!(overall_status(&[check(CheckStatus::Warn)]), "warn");
        assert_eq!(
            overall_status(&[check(CheckStatus::Warn), check(CheckStatus::Failed)]),
            "failed"
        );
    }

    #[test]
    fn doctor_first_output_line_uses_stderr_fallback() {
        assert_eq!(first_output_line(b"", b"\nsecond\n"), "second");
        assert_eq!(first_output_line(b" first\n", b"second\n"), "first");
    }

    #[test]
    fn doctor_cargo_credentials_paths_include_toml_and_legacy_names() {
        let paths = cargo_credentials_paths();
        assert!(paths.iter().any(|path| path.ends_with("credentials.toml")));
        assert!(paths.iter().any(|path| path.ends_with("credentials")));
    }
}
