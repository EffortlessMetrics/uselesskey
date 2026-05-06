use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::NaiveDate;
use toml::Value;

const POLICY_PATH: &str = "policy/clippy-lints.toml";
const DEBT_PATH: &str = "policy/clippy-debt.toml";
const CLIPPY_CONFIG_PATH: &str = "clippy.toml";
const TODAY: &str = "2026-05-06";
const OUTER_ALLOW_ATTR: &str = concat!("#", "[allow(");
const INNER_ALLOW_ATTR: &str = concat!("#!", "[allow(");
const OUTER_EXPECT_ATTR: &str = concat!("#", "[expect(");
const INNER_EXPECT_ATTR: &str = concat!("#!", "[expect(");

pub(crate) fn check_lint_policy_cmd() -> Result<()> {
    let root = Path::new("Cargo.toml");
    let root_toml = read_toml(root)?;
    let policy_toml = read_toml(Path::new(POLICY_PATH))?;
    let debt_toml = read_toml(Path::new(DEBT_PATH))?;

    let mut errors = Vec::new();

    check_msrv(&root_toml, &policy_toml, &mut errors);
    check_workspace_lints(&root_toml, &policy_toml, &mut errors);
    check_member_inheritance(&root_toml, &mut errors);
    check_clippy_config(&mut errors);
    check_debt(&debt_toml, &mut errors);
    check_suppressions(&debt_toml, &mut errors)?;

    if !errors.is_empty() {
        bail!("lint policy check failed:\n{}", errors.join("\n"));
    }

    println!("lint policy check passed");
    Ok(())
}

fn read_toml(path: &Path) -> Result<Value> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    toml::from_str::<Value>(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

fn check_msrv(root: &Value, policy: &Value, errors: &mut Vec<String>) {
    let root_msrv = root
        .get("workspace")
        .and_then(|workspace| workspace.get("package"))
        .and_then(|package| package.get("rust-version"))
        .and_then(Value::as_str);
    let policy_msrv = policy.get("msrv").and_then(Value::as_str);
    if root_msrv != policy_msrv {
        errors.push(format!(
            "workspace.package.rust-version ({root_msrv:?}) must match {POLICY_PATH} msrv ({policy_msrv:?})"
        ));
    }
}

fn check_workspace_lints(root: &Value, policy: &Value, errors: &mut Vec<String>) {
    let Some(workspace_lints) = root
        .get("workspace")
        .and_then(|workspace| workspace.get("lints"))
        .and_then(Value::as_table)
    else {
        errors.push("root Cargo.toml must define [workspace.lints]".to_string());
        return;
    };

    if !workspace_lints.contains_key("rust") || !workspace_lints.contains_key("clippy") {
        errors.push(
            "root Cargo.toml must define both [workspace.lints.rust] and [workspace.lints.clippy]"
                .to_string(),
        );
    }

    let clippy_lints = workspace_lints
        .get("clippy")
        .and_then(Value::as_table)
        .cloned()
        .unwrap_or_default();
    let active = policy
        .get("lint")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|lint| lint.get("status").and_then(Value::as_str) == Some("active"));

    for lint in active {
        let Some(name) = lint.get("name").and_then(Value::as_str) else {
            errors.push("active lint entry missing name".to_string());
            continue;
        };
        let Some(level) = lint.get("level").and_then(Value::as_str) else {
            errors.push(format!("active lint {name} missing level"));
            continue;
        };
        let manifest_name = name.strip_prefix("clippy::").unwrap_or(name);
        let manifest_level = clippy_lints.get(manifest_name).and_then(Value::as_str);
        if manifest_level != Some(level) {
            errors.push(format!(
                "active lint {name}={level:?} must match root Cargo.toml level ({manifest_level:?})"
            ));
        }
        if lint
            .get("reason")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            errors.push(format!("active lint {name} missing reason"));
        }
        if lint
            .get("class")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            errors.push(format!("active lint {name} missing class"));
        }
    }

    let msrv = policy
        .get("msrv")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let planned = policy
        .get("planned")
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    for lint in planned {
        let Some(name) = lint.get("name").and_then(Value::as_str) else {
            errors.push("planned lint entry missing name".to_string());
            continue;
        };
        let Some(activate_when) = lint.get("activate_when_msrv").and_then(Value::as_str) else {
            errors.push(format!("planned lint {name} missing activate_when_msrv"));
            continue;
        };
        let manifest_name = name.strip_prefix("clippy::").unwrap_or(name);
        if version_lt(msrv, activate_when) && clippy_lints.contains_key(manifest_name) {
            errors.push(format!(
                "planned lint {name} must not be active before MSRV {activate_when}"
            ));
        }
        for field in ["level", "reason"] {
            if lint
                .get(field)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                errors.push(format!("planned lint {name} missing {field}"));
            }
        }
    }
}

fn check_member_inheritance(root: &Value, errors: &mut Vec<String>) {
    let members = root
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);

    for member in members {
        let manifest_path = Path::new(member).join("Cargo.toml");
        let member_toml = match read_toml(&manifest_path) {
            Ok(value) => value,
            Err(err) => {
                errors.push(err.to_string());
                continue;
            }
        };
        let inherits = member_toml
            .get("lints")
            .and_then(|lints| lints.get("workspace"))
            .and_then(Value::as_bool)
            == Some(true);
        if !inherits {
            errors.push(format!(
                "workspace member {} must contain [lints] workspace = true",
                manifest_path.display()
            ));
        }
    }
}

fn check_clippy_config(errors: &mut Vec<String>) {
    let raw = match fs::read_to_string(CLIPPY_CONFIG_PATH) {
        Ok(raw) => raw,
        Err(err) => {
            errors.push(format!("failed to read {CLIPPY_CONFIG_PATH}: {err}"));
            return;
        }
    };
    let config = match toml::from_str::<Value>(&raw) {
        Ok(value) => value,
        Err(err) => {
            errors.push(format!("failed to parse {CLIPPY_CONFIG_PATH}: {err}"));
            return;
        }
    };
    for key in [
        "allow-unwrap-in-tests",
        "allow-expect-in-tests",
        "allow-panic-in-tests",
        "allow-indexing-slicing-in-tests",
        "allow-dbg-in-tests",
    ] {
        if config.get(key).and_then(Value::as_bool) == Some(true) {
            errors.push(format!("{CLIPPY_CONFIG_PATH} must not set {key} = true"));
        }
    }
}

fn check_debt(debt: &Value, errors: &mut Vec<String>) {
    if debt.get("schema").and_then(Value::as_integer) != Some(1) {
        errors.push(format!("{DEBT_PATH} must set schema = 1"));
    }
    let today = NaiveDate::parse_from_str(TODAY, "%Y-%m-%d").expect("valid built-in date");
    let entries = debt
        .get("debt")
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    for (idx, entry) in entries.enumerate() {
        for field in ["lint", "path", "owner", "reason", "expires"] {
            if entry
                .get(field)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                errors.push(format!("debt entry #{idx} missing {field}"));
            }
        }
        if let Some(expires) = entry.get("expires").and_then(Value::as_str) {
            match NaiveDate::parse_from_str(expires, "%Y-%m-%d") {
                Ok(date) if date < today => errors.push(format!(
                    "debt entry #{} for {:?} expired on {expires}",
                    idx,
                    entry.get("path").and_then(Value::as_str)
                )),
                Ok(_) => {}
                Err(err) => errors.push(format!(
                    "debt entry #{idx} has invalid expires date {expires:?}: {err}"
                )),
            }
        }
    }
}

fn check_suppressions(debt: &Value, errors: &mut Vec<String>) -> Result<()> {
    let allowed_paths = debt
        .get("debt")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| {
            entry.get("lint").and_then(Value::as_str) == Some("rust::allow")
                || entry.get("lint").and_then(Value::as_str) == Some("clippy::allow_attributes")
        })
        .filter_map(|entry| entry.get("path").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();

    for path in rust_files(Path::new("."))? {
        let display = normalize_path(&path);
        let raw = fs::read_to_string(&path).with_context(|| format!("failed to read {display}"))?;
        if raw.contains(OUTER_ALLOW_ATTR) || raw.contains(INNER_ALLOW_ATTR) {
            if !allowed_paths.contains(&display) {
                errors.push(format!(
                    "{display} uses an allow attribute; add expiring debt or migrate to expect with reason"
                ));
            }
        }
        for (line_no, line) in raw.lines().enumerate() {
            if (line.contains(OUTER_EXPECT_ATTR) || line.contains(INNER_EXPECT_ATTR))
                && !line.contains("reason")
            {
                errors.push(format!(
                    "{display}:{} uses an expect attribute without an inline reason",
                    line_no + 1
                ));
            }
        }
    }
    Ok(())
}

fn rust_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    visit_rust_files(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn visit_rust_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "target" || name == ".git" {
            continue;
        }
        if path.is_dir() {
            visit_rust_files(&path, files)?;
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            files.push(path);
        }
    }
    Ok(())
}

fn normalize_path(path: &Path) -> String {
    path.strip_prefix(".")
        .unwrap_or(path)
        .to_string_lossy()
        .trim_start_matches('/')
        .to_string()
}

fn version_lt(left: &str, right: &str) -> bool {
    parse_version(left) < parse_version(right)
}

fn parse_version(value: &str) -> Vec<u64> {
    value
        .split('.')
        .map(|part| part.parse::<u64>().unwrap_or(0))
        .collect()
}
