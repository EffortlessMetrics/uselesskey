use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use regex::Regex;

const COMMAND_LEDGER_MD: &str = "docs/release/v0.10-command-ledger.md";
const SOURCE_LEDGER_SECTION: &str = "## Command Matrix";
const COMMAND_STATUS_VALUES: &[&str] = &[
    "stable",
    "stabilizing",
    "release-time only",
    "blocked",
    "deferred",
];
const RELEASE_VERSION: &str = "0.10.0";

const HEADER_COMMAND: &str = "command / snippet";
const HEADER_SOURCE_DOC: &str = "source doc";
const HEADER_PROOF_COMMAND: &str = "proof command";
const HEADER_BOUNDARY: &str = "does-not-prove boundary";
const HEADER_SUPPORT_STATUS: &str = "support status";
const HEADER_RELEASE_STATE: &str = "release state";

#[derive(Debug)]
struct CommandLedgerRow {
    line: usize,
    command: String,
    source_docs: Vec<String>,
    proof_commands: Vec<String>,
    boundary: String,
    support_status: String,
    release_state: String,
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let errors = validate(root)?;
    if errors.is_empty() {
        let rows = read_rows(root)?;
        println!(
            "adoption-command-ledger: {} command rows; command-ledger ownership validated",
            rows.len()
        );
        Ok(())
    } else {
        for error in &errors {
            eprintln!("check-adoption-command-ledger: {error}");
        }
        bail!(
            "check-adoption-command-ledger: {} validation error(s)",
            errors.len()
        );
    }
}

fn validate(root: &Path) -> Result<Vec<String>> {
    let rows = read_rows(root)?;
    if rows.is_empty() {
        return Ok(vec![format!(
            "{COMMAND_LEDGER_MD}: no parseable command-ledger rows found"
        )]);
    }

    let mut errors = Vec::new();
    let source_path = root.join(COMMAND_LEDGER_MD);
    let source_dir = source_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing source path parent for {}", COMMAND_LEDGER_MD))?;

    let mut seen_commands = HashMap::<String, usize>::new();

    for row in &rows {
        if row.command.trim().is_empty() {
            errors.push(format!(
                "{COMMAND_LEDGER_MD}:{} command / snippet is empty",
                row.line
            ));
        }

        let support_status = row.support_status.trim().to_ascii_lowercase();
        if support_status.is_empty() {
            errors.push(format!(
                "{COMMAND_LEDGER_MD}:{} row `{}` missing support status",
                row.line, row.command
            ));
        } else if !COMMAND_STATUS_VALUES.contains(&support_status.as_str()) {
            errors.push(format!(
                "{COMMAND_LEDGER_MD}:{} row `{}` has unsupported support status `{}`",
                row.line, row.command, row.support_status
            ));
        }

        let release_state = row.release_state.trim().to_ascii_lowercase();
        if release_state.is_empty() {
            errors.push(format!(
                "{COMMAND_LEDGER_MD}:{} row `{}` missing release state",
                row.line, row.command
            ));
        } else if !COMMAND_STATUS_VALUES.contains(&release_state.as_str()) {
            errors.push(format!(
                "{COMMAND_LEDGER_MD}:{} row `{}` has unsupported release state `{}`",
                row.line, row.command, row.release_state
            ));
        }

        if row.boundary.trim().is_empty() {
            errors.push(format!(
                "{COMMAND_LEDGER_MD}:{} row `{}` has empty boundary",
                row.line, row.command
            ));
        }

        if row.proof_commands.is_empty() {
            errors.push(format!(
                "{COMMAND_LEDGER_MD}:{} row `{}` has no proof commands",
                row.line, row.command
            ));
        } else {
            for proof in &row.proof_commands {
                validate_proof_command(root, row, proof, &mut errors);
            }
        }

        if !row
            .source_docs
            .iter()
            .any(|source| !source.trim().eq_ignore_ascii_case("n/a"))
        {
            errors.push(format!(
                "{COMMAND_LEDGER_MD}:{} row `{}` has no source doc path",
                row.line, row.command
            ));
        }

        let mut command_found = false;
        for source in &row.source_docs {
            let source = source.trim();
            if source.is_empty() || source.eq_ignore_ascii_case("n/a") {
                continue;
            }
            let path_rel = source.split('#').next().unwrap_or_default().trim();
            if path_rel.is_empty() || is_external_path(path_rel) {
                continue;
            }

            let target = source_dir.join(path_rel);
            if !target.exists() {
                errors.push(format!(
                    "{COMMAND_LEDGER_MD}:{} row `{}` references missing source doc `{}`",
                    row.line, row.command, source
                ));
            } else if file_contains_command(&target, &row.command) {
                command_found = true;
            }
        }

        if !command_found {
            errors.push(format!(
                "{COMMAND_LEDGER_MD}:{} row `{}` does not appear in any source docs",
                row.line, row.command
            ));
        }

        if has_public_release_candidate_before_publication(row) {
            errors.push(format!(
                "{COMMAND_LEDGER_MD}:{} row `{}` claims `0.10.0` as public before release",
                row.line, row.command
            ));
        }

        let canonical = canonicalize_command(&row.command);
        if let Some(previous) = seen_commands.get(&canonical) {
            errors.push(format!(
                "{COMMAND_LEDGER_MD}:{} row `{}` duplicates command ownership from line {}",
                row.line, row.command, previous
            ));
        } else {
            seen_commands.insert(canonical, row.line);
        }
    }

    Ok(errors)
}

fn has_public_release_candidate_before_publication(row: &CommandLedgerRow) -> bool {
    let command_has_release_candidate = row.command.contains(RELEASE_VERSION);
    let proof_has_release_candidate = row
        .proof_commands
        .iter()
        .any(|proof| proof.contains(RELEASE_VERSION));

    if !(command_has_release_candidate || proof_has_release_candidate) {
        return false;
    }

    !matches!(
        row.release_state.trim().to_ascii_lowercase().as_str(),
        "release-time only"
    )
}

fn validate_proof_command(
    root: &Path,
    row: &CommandLedgerRow,
    proof: &str,
    errors: &mut Vec<String>,
) {
    let proof = proof.trim();
    if proof.is_empty() {
        errors.push(format!(
            "{COMMAND_LEDGER_MD}:{} row `{}` has an empty proof command",
            row.line, row.command
        ));
        return;
    }

    if proof.starts_with("cargo ") {
        crate::proof_commands::validate_repo_cargo_command(
            root,
            COMMAND_LEDGER_MD,
            &row.command,
            proof,
            "proof",
            errors,
        );
        return;
    }

    let tokens = proof
        .split_whitespace()
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        errors.push(format!(
            "{COMMAND_LEDGER_MD}:{} row `{}` has an empty proof command",
            row.line, row.command
        ));
        return;
    }

    let script_token = if tokens[0] == "bash" || tokens[0] == "sh" {
        tokens.get(1).copied().unwrap_or_default()
    } else {
        tokens[0]
    };
    if script_token.is_empty() {
        errors.push(format!(
            "{COMMAND_LEDGER_MD}:{} row `{}` proof command `{}` is missing a script path",
            row.line, row.command, proof
        ));
        return;
    }

    if tokens.iter().any(|token| token.ends_with(".sh")) || script_token.ends_with(".sh") {
        let script_path = PathBuf::from(script_token);
        if !root.join(script_path).exists() {
            errors.push(format!(
                "{COMMAND_LEDGER_MD}:{} row `{}` proof command `{}` references missing script `{}`",
                row.line, row.command, proof, script_token
            ));
        }
        return;
    }

    errors.push(format!(
        "{COMMAND_LEDGER_MD}:{} row `{}` proof command `{}` is not a supported proof form",
        row.line, row.command, proof
    ));
}

fn read_rows(root: &Path) -> Result<Vec<CommandLedgerRow>> {
    let path = root.join(COMMAND_LEDGER_MD);
    let markdown = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let mut rows = Vec::new();
    let mut in_matrix = false;
    let mut columns: Option<HashMap<String, usize>> = None;

    for (idx, line) in markdown.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed == SOURCE_LEDGER_SECTION {
            in_matrix = true;
            continue;
        }
        if in_matrix && trimmed.starts_with("## ") {
            break;
        }
        if !in_matrix || !trimmed.starts_with('|') {
            continue;
        }

        let cells = split_table_row(line);
        if cells.is_empty() {
            continue;
        }

        if is_table_separator_row(&cells) {
            continue;
        }

        if columns.is_none() {
            let mut header_map = HashMap::new();
            for (col_idx, cell) in cells.iter().enumerate() {
                header_map.insert(normalize_header_name(cell), col_idx);
            }

            let required = [
                HEADER_COMMAND,
                HEADER_SOURCE_DOC,
                HEADER_PROOF_COMMAND,
                HEADER_BOUNDARY,
                HEADER_SUPPORT_STATUS,
                HEADER_RELEASE_STATE,
            ];

            if required
                .iter()
                .all(|required_name| header_map.contains_key(&normalize_header_name(required_name)))
            {
                columns = Some(header_map);
            }
            continue;
        }

        let header = columns.as_ref().expect("headers found");
        let get = |name: &str| -> String {
            let idx = *header
                .get(&normalize_header_name(name))
                .unwrap_or(&usize::MAX);
            if idx == usize::MAX {
                String::new()
            } else {
                cells.get(idx).cloned().unwrap_or_default()
            }
        };

        rows.push(CommandLedgerRow {
            line: idx + 1,
            command: first_code_or_trimmed(&get(HEADER_COMMAND)),
            source_docs: extract_markdown_or_code_paths(&get(HEADER_SOURCE_DOC)),
            proof_commands: extract_code_segments(&get(HEADER_PROOF_COMMAND)),
            boundary: get(HEADER_BOUNDARY),
            support_status: get(HEADER_SUPPORT_STATUS),
            release_state: get(HEADER_RELEASE_STATE),
        });
    }

    Ok(rows)
}

fn is_table_separator_row(cells: &[String]) -> bool {
    cells
        .iter()
        .all(|cell| !cell.is_empty() && cell.chars().all(|ch| ch == '-' || ch == ':'))
}

fn split_table_row(line: &str) -> Vec<String> {
    line.trim_matches('|')
        .split('|')
        .map(str::trim)
        .map(|cell| cell.to_string())
        .collect()
}

fn normalize_header_name(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn first_code_or_trimmed(value: &str) -> String {
    if let Some(first) = extract_code_segments(value).into_iter().next() {
        first
    } else {
        strip_inline_code(value)
    }
}

fn strip_inline_code(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('`') && trimmed.ends_with('`') {
        trimmed.trim_matches('`').to_string()
    } else {
        trimmed.to_string()
    }
}

fn extract_code_segments(value: &str) -> Vec<String> {
    let mut values = Vec::new();
    let pattern = r"`([^`]*)`";
    let re = Regex::new(pattern).expect("valid inline-code regex");
    for captures in re.captures_iter(value) {
        let value = captures
            .get(1)
            .map(|m| m.as_str())
            .unwrap_or_default()
            .trim();
        if !value.is_empty() {
            values.push(value.to_string());
        }
    }

    if !values.is_empty() {
        return values;
    }

    value
        .split(';')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn extract_markdown_or_code_paths(value: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let re = Regex::new(r"\[[^\]]+\]\(([^)]+)\)").expect("valid markdown link regex");
    for capture in re.captures_iter(value) {
        let path = capture
            .get(1)
            .map(|m| m.as_str())
            .unwrap_or_default()
            .trim();
        let path = path.split('#').next().unwrap_or_default().trim();
        if path.is_empty() {
            continue;
        }
        let path = path.to_string();
        if !paths.contains(&path) {
            paths.push(path);
        }
    }

    if !paths.is_empty() {
        return paths;
    }

    for path in value.split(';').map(str::trim) {
        let path = path.trim_matches('`');
        let path = path.split('#').next().unwrap_or_default().trim();
        if path.is_empty() {
            continue;
        }
        let path = path.to_string();
        if !paths.contains(&path) {
            paths.push(path);
        }
    }

    paths
}

fn canonicalize_command(command: &str) -> String {
    command
        .split_whitespace()
        .map(|token| {
            if token.starts_with('<') && token.ends_with('>') {
                "<arg>"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn file_contains_command(target: &Path, command: &str) -> bool {
    let Ok(raw_content) = fs::read_to_string(target) else {
        return false;
    };
    let command_text = strip_inline_code(command);
    if command_text.is_empty() {
        return false;
    }
    let cleaned_content = raw_content
        .replace("\\\r\n", " ")
        .replace("\\\n", " ")
        .replace("\\\r", " ")
        .replace(['`', '\n', '\r', '\\'], " ");
    if command_matches(&cleaned_content, &command_text) {
        return true;
    }
    let normalized = canonicalize_command(&command_text);
    command_matches(&cleaned_content, &normalized)
}

fn is_external_path(path: &str) -> bool {
    path.starts_with("http://")
        || path.starts_with("https://")
        || path.starts_with('#')
        || path.starts_with("mailto:")
}

fn command_matches(content: &str, command: &str) -> bool {
    let tokenized = command_tokens(command);
    if tokenized.is_empty() {
        return false;
    }

    let mut pattern = String::new();
    pattern.push_str(r"(?i)(?:^|[^\w])");
    for (idx, token) in tokenized.iter().enumerate() {
        if idx > 0 {
            pattern.push_str(r"\s+");
        }
        pattern.push_str(token);
    }
    pattern.push_str(r"(?:$|[^\w])");

    let re = match Regex::new(&pattern) {
        Ok(regex) => regex,
        Err(_) => return false,
    };
    re.is_match(content)
}

fn command_tokens(command: &str) -> Vec<String> {
    let placeholder = Regex::new(r"<[^>]+>").expect("valid placeholder regex");
    let mut tokens = Vec::new();

    for token in command.split_whitespace() {
        if token.is_empty() {
            continue;
        }
        let mut fragment = String::new();
        let mut last = 0usize;
        for capture in placeholder.find_iter(token) {
            let start = capture.start();
            let end = capture.end();
            if start > last {
                fragment.push_str(&regex::escape(&token[last..start]));
            }
            fragment.push_str(r"\S+");
            last = end;
        }

        if last < token.len() {
            fragment.push_str(&regex::escape(&token[last..]));
        }

        if fragment.trim().is_empty() {
            fragment.push_str(r"\S+");
        }
        tokens.push(fragment);
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use tempfile::tempdir;

    #[test]
    fn rejects_unknown_support_status() -> Result<()> {
        let dir = tempdir()?;
        let ledger_path = dir.path().join(COMMAND_LEDGER_MD);
        fs::create_dir_all(
            ledger_path
                .parent()
                .ok_or_else(|| anyhow::anyhow!("missing ledger parent"))?,
        )?;
        fs::write(
            ledger_path,
            r#"
## Command Matrix

| Command / Snippet | Source doc | Expected result | Proof command | Failure behavior | Does-not-prove boundary | Support status | Release state |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `uselesskey bundle --profile <profile>` | [`README.md`](../../README.md) | writes a bundle | `cargo xtask check-audit-receipts` | returns bundle | command is only smoke path | Experimental | Release-time only |
"#,
        )?;
        let doc_root = dir.path().to_path_buf();
        fs::write(doc_root.join("README.md"), "placeholder")?;
        fs::write(
            doc_root.join(".gitkeep"),
            "placeholder to keep directory layout",
        )?;
        let errors = validate(&doc_root)?;
        assert!(
            errors
                .iter()
                .any(|error| error.contains("unsupported support status")),
            "expected unknown support status error"
        );
        Ok(())
    }

    #[test]
    fn catches_0_10_public_claim_before_release() -> Result<()> {
        let dir = tempdir()?;
        let doc_root = dir.path().to_path_buf();
        let ledger_path = doc_root.join(COMMAND_LEDGER_MD);
        fs::create_dir_all(
            ledger_path
                .parent()
                .ok_or_else(|| anyhow::anyhow!("missing ledger parent"))?,
        )?;
        fs::write(
            ledger_path,
            r#"
## Command Matrix

| Command / Snippet | Source doc | Expected result | Proof command | Failure behavior | Does-not-prove boundary | Support status | Release state |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `cargo install uselesskey-cli --version 0.10.0 --locked` | [`README.md`](../../README.md) | writes command | `cargo xtask check-audit-receipts` | command fails if unavailable | placeholder | Stable | Stabilizing |
"#,
        )?;
        fs::write(doc_root.join("README.md"), "# test")?;
        let errors = validate(&doc_root)?;
        assert!(
            errors
                .iter()
                .any(|error| error.contains("claims `0.10.0` as public before release")),
            "expected guarded 0.10.0 release-state error"
        );
        Ok(())
    }

    #[test]
    fn duplicate_commands_are_rejected() -> Result<()> {
        let dir = tempdir()?;
        let doc_root = dir.path().to_path_buf();
        let ledger_path = doc_root.join(COMMAND_LEDGER_MD);
        fs::create_dir_all(
            ledger_path
                .parent()
                .ok_or_else(|| anyhow::anyhow!("missing ledger parent"))?,
        )?;
        fs::write(
            ledger_path,
            r#"
## Command Matrix

| Command / Snippet | Source doc | Expected result | Proof command | Failure behavior | Does-not-prove boundary | Support status | Release state |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `uselesskey doctor --format json` | [`README.md`](../../README.md) | command works | `cargo xtask check-file-policy` | fail if missing | docs claim only | Stable | Release-time only |
| `uselesskey doctor --format json` | [`README.md`](../../README.md) | command duplicates | `cargo xtask check-file-policy` | fail if missing | docs claim only | Stable | Release-time only |
"#,
        )?;
        fs::write(
            doc_root.join("README.md"),
            "uselesskey doctor --format json\n",
        )?;
        let errors = validate(&doc_root)?;
        assert!(
            errors
                .iter()
                .any(|error| error.contains("duplicates command ownership")),
            "expected duplicate command ownership error"
        );
        Ok(())
    }

    #[test]
    fn command_presence_accepts_placeholder_values() -> Result<()> {
        let dir = tempdir()?;
        let doc = dir.path().join("docs.md");
        fs::write(
            &doc,
            "uselesskey audit-bundle target/uselesskey-webhook --ci --expect-profile webhook --policy strict --out target/uselesskey-webhook-audit",
        )?;
        let command = "uselesskey audit-bundle target/uselesskey-<profile> --ci --expect-profile <profile> --policy strict --out target/uselesskey-<profile>-audit";
        assert!(file_contains_command(&doc, command));
        Ok(())
    }

    #[test]
    fn command_presence_accepts_wrapped_command_lines() -> Result<()> {
        let dir = tempdir()?;
        let doc = dir.path().join("docs.md");
        fs::write(
            &doc,
            "cargo xtask external-adoption-smoke \\\r\n  --path . \\\r\n  --format json",
        )?;
        let command = "cargo xtask external-adoption-smoke --path . --format json";
        assert!(file_contains_command(&doc, command));
        Ok(())
    }

    #[test]
    fn command_presence_accepts_inline_code_commands() -> Result<()> {
        let dir = tempdir()?;
        let doc = dir.path().join("docs.md");
        fs::write(
            &doc,
            "Run `cargo xtask check-audit-receipts` in a clean workspace.",
        )?;
        assert!(file_contains_command(
            &doc,
            "cargo xtask check-audit-receipts"
        ));
        Ok(())
    }
}
