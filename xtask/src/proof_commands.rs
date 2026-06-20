use std::path::Path;

use clap::Parser;

pub(crate) fn validate_repo_cargo_command(
    root: &Path,
    source: &str,
    owner: &str,
    command: &str,
    command_kind: &str,
    errors: &mut Vec<String>,
) {
    let tokens = command.split_whitespace().collect::<Vec<_>>();
    if tokens.is_empty() {
        return;
    }

    if tokens.first() != Some(&"cargo") {
        errors.push(format!(
            "{source}: `{owner}` uses unsupported {command_kind} command `{command}`; expected `cargo xtask ...` or `cargo test -p <package> ...`"
        ));
        return;
    }

    match tokens.get(1).copied() {
        Some("xtask") => {
            validate_xtask_command(source, owner, command, command_kind, &tokens, errors)
        }
        Some("test") => {
            validate_cargo_test_command(root, source, owner, command, command_kind, &tokens, errors)
        }
        _ => errors.push(format!(
            "{source}: `{owner}` uses unsupported cargo {command_kind} command `{command}`; expected `cargo xtask ...` or `cargo test -p <package> ...`"
        )),
    }
}

fn validate_xtask_command(
    source: &str,
    owner: &str,
    command: &str,
    command_kind: &str,
    tokens: &[&str],
    errors: &mut Vec<String>,
) {
    let xtask_args = std::iter::once("xtask")
        .chain(tokens.iter().skip(2).copied())
        .collect::<Vec<_>>();
    if crate::Cli::try_parse_from(xtask_args).is_err() {
        errors.push(format!(
            "{source}: `{owner}` references unknown xtask {command_kind} command `{command}`"
        ));
    }
}

fn validate_cargo_test_command(
    root: &Path,
    source: &str,
    owner: &str,
    command: &str,
    command_kind: &str,
    tokens: &[&str],
    errors: &mut Vec<String>,
) {
    let Some(package) = cargo_test_package(tokens) else {
        errors.push(format!(
            "{source}: `{owner}` uses cargo test {command_kind} command `{command}` without `-p <package>`"
        ));
        return;
    };

    if !cargo_package_exists(root, package) {
        errors.push(format!(
            "{source}: `{owner}` references unknown cargo test package `{package}` in {command_kind} command `{command}`"
        ));
    }
}

fn cargo_test_package<'a>(tokens: &'a [&'a str]) -> Option<&'a str> {
    let mut idx = 2;
    while idx < tokens.len() {
        let token = tokens[idx];
        match token {
            "-p" | "--package" => return tokens.get(idx + 1).copied(),
            _ => {
                if let Some(package) = token.strip_prefix("--package=") {
                    return Some(package);
                }
                if let Some(package) = token
                    .strip_prefix("-p")
                    .filter(|package| !package.is_empty())
                {
                    return Some(package);
                }
            }
        }
        idx += 1;
    }
    None
}

pub(crate) fn cargo_package_exists(root: &Path, package: &str) -> bool {
    [
        root.join("crates").join(package).join("Cargo.toml"),
        root.join(package).join("Cargo.toml"),
    ]
    .iter()
    .any(|path| path.exists())
}
