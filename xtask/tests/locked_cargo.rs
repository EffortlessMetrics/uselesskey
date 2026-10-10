//! Execute the compiled CLI against an argument recorder. Product compilation
//! is intentionally substituted; Cargo's native lock behavior has separate tests.
#![cfg(unix)]

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};

fn invoke(arguments: &[&str], cargo_status: i32) -> io::Result<(Output, Vec<Vec<String>>)> {
    let directory = tempfile::tempdir()?;
    let bin = directory.path().join("bin");
    fs::create_dir(&bin)?;
    let cargo = bin.join("cargo");
    fs::write(
        &cargo,
        "#!/bin/sh\nprintf '%s\\0' \"$@\" >> \"$ARGUMENT_LOG\"\nprintf '\\n' >> \"$ARGUMENT_LOG\"\nexit \"$RECORDER_STATUS\"\n",
    )?;
    fs::set_permissions(cargo, fs::Permissions::from_mode(0o700))?;
    let log = directory.path().join("arguments.log");
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(arguments)
        .current_dir(directory.path())
        .env("PATH", &bin)
        .env("ARGUMENT_LOG", &log)
        .env("RECORDER_STATUS", cargo_status.to_string())
        .output()?;
    let calls = if log.exists() {
        fs::read_to_string(log)?
            .lines()
            .map(|line| {
                line.trim_end_matches('\0')
                    .split('\0')
                    .map(str::to_string)
                    .collect()
            })
            .collect()
    } else {
        Vec::new()
    };
    Ok((output, calls))
}

#[test]
fn compiled_cli_locks_clippy_and_keeps_rustc_arguments_after_the_separator() -> io::Result<()> {
    for arguments in [["--locked", "clippy"], ["clippy", "--locked"]] {
        let (output, calls) = invoke(&arguments, 0)?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            calls,
            [[
                "clippy",
                "--locked",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings"
            ]]
        );
    }
    Ok(())
}

#[test]
fn compiled_cli_locks_workspace_tests_and_bdd() -> io::Result<()> {
    for subcommand in ["test", "bdd"] {
        let (output, calls) = invoke(&["--locked", subcommand], 0)?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0][..2], ["test", "--locked"]);
    }
    Ok(())
}

#[test]
fn compiled_feature_matrix_locks_every_cargo_check() -> io::Result<()> {
    let (output, calls) = invoke(&["--locked", "feature-matrix"], 0)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(calls.len() > 1);
    for call in calls {
        assert_eq!(call[..4], ["check", "--locked", "-p", "uselesskey"]);
    }
    Ok(())
}

#[test]
fn compiled_deny_probes_then_passes_its_native_locked_option() -> io::Result<()> {
    let (output, calls) = invoke(&["--locked", "deny"], 0)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(calls[0], ["deny", "--version"]);
    assert_eq!(calls[1], ["deny", "--locked", "check"]);
    Ok(())
}

#[test]
fn compiled_cli_propagates_a_failed_cargo_process() -> io::Result<()> {
    let (output, calls) = invoke(&["--locked", "clippy"], 17)?;
    assert!(!output.status.success());
    assert_eq!(calls.len(), 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("command failed"));
    Ok(())
}

#[test]
fn standalone_cli_does_not_enable_proof_mode_implicitly() -> io::Result<()> {
    let (output, calls) = invoke(&["clippy"], 0)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!calls[0].iter().any(|argument| argument == "--locked"));
    Ok(())
}
