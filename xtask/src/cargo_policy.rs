//! Cargo subprocess policy for explicitly locked proof invocations.
//!
//! The outer `cargo run --locked -p xtask -- --locked ...` protects the
//! xtask build; this module protects the Cargo processes xtask starts.
//! Nested xtask invocations explicitly pass the mode again. It is not injected
//! into the environment of product programs or unit-test harnesses.
//! This is dependency-resolution policy, not a sandbox for candidate code.

use std::ffi::OsStr;
use std::io;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

static CLI_LOCKED: AtomicBool = AtomicBool::new(false);

pub(crate) fn initialize(explicit: bool) {
    CLI_LOCKED.store(explicit, Ordering::Relaxed);
}

pub(crate) fn locked() -> bool {
    CLI_LOCKED.load(Ordering::Relaxed)
}

/// Construct a Cargo command before callers append subcommand arguments.
/// Keeping `--locked` here prevents it from accidentally becoming a test,
/// rustc, or example-program argument after an existing `--` separator.
pub(crate) fn command(subcommand: &str) -> io::Result<Command> {
    command_for(subcommand, locked())
}

fn command_for(subcommand: &str, locked: bool) -> io::Result<Command> {
    let mut command = Command::new("cargo");
    if !locked {
        if subcommand == "nextest-run" {
            command.args(["nextest", "run"]);
        } else {
            command.arg(subcommand);
        }
        return Ok(command);
    }
    match subcommand {
        "xtask" => {
            command.args(["run", "--locked", "-p", "xtask", "--", "--locked"]);
        }
        "nextest-run" => {
            command.args(["nextest", "run", "--locked"]);
        }
        // cargo-fmt reads source/manifest shape; it does not resolve or build
        // dependencies and does not accept Cargo's --locked flag.
        "fmt" => {
            command.arg("fmt");
        }
        "build" | "check" | "test" | "run" | "metadata" | "tree" | "clippy" | "deny" | "doc"
        | "rustc" | "rustdoc" | "fetch" => {
            command.args([subcommand, "--locked"]);
        }
        "add" | "remove" | "update" | "generate-lockfile" => {
            return Err(invalid(format!(
                "locked proof forbids cargo {subcommand}; prepare and review dependency changes separately"
            )));
        }
        // Cargo 1.95 can package successfully without an input Cargo.lock,
        // even with --locked. The packaged graph is a separate obligation.
        "package" | "publish" => {
            return Err(invalid(
                "locked proof does not admit package/publish: the separately resolved package graph needs its own verified lock policy",
            ));
        }
        // cargo install --locked may fall back when a published package has
        // no lockfile. Do not mistake that behavior for strict proof locking.
        "install" => {
            return Err(invalid(
                "locked proof does not admit cargo install; use a separately prepared and verified tool installation",
            ));
        }
        _ => {
            return Err(invalid(format!(
                "cargo {subcommand} has no qualified locked proof policy"
            )));
        }
    }
    Ok(command)
}

/// Fixed non-building probes remain usable even for tools whose execution
/// policy is deliberately not qualified for locked proof.
pub(crate) fn probe(subcommand: &str, help: bool) -> Command {
    let mut command = Command::new("cargo");
    command.args([subcommand, if help { "--help" } else { "--version" }]);
    command
}

/// Command tables must use the same policy as direct Cargo call sites.
pub(crate) fn from_argv<S: AsRef<OsStr>>(program: &str, args: &[S]) -> io::Result<Command> {
    if program != "cargo" {
        let mut command = Command::new(program);
        command.args(args);
        return Ok(command);
    }
    let (subcommand, rest) = args
        .split_first()
        .ok_or_else(|| invalid("missing Cargo subcommand"))?;
    let subcommand = subcommand
        .as_ref()
        .to_str()
        .ok_or_else(|| invalid("Cargo subcommand must be UTF-8"))?;
    let mut command = self::command(subcommand)?;
    command.args(rest);
    Ok(command)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn argv(command: &Command) -> Vec<OsString> {
        command.get_args().map(OsStr::to_os_string).collect()
    }

    fn strings(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn every_resolving_command_places_locked_before_caller_arguments() -> io::Result<()> {
        for subcommand in [
            "build", "check", "test", "run", "metadata", "tree", "clippy", "deny", "doc", "rustc",
            "rustdoc", "fetch",
        ] {
            let mut command = command_for(subcommand, true)?;
            command.args([
                "--manifest-path",
                "consumer/Cargo.toml",
                "--",
                "--locked-is-program-input",
            ]);
            assert_eq!(
                argv(&command),
                strings(&[
                    subcommand,
                    "--locked",
                    "--manifest-path",
                    "consumer/Cargo.toml",
                    "--",
                    "--locked-is-program-input",
                ])
            );
        }
        Ok(())
    }

    #[test]
    fn child_xtask_locks_its_build_and_propagates_proof_mode() -> io::Result<()> {
        let mut command = command_for("xtask", true)?;
        command.args(["public-surface"]);
        assert_eq!(
            argv(&command),
            strings(&[
                "run",
                "--locked",
                "-p",
                "xtask",
                "--",
                "--locked",
                "public-surface",
            ])
        );
        Ok(())
    }

    #[test]
    fn nextest_places_locked_after_its_run_subcommand() -> io::Result<()> {
        let command = command_for("nextest-run", true)?;
        assert_eq!(argv(&command), strings(&["nextest", "run", "--locked"]));
        Ok(())
    }

    #[test]
    fn non_resolving_fmt_and_fixed_probes_are_not_given_unsupported_options() -> io::Result<()> {
        assert_eq!(argv(&command_for("fmt", true)?), strings(&["fmt"]));
        assert_eq!(argv(&probe("deny", false)), strings(&["deny", "--version"]));
        assert_eq!(argv(&probe("fuzz", true)), strings(&["fuzz", "--help"]));
        Ok(())
    }

    #[test]
    fn proof_mode_rejects_dependency_mutation_instead_of_refreshing_locks() {
        for subcommand in ["add", "remove", "update", "generate-lockfile"] {
            let error = command_for(subcommand, true).expect_err("must reject dependency mutation");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(
                error
                    .to_string()
                    .contains("prepare and review dependency changes separately")
            );
        }
    }

    #[test]
    fn proof_mode_rejects_unqualified_plugins_toolchains_and_install_fallback() {
        for subcommand in [
            "fuzz", "mutants", "llvm-cov", "+nightly", "install", "package", "publish", "custom",
            "nextest",
        ] {
            assert!(command_for(subcommand, true).is_err(), "{subcommand}");
        }
    }

    #[test]
    fn standalone_commands_keep_their_existing_dependency_update_behavior() -> io::Result<()> {
        for subcommand in [
            "update",
            "add",
            "generate-lockfile",
            "install",
            "package",
            "publish",
            "fuzz",
            "xtask",
        ] {
            let command = command_for(subcommand, false)?;
            assert_eq!(argv(&command), strings(&[subcommand]));
        }
        Ok(())
    }

    #[test]
    fn child_arguments_are_not_shell_interpreted() -> io::Result<()> {
        let mut command = command_for("test", true)?;
        command.arg("a path with spaces;$(literal)");
        assert_eq!(
            argv(&command),
            strings(&["test", "--locked", "a path with spaces;$(literal)"])
        );
        Ok(())
    }

    fn tiny_project() -> io::Result<tempfile::TempDir> {
        let directory = tempfile::tempdir()?;
        std::fs::create_dir(directory.path().join("src"))?;
        std::fs::write(
            directory.path().join("Cargo.toml"),
            "[package]\nname = \"locked-policy-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n[workspace]\n",
        )?;
        std::fs::write(directory.path().join("src/lib.rs"), "pub fn fixture() {}\n")?;
        Ok(directory)
    }

    #[test]
    fn native_cargo_rejects_missing_lock_for_a_fresh_consumer() -> io::Result<()> {
        let directory = tiny_project()?;
        let output = command_for("check", true)?
            .arg("--offline")
            .current_dir(directory.path())
            .env("CARGO_TARGET_DIR", directory.path().join("target"))
            .output()?;
        assert!(
            !output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!directory.path().join("Cargo.lock").exists());
        assert!(String::from_utf8_lossy(&output.stderr).contains("--locked"));
        Ok(())
    }

    #[test]
    fn native_cargo_accepts_prepared_lock_then_rejects_a_resolution_change() -> io::Result<()> {
        let directory = tiny_project()?;
        let output = command_for("generate-lockfile", false)?
            .arg("--offline")
            .current_dir(directory.path())
            .env("CARGO_TARGET_DIR", directory.path().join("target"))
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let lock_path = directory.path().join("Cargo.lock");
        let original_lock = std::fs::read(&lock_path)?;
        let output = command_for("check", true)?
            .arg("--offline")
            .current_dir(directory.path())
            .env("CARGO_TARGET_DIR", directory.path().join("target"))
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let manifest = directory.path().join("Cargo.toml");
        let changed = std::fs::read_to_string(&manifest)?.replace("0.0.0", "0.0.1");
        std::fs::write(manifest, changed)?;
        let output = command_for("check", true)?
            .arg("--offline")
            .current_dir(directory.path())
            .env("CARGO_TARGET_DIR", directory.path().join("target"))
            .output()?;
        assert!(
            !output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("--locked"));
        assert_eq!(std::fs::read(lock_path)?, original_lock);
        Ok(())
    }

    #[test]
    fn native_package_locked_flag_does_not_establish_an_input_lock() -> io::Result<()> {
        let directory = tiny_project()?;
        // This is the Cargo 1.95 counterexample behind the proof-mode block,
        // not an accepted proof invocation. Standalone packaging is retained.
        let output = command_for("package", false)?
            .args([
                "--locked",
                "--offline",
                "--no-verify",
                "--exclude-lockfile",
                "--allow-dirty",
            ])
            .current_dir(directory.path())
            .env("CARGO_TARGET_DIR", directory.path().join("target"))
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!directory.path().join("Cargo.lock").exists());
        let error =
            command_for("package", true).expect_err("packaging needs a separate lock policy");
        assert!(
            error
                .to_string()
                .contains("separately resolved package graph")
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn actual_subprocess_receives_the_locked_arguments_without_shell_rewriting() -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir()?;
        let executable = directory.path().join("cargo");
        std::fs::write(&executable, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n")?;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))?;
        let output = command_for("run", true)?
            .args(["-p", "consumer", "--", "a path with spaces;$(literal)"])
            .env("PATH", directory.path())
            .current_dir(directory.path())
            .output()?;
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "run\n--locked\n-p\nconsumer\n--\na path with spaces;$(literal)\n",
        );
        Ok(())
    }
}
