use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
#[cfg(not(target_os = "windows"))]
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

const OUTPUT_LOCK_TIMEOUT: Duration = Duration::from_mins(2);
const OUTPUT_LOCK_RETRY: Duration = Duration::from_millis(250);
const OUTPUT_LOCK_CLEANUP_RETRIES: usize = 120;
const OUTPUT_LOCK_CLEANUP_RETRY: Duration = Duration::from_millis(250);
const LOCK_METADATA_FILE: &str = ".xtask-output-lock.json";

#[derive(Debug, Serialize, Deserialize)]
struct OutputLockMetadata {
    command_name: String,
    pid: u32,
    created_at: u64,
}

#[derive(Debug)]
enum LockStatus {
    Live(String),
    Stale(String),
}

pub(crate) struct TargetOutputLock {
    path: PathBuf,
}

impl Drop for TargetOutputLock {
    fn drop(&mut self) {
        if let Err(err) = remove_lock_directory(&self.path)
            && cfg!(debug_assertions)
        {
            eprintln!(
                "failed to remove target output lock {}: {}",
                self.path.display(),
                err
            );
        }
    }
}

fn remove_lock_directory(path: &Path) -> Result<()> {
    remove_dir_all_with_retries(path, OUTPUT_LOCK_CLEANUP_RETRIES, OUTPUT_LOCK_CLEANUP_RETRY)
        .with_context(|| format!("failed to clear stale output lock at {}", path.display()))
}

fn remove_dir_all_with_retries(path: &Path, attempts: usize, retry: Duration) -> Result<()> {
    for attempt in 0..attempts {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(err).with_context(|| format!("failed to read {}", path.display()));
            }
        };

        let remove_result = if metadata.is_dir() {
            fs::remove_dir_all(path)
        } else {
            fs::remove_file(path)
        };

        match remove_result {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                if let Err(clear_err) = clear_readonly_attributes(path) {
                    return Err(clear_err).with_context(|| {
                        format!("failed to clear read-only state at {}", path.display())
                    })?;
                }
                if attempt + 1 >= attempts {
                    return Err(err).with_context(|| {
                        format!("failed to remove stale output path {}", path.display())
                    });
                }
                thread::sleep(retry);
            }
        }
    }

    bail!("failed to remove output path {}", path.display())
}

fn clear_readonly_attributes(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to read {}", path.display()));
        }
    };

    let mut permissions = metadata.permissions();
    if permissions.readonly() {
        clear_readonly_flag(&mut permissions)?;
        fs::set_permissions(path, permissions)
            .with_context(|| format!("failed to clear read-only on {}", path.display()))?;
    }

    if metadata.is_dir() {
        for entry in
            fs::read_dir(path).with_context(|| format!("failed to read {}", path.display()))?
        {
            let entry =
                entry.with_context(|| format!("failed to read entry under {}", path.display()))?;
            clear_readonly_attributes(&entry.path())?;
        }
    }

    Ok(())
}

fn clear_readonly_flag(permissions: &mut std::fs::Permissions) -> Result<()> {
    if permissions.readonly() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = permissions.mode();
            permissions.set_mode(mode | 0o200);
            return Ok(());
        }

        #[cfg(not(unix))]
        {
            permissions.set_readonly(false);
            return Ok(());
        }
    }

    Ok(())
}

pub(crate) fn acquire_lock(
    root: &Path,
    lock_dir: impl AsRef<Path>,
    command_name: &str,
) -> Result<TargetOutputLock> {
    let lock_dir = lock_dir.as_ref();
    if lock_dir.is_absolute()
        || lock_dir
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        bail!(
            "{command_name} output lock path must be a relative target/ child: {}",
            lock_dir.display()
        );
    }

    let lock_dir = root.join(lock_dir);
    ensure_target_child(root, &lock_dir, command_name)?;
    let target_dir = root.join("target");
    fs::create_dir_all(&target_dir)
        .with_context(|| format!("failed to create {}", target_dir.display()))?;

    let start = Instant::now();
    loop {
        match fs::create_dir(&lock_dir) {
            Ok(()) => {
                if let Err(err) = write_lock_metadata(&lock_dir, command_name) {
                    let _ = remove_lock_directory(&lock_dir);
                    return Err(err).with_context(|| {
                        format!("failed to write lock metadata for {}", lock_dir.display())
                    });
                }
                return Ok(TargetOutputLock { path: lock_dir });
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                match inspect_existing_lock(&lock_dir, command_name)? {
                    LockStatus::Live(reason) => {
                        if start.elapsed() >= OUTPUT_LOCK_TIMEOUT {
                            bail!(
                                "timed out waiting for {command_name} output lock at {}; {reason}; remove this directory only if no {command_name} run is active",
                                lock_dir.display()
                            );
                        }
                        thread::sleep(OUTPUT_LOCK_RETRY);
                    }
                    LockStatus::Stale(_reason) => {
                        remove_lock_directory(&lock_dir).with_context(|| {
                            format!(
                                "failed to remove stale {command_name} output lock at {}",
                                lock_dir.display()
                            )
                        })?;
                    }
                }
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to create {}", lock_dir.display()));
            }
        }
    }
}

fn ensure_target_child(root: &Path, path: &Path, command_name: &str) -> Result<()> {
    let absolute = absolute_path(root, path);
    let target_root = absolute_path(root, &root.join("target"));
    if !absolute.starts_with(&target_root) {
        bail!(
            "{command_name} refuses to write outside target/: {}",
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

fn write_lock_metadata(lock_dir: &Path, command_name: &str) -> Result<()> {
    let metadata = OutputLockMetadata {
        command_name: command_name.to_string(),
        pid: std::process::id(),
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .with_context(|| "system time before UNIX_EPOCH")?
            .as_secs(),
    };
    fs::write(
        lock_dir.join(LOCK_METADATA_FILE),
        serde_json::to_vec_pretty(&metadata).context("serialize lock metadata")?,
    )
    .with_context(|| {
        format!(
            "failed to write {}",
            lock_dir.join(LOCK_METADATA_FILE).display()
        )
    })
}

fn inspect_existing_lock(lock_dir: &Path, command_name: &str) -> Result<LockStatus> {
    match read_lock_metadata(lock_dir) {
        Ok(Some(meta)) => classify_existing_lock(meta, command_name),
        Ok(None) => Ok(LockStatus::Stale(
            "lock metadata file is missing".to_string(),
        )),
        Err(err) => Ok(LockStatus::Stale(format!(
            "existing output lock metadata is unreadable: {err}"
        ))),
    }
}

fn classify_existing_lock(meta: OutputLockMetadata, command_name: &str) -> Result<LockStatus> {
    if meta.command_name != command_name {
        return Ok(LockStatus::Stale(format!(
            "lock metadata command mismatch: expected `{command_name}` but found `{}`",
            meta.command_name
        )));
    }

    let process_state = process_is_alive(meta.pid)?;
    Ok(classify_existing_lock_with_state(meta, process_state))
}

fn classify_existing_lock_with_state(
    meta: OutputLockMetadata,
    process_state: ProcessState,
) -> LockStatus {
    match process_state {
        ProcessState::Alive => LockStatus::Live(format!("owned by live process pid={}", meta.pid)),
        ProcessState::NotRunning => LockStatus::Stale(format!(
            "metadata owner pid {} for command `{}` is not running",
            meta.pid, meta.command_name
        )),
        ProcessState::Unknown(reason) => {
            if is_lock_stale_by_age(meta.created_at) {
                LockStatus::Stale(format!(
                    "lock owner pid {} for command `{}` is stale by age and unverified: {reason}",
                    meta.pid, meta.command_name
                ))
            } else {
                LockStatus::Live(format!(
                    "lock metadata for pid {} is still unverified: {reason}",
                    meta.pid
                ))
            }
        }
    }
}

fn is_lock_stale_by_age(created_at: u64) -> bool {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_secs(),
        Err(_) => return false,
    };

    now.saturating_sub(created_at) > OUTPUT_LOCK_TIMEOUT.as_secs()
}

fn read_lock_metadata(lock_dir: &Path) -> Result<Option<OutputLockMetadata>> {
    let path = lock_dir.join(LOCK_METADATA_FILE);
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to read {}", path.display()))?;
        }
    };
    serde_json::from_str(&raw).context("failed to parse output-lock metadata")
}

#[derive(Debug)]
enum ProcessState {
    Alive,
    NotRunning,
    Unknown(String),
}

#[cfg(not(target_os = "windows"))]
fn process_is_alive(pid: u32) -> Result<ProcessState> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "pid="])
        .output()
        .with_context(|| "failed to run ps for lock owner check")?;
    if !output.status.success() {
        return Ok(ProcessState::Unknown(format!(
            "ps returned non-zero exit code {}",
            output.status
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.lines().any(|line| !line.trim().is_empty()) {
        Ok(ProcessState::Alive)
    } else {
        Ok(ProcessState::NotRunning)
    }
}

#[cfg(target_os = "windows")]
fn process_is_alive(pid: u32) -> Result<ProcessState> {
    if pid == 0 {
        return Ok(ProcessState::NotRunning);
    }
    if pid == std::process::id() {
        return Ok(ProcessState::Alive);
    }

    let output = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "LIST"])
        .output()
        .with_context(|| format!("failed to run tasklist for pid {pid}"))?;
    if !output.status.success() {
        return Ok(ProcessState::Unknown(format!(
            "tasklist returned non-zero status for pid {pid}: {}",
            output.status
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout
        .lines()
        .any(|line| line.to_ascii_lowercase().contains("no tasks"))
    {
        return Ok(ProcessState::NotRunning);
    }

    for line in stdout.lines() {
        let mut fields = line.split(':');
        let Some((label, value)) = fields.next().zip(fields.next()) else {
            continue;
        };
        if !label.trim().eq_ignore_ascii_case("pid") {
            continue;
        }
        if let Ok(found_pid) = value.trim().parse::<u32>()
            && found_pid == pid
        {
            return Ok(ProcessState::Alive);
        }
    }

    // If tasklist output is non-empty but cannot be parsed, treat as alive:
    // the PID likely still exists, and the ambiguity should not block teardown as a safe removal of stale state.
    if stdout.lines().any(|line| !line.trim().is_empty()) {
        Ok(ProcessState::Alive)
    } else {
        Ok(ProcessState::Unknown(format!(
            "tasklist output for pid {pid} was empty or unparsable"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    #[test]
    fn target_output_process_is_alive_uses_tasklist() -> Result<()> {
        let pid = std::process::id();
        match process_is_alive(pid)? {
            ProcessState::Alive => Ok(()),
            other => bail!("expected current process {pid} to be alive, got {other:?}"),
        }
    }

    #[test]
    fn target_output_lock_rejects_non_target_lock_dir() -> Result<()> {
        let root = std::env::temp_dir().join("uselesskey-target-output-test");
        let err = match acquire_lock(&root, "../outside-target-output.lock", "test-command") {
            Ok(_) => bail!("non-target output lock was accepted"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("relative target/ child"));
        Ok(())
    }

    #[test]
    fn target_output_lock_rejects_target_parent_traversal() -> Result<()> {
        let root = std::env::temp_dir().join("uselesskey-target-output-test");
        let err = match acquire_lock(
            &root,
            "target/../outside-target-output.lock",
            "test-command",
        ) {
            Ok(_) => bail!("traversing output lock was accepted"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("relative target/ child"));
        Ok(())
    }

    #[test]
    fn target_output_lock_reuses_stale_lock() -> Result<()> {
        let root = tempfile::tempdir()?;
        let stale_dir = root.path().join("target/test-command.lock");
        fs::create_dir_all(&stale_dir)?;
        write_lock_metadata(&stale_dir, "stale-command")?;
        let stale_path = stale_dir.join(LOCK_METADATA_FILE);
        let mut metadata: OutputLockMetadata =
            serde_json::from_str(&fs::read_to_string(&stale_path).context("read stale metadata")?)?;
        metadata.created_at = metadata
            .created_at
            .saturating_sub(Duration::from_hours(2).as_secs());
        metadata.pid = 0;
        fs::write(
            &stale_path,
            serde_json::to_vec_pretty(&metadata).context("rewrite stale metadata")?,
        )?;

        let lock = acquire_lock(root.path(), "target/test-command.lock", "test-command")?;
        drop(lock);
        Ok(())
    }

    #[test]
    fn target_output_lock_reuses_stale_missing_metadata_lock() -> Result<()> {
        let root = tempfile::tempdir()?;
        let stale_dir = root.path().join("target/test-command.lock");
        fs::create_dir_all(&stale_dir)?;

        let lock = acquire_lock(root.path(), "target/test-command.lock", "test-command")?;
        drop(lock);
        Ok(())
    }

    #[test]
    fn target_output_remove_lock_directory_removes_file_path() -> Result<()> {
        let root = tempfile::tempdir()?;
        let stale_path = root.path().join("target/test-command.lock");
        fs::create_dir_all(
            stale_path
                .parent()
                .expect("target path must have a parent for test setup"),
        )?;
        fs::write(&stale_path, b"stale lock file")?;
        let mut permissions = fs::metadata(&stale_path)?.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&stale_path, permissions)?;

        remove_lock_directory(&stale_path)?;
        assert!(!stale_path.exists());
        Ok(())
    }

    #[test]
    fn target_output_lock_classifies_command_mismatch_as_stale() {
        let metadata = OutputLockMetadata {
            command_name: "other-command".to_string(),
            pid: 1,
            created_at: 0,
        };

        let status = classify_existing_lock(metadata, "test-command").expect("classify");
        match status {
            LockStatus::Stale(reason) => assert!(reason.contains("command mismatch")),
            _ => panic!("expected stale status for command mismatch"),
        }
    }

    #[test]
    fn target_output_lock_classifies_unknown_owner_as_stale_after_age() {
        let metadata = OutputLockMetadata {
            command_name: "test-command".to_string(),
            pid: 1234,
            created_at: 0,
        };

        let status = classify_existing_lock_with_state(
            metadata,
            ProcessState::Unknown("unit test".to_string()),
        );
        match status {
            LockStatus::Stale(reason) => assert!(
                reason.contains("stale by age"),
                "expected stale-by-age reason, got {reason:?}"
            ),
            _ => panic!("expected stale status for old unknown-owner metadata"),
        }
    }

    #[test]
    fn target_output_lock_serializes_access() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let first_lock = acquire_lock(dir.path(), "target/test-command.lock", "test-command")?;
        let (tx, rx) = std::sync::mpsc::channel();
        let root = dir.path().to_path_buf();
        let root_for_waiter = root.clone();
        let waiter = std::thread::spawn(move || -> Result<()> {
            let _second_lock =
                acquire_lock(&root_for_waiter, "target/test-command.lock", "test-command")?;
            tx.send(())
                .expect("lock waiter can report successful acquisition");
            Ok(())
        });

        match rx.recv_timeout(Duration::from_millis(300)) {
            Ok(()) => bail!("second target output lock acquired too early"),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                bail!("lock waiter disconnected before acquiring the output lock")
            }
        }

        drop(first_lock);
        rx.recv_timeout(Duration::from_secs(5))
            .context("second target output lock did not acquire after release")?;
        waiter
            .join()
            .expect("lock waiter thread panicked while acquiring output lock")?;
        Ok(())
    }
}
