from __future__ import annotations

import base64
import gzip
import subprocess
import tomllib
from collections import Counter
from pathlib import Path


def run(*args: str) -> None:
    subprocess.run(args, check=True)


def output(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


def replace_exact(path: str, replacements: list[tuple[str, str]]) -> None:
    target = Path(path)
    content = target.read_text(encoding="utf-8")
    for old, new in replacements:
        count = content.count(old)
        assert count == 1, f"{path}: expected one occurrence, found {count}: {old!r}"
        content = content.replace(old, new, 1)
    target.write_text(content, encoding="utf-8")


anchors = {
    "crates/uselesskey-core/src/srp/seed.rs": "fbb35c896f74ea61f690e926fcdfa4f8f4d8f9a1",
    "crates/uselesskey-core/src/srp/sink.rs": "020501764f3c10c5a9306bdd6f03a9ef972a1250",
    "xtask/src/adoption_command_ledger.rs": "5acd7f6659c6938298681d1d3fa838e8b4281595",
    "xtask/src/target_output.rs": "3e14cbe32811cf02f477d7ae010b90b956010c49",
}
for path, expected in anchors.items():
    actual = output("git", "hash-object", path)
    assert actual == expected, (path, actual, expected)

baseline_path = Path("policy/no-panic-baseline.toml")
before_text = baseline_path.read_text(encoding="utf-8")
before = tomllib.loads(before_text)
assert int(before["summary"]["total"]) == 3466

payload = Path(".github/bootstrap/no-panic-core.patch.gz.b64").read_bytes()
patch = gzip.decompress(base64.b64decode(payload))
patch_path = Path("/tmp/no-panic-core.patch")
patch_path.write_bytes(patch)
run("git", "apply", "--check", str(patch_path))
run("git", "apply", str(patch_path))

replace_exact(
    "xtask/src/adoption_command_ledger.rs",
    [
        (
            '        let header = columns.as_ref().expect("headers found");',
            '        let Some(header) = columns.as_ref() else {\n            continue;\n        };',
        ),
        (
            '    let re = Regex::new(pattern).expect("valid inline-code regex");',
            '    let Ok(re) = Regex::new(pattern) else {\n        return Vec::new();\n    };',
        ),
        (
            '    let re = Regex::new(r"\\[[^\\]]+\\]\\(([^)]+)\\)").expect("valid markdown link regex");',
            '    let Ok(re) = Regex::new(r"\\[[^\\]]+\\]\\(([^)]+)\\)") else {\n        return paths;\n    };',
        ),
        (
            '    let placeholder = Regex::new(r"<[^>]+>").expect("valid placeholder regex");',
            '    let Ok(placeholder) = Regex::new(r"<[^>]+>") else {\n        return Vec::new();\n    };',
        ),
    ],
)

replace_exact(
    "xtask/src/target_output.rs",
    [
        (
            '''        fs::create_dir_all(
            stale_path
                .parent()
                .expect("target path must have a parent for test setup"),
        )?;''',
            '''        let parent = stale_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("target path must have a parent for test setup"))?;
        fs::create_dir_all(parent)?;''',
        ),
        (
            '''    #[test]
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
    }''',
            '''    #[test]
    fn target_output_lock_classifies_command_mismatch_as_stale() -> Result<()> {
        let metadata = OutputLockMetadata {
            command_name: "other-command".to_string(),
            pid: 1,
            created_at: 0,
        };

        let status = classify_existing_lock(metadata, "test-command")?;
        match status {
            LockStatus::Stale(reason) => assert!(reason.contains("command mismatch")),
            _ => bail!("expected stale status for command mismatch"),
        }
        Ok(())
    }''',
        ),
        (
            '''    #[test]
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
    }''',
            '''    #[test]
    fn target_output_lock_classifies_unknown_owner_as_stale_after_age() -> Result<()> {
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
            _ => bail!("expected stale status for old unknown-owner metadata"),
        }
        Ok(())
    }''',
        ),
        (
            '''            tx.send(())
                .expect("lock waiter can report successful acquisition");''',
            '''            tx.send(())
                .context("lock waiter could not report successful acquisition")?;''',
        ),
        (
            '''        waiter
            .join()
            .expect("lock waiter thread panicked while acquiring output lock")?;''',
            '''        match waiter.join() {
            Ok(result) => result?,
            Err(_) => bail!("lock waiter thread panicked while acquiring output lock"),
        }''',
        ),
    ],
)

run("cargo", "fmt", "--all")
run("cargo", "fmt", "--all", "--", "--check")
run("cargo", "test", "-p", "uselesskey-core", "--all-features", "--locked")
run("cargo", "clippy", "-p", "uselesskey-core", "--all-targets", "--all-features", "--locked", "--", "-D", "warnings")
run("cargo", "test", "-p", "xtask", "--locked")
run("cargo", "clippy", "-p", "xtask", "--all-targets", "--locked", "--", "-D", "warnings")

Path("/tmp/no-panic-baseline.before.toml").write_text(before_text, encoding="utf-8")
run("cargo", "xtask", "no-panic", "baseline")
run("cargo", "xtask", "check-no-panic-family")

after = tomllib.loads(baseline_path.read_text(encoding="utf-8"))
assert int(after["summary"]["total"]) == 3448


def identities(document: dict[str, object]) -> Counter[tuple[tuple[str, str], ...]]:
    result: Counter[tuple[tuple[str, str], ...]] = Counter()
    for entry in document.get("entry", []):
        identity = tuple(sorted((key, str(value)) for key, value in entry.items() if key != "count"))
        result[identity] += int(entry["count"])
    return result


before_entries = identities(before)
after_entries = identities(after)
added = after_entries - before_entries
removed = before_entries - after_entries
assert not added, f"baseline refresh added or increased findings: {added}"
assert sum(removed.values()) == 18, removed
for record, count in removed.items():
    fields = dict(record)
    assert fields.get("path") in {
        "crates/uselesskey-core/src/srp/seed.rs",
        "crates/uselesskey-core/src/srp/sink.rs",
    }, (fields, count)
    assert fields.get("family") == "unwrap", (fields, count)
assert sum(after_entries.values()) == 3448

run("git", "diff", "--check")
expected = {
    "crates/uselesskey-core/src/srp/seed.rs",
    "crates/uselesskey-core/src/srp/sink.rs",
    "policy/no-panic-baseline.toml",
    "xtask/src/adoption_command_ledger.rs",
    "xtask/src/target_output.rs",
}
changed = set(output("git", "diff", "--name-only").splitlines())
assert changed == expected, (changed, expected)

run("git", "config", "user.name", "EffortlessSteven")
run("git", "config", "user.email", "git@effortlesssteven.com")
run("git", "add", *sorted(expected))
run("git", "commit", "-m", "test: reduce historical panic-family baseline")
run("git", "push", "origin", f"HEAD:{output('git', 'branch', '--show-current')}")
