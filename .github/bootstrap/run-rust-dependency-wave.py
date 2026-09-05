from __future__ import annotations

import subprocess
import tomllib
from pathlib import Path


def run(*args: str) -> None:
    subprocess.run(args, check=True)


def output(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


anchors = {
    "Cargo.lock": "2029404cc8a9fb045466b554f90de5596c6f021a",
    "crates/uselesskey-core/Cargo.toml": "dde81f71c1d655eb98cbf5fb4ba138a8aed4b41e",
}
for path, expected in anchors.items():
    assert output("git", "hash-object", path) == expected, path

manifest = Path("crates/uselesskey-core/Cargo.toml")
text = manifest.read_text(encoding="utf-8")
old = 'spin = { version = "0.11.0", default-features = false, features = ["mutex", "spin_mutex"] }'
new = 'spin = { version = "0.12.3", default-features = false, features = ["mutex", "spin_mutex"] }'
assert text.count(old) == 1
manifest.write_text(text.replace(old, new, 1), encoding="utf-8")

updates = [
    ("dashmap@6.1.0", "6.2.1"),
    ("chrono@0.4.44", "0.4.45"),
    ("regex@1.12.3", "1.13.1"),
    ("serde_json@1.0.149", "1.0.151"),
    ("trybuild@1.0.116", "1.0.120"),
    ("http@1.4.0", "1.5.0"),
    ("insta@1.47.2", "1.48.0"),
    ("time@0.3.47", "0.3.55"),
    ("rustls@0.23.40", "0.23.43"),
    ("spin@0.11.0", "0.12.3"),
]
for package, version in updates:
    run("cargo", "update", "-p", package, "--precise", version)

lock = tomllib.loads(Path("Cargo.lock").read_text(encoding="utf-8"))
versions: dict[str, set[str]] = {}
for package in lock["package"]:
    versions.setdefault(package["name"], set()).add(package["version"])

expected = {
    "dashmap": ("6.1.0", "6.2.1"),
    "chrono": ("0.4.44", "0.4.45"),
    "regex": ("1.12.3", "1.13.1"),
    "serde_json": ("1.0.149", "1.0.151"),
    "trybuild": ("1.0.116", "1.0.120"),
    "http": ("1.4.0", "1.5.0"),
    "insta": ("1.47.2", "1.48.0"),
    "time": ("0.3.47", "0.3.55"),
    "rustls": ("0.23.40", "0.23.43"),
    "spin": ("0.11.0", "0.12.3"),
}
for name, (old_version, new_version) in expected.items():
    assert new_version in versions.get(name, set()), (name, versions.get(name))
    assert old_version not in versions.get(name, set()), (name, versions.get(name))

run("cargo", "metadata", "--locked", "--no-deps", "--format-version", "1")
run("cargo", "check", "--workspace", "--all-targets", "--all-features", "--locked")
run("cargo", "deny", "check", "advisories")
run("git", "diff", "--check")

changed = set(output("git", "diff", "--name-only").splitlines())
assert changed == {"Cargo.lock", "crates/uselesskey-core/Cargo.toml"}, changed

run("git", "config", "user.name", "EffortlessSteven")
run("git", "config", "user.email", "git@effortlesssteven.com")
run("git", "add", "Cargo.lock", "crates/uselesskey-core/Cargo.toml")
run("git", "commit", "-m", "build(deps): consolidate current Rust dependency updates")
run("git", "push", "origin", f"HEAD:{output('git', 'branch', '--show-current')}")
