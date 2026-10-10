#!/usr/bin/env python3
"""Run the protected Uselesskey integration portfolio and write a bounded receipt."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("fmt", ("cargo", "xtask", "fmt")),
    ("clippy", ("cargo", "xtask", "clippy")),
    ("typos", ("cargo", "xtask", "typos")),
    ("deny", ("cargo", "xtask", "deny")),
    ("tests", ("cargo", "xtask", "test")),
    ("feature-matrix", ("cargo", "xtask", "feature-matrix")),
    ("dep-guard", ("cargo", "xtask", "dep-guard")),
    ("docs-sync", ("cargo", "xtask", "docs-sync", "--check")),
    ("public-surface", ("cargo", "xtask", "public-surface")),
    ("bdd", ("cargo", "xtask", "bdd")),
    ("no-blob", ("cargo", "xtask", "no-blob")),
    ("no-panic", ("cargo", "xtask", "check-no-panic-family")),
    ("file-policy", ("cargo", "xtask", "check-file-policy")),
    ("lint-policy", ("cargo", "xtask", "check-lint-policy")),
    ("spec-check", ("cargo", "xtask", "spec-check", "--strict")),
    ("diff-check", ("git", "diff", "--check")),
)

FORBIDDEN_TOKENS = {
    "mutants",
    "mutants-pr",
    "mutants-nightly",
    "fuzz",
    "coverage",
    "perf",
    "economics",
    "audit-surface",
    "publish",
    "publish-check",
    "publish-preflight",
    "release-evidence",
}


class ProofError(RuntimeError):
    """The bounded integration proof could not be run honestly."""


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def command_text(argv: tuple[str, ...]) -> str:
    return " ".join(argv)


def git_head(workspace: Path) -> str:
    completed = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=workspace,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise ProofError(
            "unable to identify exact workspace HEAD: "
            + completed.stderr.strip()
        )
    head = completed.stdout.strip()
    if not re_full_sha(head):
        raise ProofError(f"git rev-parse returned an invalid SHA: {head!r}")
    return head


def re_full_sha(value: str) -> bool:
    return len(value) == 40 and all(ch in "0123456789abcdef" for ch in value)


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        handle.write(encoded)
        temp_path = Path(handle.name)
    temp_path.replace(path)


def new_receipt(workspace: Path, head: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "git_sha": head,
        "event_name": os.environ.get("GITHUB_EVENT_NAME"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "workspace": str(workspace),
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "started_at": utc_now(),
        "finished_at": None,
        "conclusion": "running",
        "commands": [],
        "claim_boundary": [
            "exact checked-out integration revision",
            "workspace tests, feature shapes, BDD, dependency, docs, public-surface, and repository policy",
            "does not run mutation, fuzzing, coverage, performance, publication, or release evidence",
            "does not replace exact development-head proof or substantive review",
        ],
    }


def validate_command_contract() -> None:
    names = [name for name, _ in COMMANDS]
    if len(names) != len(set(names)):
        raise ProofError("integration command names must be unique")
    if not COMMANDS:
        raise ProofError("integration command portfolio must not be empty")

    for name, argv in COMMANDS:
        if not name or not argv or any(not item for item in argv):
            raise ProofError(f"invalid command entry: {name!r} {argv!r}")
        lowered = {item.lower() for item in argv}
        forbidden = sorted(lowered & FORBIDDEN_TOKENS)
        if forbidden:
            raise ProofError(
                f"integration command {name!r} contains deep-evidence token(s): "
                + ", ".join(forbidden)
            )


def self_test() -> None:
    validate_command_contract()
    expected = {
        "fmt",
        "clippy",
        "typos",
        "deny",
        "tests",
        "feature-matrix",
        "dep-guard",
        "docs-sync",
        "public-surface",
        "bdd",
        "no-blob",
        "no-panic",
        "file-policy",
        "lint-policy",
        "spec-check",
        "diff-check",
    }
    actual = {name for name, _ in COMMANDS}
    if actual != expected:
        raise ProofError(
            f"integration portfolio drift: expected {sorted(expected)}, got {sorted(actual)}"
        )
    print(f"integration proof self-test: ok ({len(COMMANDS)} commands)")


def run_proof(workspace: Path, receipt_path: Path) -> int:
    validate_command_contract()
    workspace = workspace.resolve()
    if not (workspace / "Cargo.toml").is_file():
        raise ProofError(f"workspace lacks Cargo.toml: {workspace}")
    if not (workspace / ".git").exists():
        raise ProofError(f"workspace lacks Git metadata: {workspace}")

    head = git_head(workspace)
    receipt = new_receipt(workspace, head)
    atomic_write_json(receipt_path, receipt)

    exit_code = 0
    try:
        for name, argv in COMMANDS:
            started_at = utc_now()
            started = time.monotonic()
            print(f"::group::{name}: {command_text(argv)}", flush=True)
            completed = subprocess.run(argv, cwd=workspace, check=False)
            print("::endgroup::", flush=True)
            duration_seconds = round(time.monotonic() - started, 3)
            result = {
                "name": name,
                "command": list(argv),
                "started_at": started_at,
                "duration_seconds": duration_seconds,
                "return_code": completed.returncode,
                "conclusion": (
                    "success" if completed.returncode == 0 else "failure"
                ),
            }
            receipt["commands"].append(result)
            atomic_write_json(receipt_path, receipt)
            if completed.returncode != 0:
                exit_code = completed.returncode or 1
                receipt["conclusion"] = "failure"
                break
        else:
            receipt["conclusion"] = "success"
    except KeyboardInterrupt:
        exit_code = 130
        receipt["conclusion"] = "cancelled"
        raise
    except BaseException:
        exit_code = 1
        receipt["conclusion"] = "error"
        raise
    finally:
        receipt["finished_at"] = utc_now()
        atomic_write_json(receipt_path, receipt)

    return exit_code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path("."),
        help="Exact checked-out integration workspace.",
    )
    parser.add_argument(
        "--receipt",
        type=Path,
        default=Path("target/integration-proof/receipt.json"),
        help="Receipt path, interpreted relative to the workspace when not absolute.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Validate the bounded command contract without running Cargo.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Print the bounded command portfolio and exit.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.list:
        validate_command_contract()
        for name, argv in COMMANDS:
            print(f"{name}\t{command_text(argv)}")
        return 0

    workspace = args.workspace.resolve()
    receipt_path = args.receipt
    if not receipt_path.is_absolute():
        receipt_path = workspace / receipt_path
    return run_proof(workspace, receipt_path)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProofError as exc:
        print(f"integration proof error: {exc}", file=sys.stderr)
        raise SystemExit(2)
