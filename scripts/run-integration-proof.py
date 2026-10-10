#!/usr/bin/env python3
"""Run the bounded integration portfolio and verify its exact-subject receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 2
POLICY_ID = "uselesskey-bounded-integration-v1"

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
    "ci", "mutants", "mutants-pr", "mutants-nightly", "fuzz", "coverage",
    "perf", "economics", "audit-surface", "publish", "publish-check",
    "publish-preflight", "release-evidence",
}
INPUT_PATHS = ("Cargo.lock", "rust-toolchain.toml")


class ProofError(RuntimeError):
    """The integration result cannot honestly be credited."""


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str) and len(value) == length
        and all(ch in "0123456789abcdef" for ch in value)
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProofError(message)


def invocation_uuid(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ProofError("invocation ID must be a canonical UUID") from exc
    require(str(parsed) == value, "invocation ID must be a canonical UUID")
    return value


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def policy() -> dict[str, Any]:
    return {
        "id": POLICY_ID,
        "commands": [{"name": name, "command": list(argv)} for name, argv in COMMANDS],
    }


def policy_digest() -> str:
    encoded = json.dumps(policy(), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def validate_command_contract() -> None:
    names = [name for name, _ in COMMANDS]
    require(bool(COMMANDS), "integration command portfolio must not be empty")
    require(len(names) == len(set(names)), "integration command names must be unique")
    for name, argv in COMMANDS:
        require(bool(name and argv and all(argv)), f"invalid command entry: {name!r}")
        forbidden = {item.lower() for item in argv} & FORBIDDEN_TOKENS
        require(not forbidden, f"unbounded/deep-evidence command: {name!r}")


def capture(argv: tuple[str, ...], workspace: Path) -> str:
    completed = subprocess.run(
        argv, cwd=workspace, check=False, capture_output=True, text=True,
    )
    require(
        completed.returncode == 0,
        f"{' '.join(argv)} failed ({completed.returncode}): {completed.stderr.strip()}",
    )
    return completed.stdout.strip()


def git(workspace: Path, *args: str) -> str:
    return capture(("git", "--no-optional-locks", *args), workspace)


def source_state(workspace: Path) -> dict[str, Any]:
    require(
        Path(git(workspace, "rev-parse", "--show-toplevel")).resolve() == workspace,
        "workspace must be the Git repository root",
    )
    head = git(workspace, "rev-parse", "HEAD")
    tree = git(workspace, "rev-parse", "HEAD^{tree}")
    require(is_hex(head, 40) and is_hex(tree, 40), "invalid Git source identity")
    # Do not let index hints hide modified tracked input from the cleanliness check.
    flags = git(workspace, "ls-files", "-v").splitlines()
    require(
        all(line and line[0] != "S" and not line[0].islower() for line in flags),
        "tracked files have skip-worktree or assume-unchanged flags",
    )
    status = git(
        workspace, "status", "--porcelain=v1", "--untracked-files=no",
        "--ignore-submodules=none",
    )
    return {"sha": head, "tree": tree, "tracked_clean": not bool(status)}


def require_source(
    workspace: Path, expected_sha: str, expected_tree: str | None = None,
) -> dict[str, Any]:
    state = source_state(workspace)
    require(state["sha"] == expected_sha, "workspace HEAD differs from expected subject")
    require(state["tracked_clean"], "workspace has tracked changes")
    if expected_tree is not None:
        require(state["tree"] == expected_tree, "workspace tree changed during proof")
    return state


def tracked_inputs(workspace: Path) -> dict[str, Any]:
    inputs: dict[str, Any] = {}
    for name in INPUT_PATHS:
        git(workspace, "ls-files", "--error-unmatch", "--", name)
        path = workspace / name
        require(path.is_file() and not path.is_symlink(), f"missing regular input: {name}")
        inputs[name] = {"sha256": sha256_file(path)}
    return inputs


def control_identity() -> dict[str, Any]:
    script = Path(__file__).resolve()
    root = Path(git(script.parent, "rev-parse", "--show-toplevel")).resolve()
    relative = script.relative_to(root).as_posix()
    git(root, "ls-files", "--error-unmatch", "--", relative)
    state = source_state(root)
    require(state["tracked_clean"], "integration control checkout has tracked changes")
    return {
        "script": relative, "sha256": sha256_file(script),
        "git_sha": state["sha"], "git_tree": state["tree"],
    }


def toolchain_identity(workspace: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in ("rustc", "cargo"):
        argv = (name, "-vV")
        version = capture(argv, workspace)
        require(bool(version), f"{name} returned no version identity")
        result[name] = {"command": list(argv), "version": version}
    return result


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    encoded = json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON field: {key}")
        result[key] = value
    return result


def read_receipt(path: Path) -> dict[str, Any]:
    def invalid_constant(value: str) -> None:
        raise ProofError(f"non-finite JSON value: {value}")

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=unique_object,
            parse_constant=invalid_constant,
        )
    except (OSError, ValueError) as exc:
        raise ProofError(f"cannot read complete receipt: {exc}") from exc
    require(isinstance(value, dict), "receipt must be a JSON object")
    return value


def timestamp(value: Any) -> datetime:
    require(isinstance(value, str), "missing receipt timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProofError("invalid receipt timestamp") from exc
    require(parsed.tzinfo is not None, "receipt timestamps must include a timezone")
    return parsed


def verify_receipt(
    receipt: dict[str, Any], *, expected_sha: str, invocation_id: str,
    expected_control_sha256: str, expected_policy_sha256: str,
    subject_kind: str = "manual", expected_base: str | None = None,
) -> None:
    """Verify caller-owned subject/control/policy identities; run_context is observational."""
    validate_command_contract()
    invocation_uuid(invocation_id)
    require(is_hex(expected_sha, 40), "expected SHA must be a full lowercase SHA")
    require(is_hex(expected_control_sha256, 64), "expected control digest is required")
    require(is_hex(expected_policy_sha256, 64), "expected policy digest is required")
    require(expected_policy_sha256 == policy_digest(), "verifier policy digest mismatch")
    require(type(receipt.get("schema_version")) is int, "invalid schema version type")
    require(receipt["schema_version"] == SCHEMA_VERSION, "unsupported receipt schema")
    require(receipt.get("invocation_id") == invocation_id, "receipt belongs to another invocation")
    require(receipt.get("conclusion") == "success", "receipt did not succeed")
    require(receipt.get("complete") is True, "receipt is incomplete")
    require(receipt.get("policy") == {**policy(), "sha256": expected_policy_sha256}, "receipt policy mismatch")
    subject = receipt.get("subject", {})
    require(isinstance(subject, dict), "invalid receipt subject")
    require(
        subject == {"kind": subject_kind, "expected_sha": expected_sha, "expected_base": expected_base},
        "receipt subject mismatch",
    )
    require(subject_kind in ("manual", "merge-group"), "invalid subject kind")
    require(
        expected_base is None or is_hex(expected_base, 40), "invalid expected base",
    )
    require(subject_kind != "merge-group" or expected_base is not None, "merge-group proof needs its base")
    control = receipt.get("control", {})
    require(isinstance(control, dict), "invalid control identity")
    require(control.get("sha256") == expected_control_sha256, "receipt control digest mismatch")
    require(
        is_hex(control.get("git_sha"), 40) and is_hex(control.get("git_tree"), 40)
        and isinstance(control.get("script"), str) and bool(control["script"]),
        "incomplete control identity",
    )
    source = receipt.get("source", {})
    require(isinstance(source, dict), "invalid source identity")
    before, after = source.get("before", {}), source.get("after", {})
    require(isinstance(before, dict) and isinstance(after, dict), "missing source checks")
    require(
        before == after and before.get("sha") == expected_sha
        and is_hex(before.get("tree"), 40) and before.get("tracked_clean") is True,
        "receipt does not establish unchanged clean tracked source",
    )
    require(
        source.get("base_is_ancestor") is (True if expected_base else None),
        "receipt base relationship is missing",
    )
    inputs = receipt.get("inputs", {})
    require(isinstance(inputs, dict) and set(inputs) == set(INPUT_PATHS), "missing tracked input identity")
    require(
        all(isinstance(value, dict) and is_hex(value.get("sha256"), 64) for value in inputs.values()),
        "invalid tracked input digest",
    )
    toolchain = receipt.get("toolchain", {})
    require(isinstance(toolchain, dict) and set(toolchain) == {"rustc", "cargo"}, "missing toolchain identity")
    for name, value in toolchain.items():
        require(
            isinstance(value, dict) and value.get("command") == [name, "-vV"]
            and isinstance(value.get("version"), str) and bool(value["version"].strip()),
            f"missing {name} identity",
        )
    started, finished = timestamp(receipt.get("started_at")), timestamp(receipt.get("finished_at"))
    require(finished >= started, "receipt finished before it started")
    results = receipt.get("commands")
    require(isinstance(results, list) and len(results) == len(COMMANDS), "incomplete command portfolio")
    previous_end = started
    for result, (name, argv) in zip(results, COMMANDS, strict=True):
        require(isinstance(result, dict), "invalid command result")
        require(
            result.get("name") == name and result.get("command") == list(argv),
            "missing, duplicated, reordered, or changed command",
        )
        require(
            result.get("conclusion") == "success" and type(result.get("return_code")) is int
            and result["return_code"] == 0, f"command did not succeed: {name}",
        )
        command_start = timestamp(result.get("started_at"))
        command_end = timestamp(result.get("finished_at"))
        require(
            previous_end <= command_start <= command_end <= finished,
            "command timestamps overlap, are reordered, or are outside invocation",
        )
        previous_end = command_end
        duration = result.get("duration_seconds")
        require(
            type(duration) in (int, float) and math.isfinite(duration) and duration >= 0,
            "invalid command duration",
        )


def run_proof(
    workspace: Path, receipt_path: Path, *, expected_sha: str, invocation_id: str,
    subject_kind: str = "manual", expected_base: str | None = None,
    expected_control_sha256: str | None = None, expected_policy_sha256: str | None = None,
) -> int:
    workspace, receipt_path = workspace.resolve(), receipt_path.resolve()
    invocation_uuid(invocation_id)
    require(receipt_path.parent.name == invocation_id, "receipt must be inside its invocation UUID directory")
    # A repeated ID fails before writing anything; an older attempt cannot be reused.
    receipt_path.parent.parent.mkdir(parents=True, exist_ok=True)
    try:
        receipt_path.parent.mkdir()
    except FileExistsError as exc:
        raise ProofError("invocation output directory already exists; use a new UUID") from exc
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION, "invocation_id": invocation_id,
        "subject": {"kind": subject_kind, "expected_sha": expected_sha, "expected_base": expected_base},
        "policy": {**policy(), "sha256": policy_digest()},
        "source": {}, "control": {}, "inputs": {}, "toolchain": {},
        # Ambient environment metadata does not authenticate the GitHub event or run.
        "run_context": {
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "event_name": os.environ.get("GITHUB_EVENT_NAME"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "workflow_sha": os.environ.get("GITHUB_WORKFLOW_SHA"),
        },
        "host": {"platform": platform.platform(), "python": platform.python_version()},
        "started_at": utc_now(), "finished_at": None,
        "conclusion": "running", "complete": False, "commands": [],
        "claim_boundary": [
            "bounded portfolio for the expected Git subject and unchanged tracked source",
            "input and control digests identify evidence; they are not signatures or attestations",
            "run_context records ambient environment values; it does not authenticate a GitHub run",
            "native merge-group routing, required-check credit, and artifact custody require live qualification",
            "untracked files, external dependencies, and the host are not a hermetic build claim",
            "excludes mutation, fuzzing, coverage, performance, publication, and release evidence",
            "does not replace development-head proof or substantive review",
        ],
    }
    atomic_write_json(receipt_path, receipt)
    print(f"integration invocation: {invocation_id}\nreceipt: {receipt_path}", flush=True)
    exit_code = 2
    current_result: dict[str, Any] | None = None
    try:
        validate_command_contract()
        require(is_hex(expected_sha, 40), "expected SHA must be a full lowercase SHA")
        require(subject_kind in ("manual", "merge-group"), "invalid subject kind")
        require(expected_base is None or is_hex(expected_base, 40), "invalid expected base")
        require(subject_kind != "merge-group" or expected_base is not None, "merge-group proof needs its base")
        require((workspace / "Cargo.toml").is_file(), "workspace lacks Cargo.toml")
        before = require_source(workspace, expected_sha)
        receipt["source"]["before"] = before
        if expected_base is not None:
            git(workspace, "merge-base", "--is-ancestor", expected_base, expected_sha)
        receipt["source"]["base_is_ancestor"] = True if expected_base else None
        receipt["control"] = control_identity()
        control_digest = receipt["control"]["sha256"]
        if expected_control_sha256 is not None:
            require(control_digest == expected_control_sha256, "running control digest mismatch")
        if expected_policy_sha256 is not None:
            require(policy_digest() == expected_policy_sha256, "running policy digest mismatch")
        receipt["inputs"] = tracked_inputs(workspace)
        receipt["toolchain"] = toolchain_identity(workspace)
        atomic_write_json(receipt_path, receipt)
        for name, argv in COMMANDS:
            require_source(workspace, expected_sha, before["tree"])
            started = time.monotonic()
            current_result = {
                "name": name, "command": list(argv), "started_at": utc_now(),
                "finished_at": None, "duration_seconds": None,
                "return_code": None, "conclusion": "running",
            }
            receipt["commands"].append(current_result)
            atomic_write_json(receipt_path, receipt)
            print(f"::group::{name}: {' '.join(argv)}", flush=True)
            try:
                completed = subprocess.run(argv, cwd=workspace, check=False)
            finally:
                print("::endgroup::", flush=True)
            current_result.update({
                "finished_at": utc_now(),
                "duration_seconds": round(time.monotonic() - started, 3),
                "return_code": completed.returncode,
                "conclusion": "success" if completed.returncode == 0 else "failure",
            })
            atomic_write_json(receipt_path, receipt)
            if completed.returncode != 0:
                receipt["conclusion"] = "failure"
                exit_code = completed.returncode if completed.returncode > 0 else 128 - completed.returncode
                break
        else:
            receipt["source"]["after"] = require_source(workspace, expected_sha, before["tree"])
            require(tracked_inputs(workspace) == receipt["inputs"], "tracked build inputs changed")
            require(control_identity() == receipt["control"], "integration controls changed")
            receipt.update({"conclusion": "success", "complete": True, "finished_at": utc_now()})
            verify_receipt(
                receipt, expected_sha=expected_sha, invocation_id=invocation_id,
                expected_control_sha256=control_digest, expected_policy_sha256=policy_digest(),
                subject_kind=subject_kind, expected_base=expected_base,
            )
            atomic_write_json(receipt_path, receipt)
            verify_receipt(
                read_receipt(receipt_path), expected_sha=expected_sha, invocation_id=invocation_id,
                expected_control_sha256=control_digest, expected_policy_sha256=policy_digest(),
                subject_kind=subject_kind, expected_base=expected_base,
            )
            exit_code = 0
    except KeyboardInterrupt:
        receipt["conclusion"] = "cancelled"
        if current_result and current_result["conclusion"] == "running":
            current_result["conclusion"] = "cancelled"
            current_result["finished_at"] = utc_now()
        exit_code = 130
    except Exception as exc:
        receipt["conclusion"] = "error"
        receipt["error"] = {"type": type(exc).__name__, "message": str(exc)}
        if current_result and current_result["conclusion"] == "running":
            current_result["conclusion"] = "error"
            current_result["finished_at"] = utc_now()
        print(f"integration proof error: {exc}", file=sys.stderr)
        exit_code = 2
    if exit_code != 0:
        receipt["complete"] = False
        receipt["finished_at"] = utc_now()
        atomic_write_json(receipt_path, receipt)
    return exit_code


def self_test() -> None:
    validate_command_contract()
    require(len(COMMANDS) == 16, "bounded integration portfolio must contain 16 commands")
    print(f"integration proof self-test: ok ({len(COMMANDS)} commands)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path("."))
    parser.add_argument(
        "--receipt", type=Path,
        help="Exact receipt file inside its invocation UUID directory; default: target/integration-proof/UUID/receipt.json.",
    )
    parser.add_argument("--expected-sha", help="Caller-selected full subject SHA; required for execution/verification.")
    parser.add_argument("--expected-base", help="Caller-selected full integration base SHA.")
    parser.add_argument("--subject-kind", choices=("manual", "merge-group"), default="manual")
    parser.add_argument("--invocation-id", help="Fresh canonical UUID; generated for execution if omitted.")
    parser.add_argument("--expected-control-sha256", help="Caller-trusted runner script digest; required for verification.")
    parser.add_argument("--expected-policy-sha256", help="Caller-trusted command policy digest; required for verification.")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--self-test", action="store_true")
    modes.add_argument("--list", action="store_true")
    modes.add_argument("--policy-digest", action="store_true")
    modes.add_argument("--verify-receipt", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    if args.list:
        validate_command_contract()
        for name, command in COMMANDS:
            print(f"{name}\t{' '.join(command)}")
        return 0
    if args.policy_digest:
        validate_command_contract()
        print(policy_digest())
        return 0
    require(args.expected_sha is not None, "--expected-sha is required")
    if args.verify_receipt:
        require(args.invocation_id is not None, "--invocation-id is required for verification")
        require(args.expected_control_sha256 is not None, "--expected-control-sha256 is required for verification")
        require(args.expected_policy_sha256 is not None, "--expected-policy-sha256 is required for verification")
    invocation_id = invocation_uuid(args.invocation_id or str(uuid.uuid4()))
    workspace = args.workspace.resolve()
    receipt_path = args.receipt or Path("target/integration-proof") / invocation_id / "receipt.json"
    if not receipt_path.is_absolute():
        receipt_path = workspace / receipt_path
    if args.verify_receipt:
        verify_receipt(
            read_receipt(receipt_path), expected_sha=args.expected_sha, invocation_id=invocation_id,
            expected_control_sha256=args.expected_control_sha256,
            expected_policy_sha256=args.expected_policy_sha256,
            subject_kind=args.subject_kind, expected_base=args.expected_base,
        )
        print(f"integration receipt verified: {invocation_id}")
        return 0
    return run_proof(
        workspace, receipt_path, expected_sha=args.expected_sha, invocation_id=invocation_id,
        subject_kind=args.subject_kind, expected_base=args.expected_base,
        expected_control_sha256=args.expected_control_sha256,
        expected_policy_sha256=args.expected_policy_sha256,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ProofError, OSError) as exc:
        print(f"integration proof error: {exc}", file=sys.stderr)
        raise SystemExit(2)
