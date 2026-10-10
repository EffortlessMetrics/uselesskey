"""Versioned development-proof validation shared with canonical admission.

This module performs no process execution or repository access. A validated
local envelope is evidence of a declared invocation, not authenticated runner
attestation or an automated judgment of the plan's adequacy. Canonical admission
must bind the exact envelope and accepted plan digests using its trusted copy.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
import re
import tomllib
from typing import Any

KIND = "uselesskey-development-proof"

SCHEMA_VERSION = 1

PR_COMMAND = ["cargo", "xtask", "pr"]

BASELINE_STEPS = {"detect-changes", "public-surface", "spec-check"}

SKIP_FAMILIES = {"test:*", "feature-matrix:*", "preflight:package:*"}

DOC_COMMANDS = {
    "docs-sync", "spec-check", "typos", "check-doc-artifacts", "check-goals",
    "check-support-tiers", "check-claim-proof-policy",
}

CONTROL_COMMANDS = DOC_COMMANDS | {
    "check-file-policy", "check-lint-policy", "check-no-panic-family",
    "check-negative-fixtures", "check-bundle-schemas", "check-audit-receipts",
    "no-blob", "public-surface",
}

PRODUCT_COMMANDS = {"test", "bdd", "nextest", "coverage"}

FOCUSED_FUZZ_LIMITS = {"-runs": 1_000_000, "-max_total_time": 300, "-timeout": 300}

INFORMATIONAL_ARGS = {"-h", "--help", "-V", "--version", "--list", "--no-run"}

class ProofError(ValueError):
    """The evidence does not establish a completed development invocation."""

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def require_sha(value: Any, size: int = 40) -> str:
    if not isinstance(value, str) or re.fullmatch(rf"[0-9a-f]{{{size}}}", value) is None:
        raise ProofError(f"expected a lowercase {size}-character digest")
    return value

def exact_keys(value: Any, required: set[str], optional: set[str] = frozenset()) -> None:
    if not isinstance(value, dict):
        raise ProofError("expected an object")
    if set(value) - required - optional or required - set(value):
        raise ProofError(f"unexpected or missing fields: expected {sorted(required)}")

def json_object(data: bytes) -> dict[str, Any]:
    def reject_constant(value: str) -> None:
        raise ProofError(f"non-finite JSON number is not permitted: {value}")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ProofError(f"duplicate JSON field: {key}")
            result[key] = value
        return result

    try:
        result = json.loads(
            data.decode("utf-8"), object_pairs_hook=unique, parse_constant=reject_constant
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProofError(f"invalid UTF-8 JSON: {exc}") from exc
    if not isinstance(result, dict):
        raise ProofError("receipt must be a JSON object")
    return result

def classify_paths(paths: list[str]) -> dict[str, Any]:
    if not isinstance(paths, list) or any(not isinstance(path, str) or not path for path in paths):
        raise ProofError("changed paths must be nonempty repository-relative strings")
    for path in paths:
        parsed = PurePosixPath(path)
        if parsed.is_absolute() or ".." in parsed.parts or str(parsed) != path:
            raise ProofError(f"changed path is not a canonical repository-relative path: {path}")
    paths = sorted(set(paths))
    if not paths:
        raise ProofError("candidate has no changed paths")
    classes: set[str] = set()
    for path in paths:
        suffix = PurePosixPath(path).suffix
        if (
            path.startswith((".github/", ".cargo/", ".githooks/", "policy/", ".rails/", ".uselesskey/"))
            or path in {
                ".gitignore", ".gitattributes", "rust-toolchain.toml", "rustfmt.toml",
                "clippy.toml", "deny.toml", "lefthook.yml", "codecov.yml",
            }
            or path.startswith("scripts/") and suffix in {".py", ".sh", ".ps1", ".toml", ".json"}
            or path.startswith("xtask/") and suffix == ".rs"
            or path.startswith("docs/schemas/") and suffix == ".json"
        ):
            classes.add("control")
        elif path.startswith("fuzz/") and suffix != ".md":
            classes.update({"product", "fuzz"})
        elif PurePosixPath(path).name in {"Cargo.toml", "Cargo.lock"} or (
            path.startswith(("crates/", "tests/", "fuzz/", "examples/"))
            and suffix in {".rs", ".feature", ".snap"}
        ):
            classes.add("product")
        elif suffix == ".md":
            classes.add("docs")
        else:
            raise ProofError(f"unclassified changed path requires an explicit route: {path}")
    profile = "product" if "product" in classes else "control" if "control" in classes else "docs"
    return {"changed_paths": paths, "classes": sorted(classes), "profile": profile}


def validate_focused(item: Any) -> None:
    exact_keys(item, {"name", "kind", "command"})
    if not isinstance(item["name"], str) or not re.fullmatch(r"[a-z][a-z0-9_-]*", item["name"]):
        raise ProofError("focused command name must be a stable lowercase identifier")
    kind, command = item["kind"], item["command"]
    if kind not in ("product", "docs", "control", "fuzz"):
        raise ProofError("focused command kind must be product, docs, control, or fuzz")
    if (
        not isinstance(command, list) or not command
        or any(not isinstance(arg, str) or not arg or "\0" in arg for arg in command)
        or INFORMATIONAL_ARGS.intersection(command)
    ):
        raise ProofError("focused proof must contain executable argv, not a listing or help request")
    recognized = False
    if kind == "fuzz":
        validate_focused_fuzz(command)
        recognized = True
    elif command[:2] == ["cargo", "test"]:
        recognized = kind in {"product", "control"}
    elif len(command) >= 3 and command[:2] == ["cargo", "xtask"]:
        allowed = PRODUCT_COMMANDS if kind == "product" else DOC_COMMANDS if kind == "docs" else CONTROL_COMMANDS
        recognized = command[2] in allowed
    elif command[0] in {"python", "python3"} and kind == "control":
        args = command[1:]
        if args and args[0] == "-B":
            args = args[1:]
        recognized = args[:2] == ["-m", "unittest"] and len(args) > 2
    if not recognized:
        raise ProofError(f"unrecognized {kind} proof command; no arbitrary shell command is accepted")

def validate_focused_fuzz(command: list[str]) -> None:
    if (
        len(command) != 9 or command[:4] != ["cargo", "xtask", "fuzz", "--target"]
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", command[4]) is None
        or command[5] != "--"
    ):
        raise ProofError("focused fuzz proof requires one explicit target and three libFuzzer limits")
    limits: dict[str, int] = {}
    for argument in command[6:]:
        match = re.fullmatch(r"(-runs|-max_total_time|-timeout)=([1-9][0-9]{0,6})", argument)
        if match is None:
            raise ProofError("focused fuzz proof permits only positive run, total-time, and timeout limits")
        name, raw = match.groups()
        value = int(raw)
        if name in limits or value > FOCUSED_FUZZ_LIMITS[name]:
            raise ProofError("focused fuzz limits are duplicated or exceed the bounded proof policy")
        limits[name] = value
    if set(limits) != set(FOCUSED_FUZZ_LIMITS) or limits["-timeout"] > limits["-max_total_time"]:
        raise ProofError("focused fuzz proof needs every limit and timeout no greater than total time")

def parse_plan(data: bytes) -> dict[str, Any]:
    try:
        plan = tomllib.loads(data.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ProofError(f"invalid proof plan TOML: {exc}") from exc
    exact_keys(plan, {"schema_version", "profile", "required_steps"}, {"allow_skips", "focused"})
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        raise ProofError("proof plan schema_version must be 1")
    if plan["profile"] not in ("product", "docs", "control"):
        raise ProofError("proof plan profile must be product, docs, or control")
    required = plan["required_steps"]
    if (
        not isinstance(required, list) or not required
        or any(not isinstance(name, str) or not name for name in required)
        or len(required) != len(set(required))
    ):
        raise ProofError("required_steps must contain distinct exact xtask step names")
    skips = plan.setdefault("allow_skips", {})
    if not isinstance(skips, dict):
        raise ProofError("allow_skips must map step names to reviewed reasons")
    for name, reason in skips.items():
        if not name or "*" in name and name not in SKIP_FAMILIES:
            raise ProofError("skip wildcard is not a supported step family")
        if not isinstance(reason, str) or not reason.strip():
            raise ProofError("every allowed skip needs a nonempty reason")
        if any(skip_matches(name, required_name) for required_name in set(required) | BASELINE_STEPS):
            raise ProofError("a required successful step cannot also be allowed to skip")
    focused = plan.setdefault("focused", [])
    if not isinstance(focused, list):
        raise ProofError("focused must be an array")
    for item in focused:
        validate_focused(item)
    names = [item["name"] for item in focused]
    if len(names) != len(set(names)):
        raise ProofError("focused command names must be unique")
    return plan

def skip_matches(pattern: str, name: str) -> bool:
    return name.startswith(pattern[:-1]) if pattern in SKIP_FAMILIES else name == pattern

def validate_profile(plan: dict[str, Any], classification: dict[str, Any]) -> None:
    if plan["profile"] != classification["profile"]:
        raise ProofError("proof-plan profile does not match the changed-path classification")
    focused_kinds = {item["kind"] for item in plan["focused"]}
    if "fuzz" in classification["classes"] and "fuzz" not in focused_kinds:
        raise ProofError("fuzz-owned changes require explicit focused fuzz proof; ordinary PR proof does not run it")
    for kind in {"docs", "control"} & set(classification["classes"]):
        # Product/control proof can cover accompanying prose, but control changes need their own proof.
        if kind == "docs" and classification["profile"] != "docs":
            continue
        if kind not in focused_kinds:
            raise ProofError(f"{kind} changes require a declared focused {kind} proof")

def validate_xtask(
    data: bytes, subject: dict[str, str], plan: dict[str, Any], started: int, finished: int
) -> dict[str, Any]:
    receipt = json_object(data)
    if type(receipt.get("schema_version")) is not int or receipt["schema_version"] != 2:
        raise ProofError("raw xtask receipt schema_version must be 2")
    if receipt.get("git_sha") != subject["head"]:
        raise ProofError("raw xtask receipt does not match the invocation head")
    timestamp = receipt.get("timestamp")
    if type(timestamp) is not int or not started <= timestamp <= finished:
        raise ProofError("raw xtask receipt is stale or outside this invocation")
    if not isinstance(receipt.get("crate_set"), str) or not receipt["crate_set"].startswith("pr:"):
        raise ProofError("raw receipt is not a cargo xtask pr result")
    steps = receipt.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ProofError("raw receipt has no step ledger")
    by_name: dict[str, dict[str, Any]] = {}
    for step in steps:
        if not isinstance(step, dict) or not isinstance(step.get("name"), str) or not step["name"]:
            raise ProofError("invalid xtask step")
        name, status = step["name"], step.get("status")
        if name in by_name:
            raise ProofError(f"duplicate xtask step: {name}")
        by_name[name] = step
        if status not in ("ok", "skipped"):
            raise ProofError(f"failed or unknown xtask result: {name}")
        if status == "skipped":
            if not isinstance(step.get("details"), str) or not step["details"].strip():
                raise ProofError(f"xtask skip has no recorded reason: {name}")
            if not any(skip_matches(pattern, name) for pattern in plan["allow_skips"]):
                raise ProofError(f"xtask skip was not accepted in the proof plan: {name}")
    for name in set(plan["required_steps"]) | BASELINE_STEPS:
        if by_name.get(name, {}).get("status") != "ok":
            raise ProofError(f"required successful obligation is absent: {name}")
    details = by_name["detect-changes"].get("details")
    if not isinstance(details, str) or not details.startswith(f"base_ref={subject['base']},"):
        raise ProofError("xtask did not record the explicit invocation base")
    for field, identity, prefix in (
        ("feature_matrix", "features", "feature-matrix"),
        ("bdd_matrix", "feature_set", "bdd-matrix"),
    ):
        entries = receipt.get(field)
        if not isinstance(entries, list):
            raise ProofError(f"raw receipt lacks {field}")
        seen: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get(identity), str):
                raise ProofError(f"invalid {field} entry")
            label, status = entry[identity], entry.get("status")
            if label in seen or status not in ("ok", "skipped"):
                raise ProofError(f"duplicate, failed or unknown {field} result")
            seen.add(label)
            corresponding = by_name.get(f"{prefix}:{label}", by_name.get(prefix, {}))
            if corresponding.get("status") != status:
                raise ProofError(f"{field} result has no corresponding executed/skipped step")
        for name in by_name:
            if name.startswith(f"{prefix}:") and name[len(prefix) + 1:] not in seen:
                raise ProofError(f"{name} step has no corresponding matrix result")
            if name == prefix and not entries:
                raise ProofError(f"{name} step has no corresponding matrix results")
    if plan["profile"] == "product":
        behavioral = any(
            by_name.get(name, {}).get("status") == "ok"
            and (name.startswith("test:") or name in {"tests", "bdd", "root-tests", "xtask-tests"})
            for name in plan["required_steps"]
        )
        if not behavioral and not any(item["kind"] in {"product", "fuzz"} for item in plan["focused"]):
            raise ProofError("product changes require actual declared behavioral proof")
    return receipt

def expected_commands(plan: dict[str, Any]) -> list[tuple[str, list[str]]]:
    return [(f"focused:{item['name']}", item["command"]) for item in plan["focused"]] + [
        ("xtask-pr", PR_COMMAND)
    ]

def validate_envelope(data: bytes) -> dict[str, Any]:
    envelope = json_object(data)
    if envelope.get("kind") != KIND:
        raise ProofError("bare xtask receipts are not seals; use --run --base SHA --plan FILE")
    if envelope.get("conclusion") != "success":
        raise ProofError("development invocation is incomplete or unsuccessful")
    exact_keys(envelope, {
        "schema_version", "kind", "invocation_id", "subject", "started_at_ms",
        "finished_at_ms", "conclusion", "plan", "xtask_receipt", "outcomes", "classification",
    })
    if type(envelope["schema_version"]) is not int or envelope["schema_version"] != SCHEMA_VERSION:
        raise ProofError("development proof schema_version must be 1")
    require_sha(envelope["invocation_id"], 32)
    subject = envelope["subject"]
    exact_keys(subject, {"head", "tree", "base"})
    for digest in subject.values():
        require_sha(digest)
    start, end = envelope["started_at_ms"], envelope["finished_at_ms"]
    if type(start) is not int or type(end) is not int or not 0 < start <= end:
        raise ProofError("invocation timestamps are incomplete or reversed")
    exact_keys(envelope["plan"], {"sha256", "toml"})
    exact_keys(envelope["xtask_receipt"], {"sha256", "utf8"})
    for field, text_field in (("plan", "toml"), ("xtask_receipt", "utf8")):
        record = envelope[field]
        if not isinstance(record[text_field], str):
            raise ProofError(f"{field} is not UTF-8 text")
        if sha256(record[text_field].encode("utf-8")) != require_sha(record["sha256"], 64):
            raise ProofError(f"{field} digest mismatch")
    plan = parse_plan(envelope["plan"]["toml"].encode("utf-8"))
    classification = envelope["classification"]
    exact_keys(classification, {"changed_paths", "classes", "profile"})
    if (
        not isinstance(classification["changed_paths"], list) or not classification["changed_paths"]
        or any(not isinstance(path, str) or not path for path in classification["changed_paths"])
        or not isinstance(classification["classes"], list) or not classification["classes"]
        or any(kind not in ("product", "docs", "control", "fuzz") for kind in classification["classes"])
        or set(classification["classes"]) - {"product", "docs", "control", "fuzz"}
        or sorted(set(classification["classes"])) != classification["classes"]
        or sorted(set(classification["changed_paths"])) != classification["changed_paths"]
    ):
        raise ProofError("invalid changed-path classification")
    if classify_paths(classification["changed_paths"]) != classification:
        raise ProofError("declared classification does not match its changed paths")
    validate_profile(plan, classification)
    outcomes = envelope["outcomes"]
    commands = expected_commands(plan)
    if not isinstance(outcomes, list) or len(outcomes) != len(commands):
        raise ProofError("invocation lacks declared command outcomes")
    previous_end = start
    for result, (name, command) in zip(outcomes, commands):
        exact_keys(result, {"name", "command", "started_at_ms", "finished_at_ms", "return_code"})
        begin, finish = result["started_at_ms"], result["finished_at_ms"]
        if result["name"] != name or result["command"] != command:
            raise ProofError("command outcome differs from the proof plan")
        if type(result["return_code"]) is not int or result["return_code"] != 0:
            raise ProofError(f"command did not succeed: {name}")
        if type(begin) is not int or type(finish) is not int or not previous_end <= begin <= finish <= end:
            raise ProofError("command outcomes are incomplete, overlapping or out of order")
        previous_end = finish
    pr = outcomes[-1]
    validate_xtask(
        envelope["xtask_receipt"]["utf8"].encode("utf-8"), subject, plan,
        pr["started_at_ms"], pr["finished_at_ms"],
    )
    return envelope

def encode(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
