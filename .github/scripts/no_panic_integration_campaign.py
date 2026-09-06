#!/usr/bin/env python3
"""Bounded integration-test no-panic campaign helper.

This script is intentionally branch-local control-plane code. It ranks only
single-file integration-test owners, rewrites only attributed test bodies, and
compares the refusing baseline by semantic identity rather than by summary
counts alone.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from typing import Iterable


PANIC_FAMILIES = {"unwrap", "expect"}


def load_toml(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def git_show_toml(ref: str, path: str) -> dict:
    text = subprocess.check_output(["git", "show", f"{ref}:{path}"], text=True)
    return tomllib.loads(text)


def identities(document: dict) -> dict[tuple[str, str, str, str, str], int]:
    return {
        (
            row["path"],
            row["family"],
            row["selector_kind"],
            row["selector_callee"],
            row["snippet"],
        ): int(row["count"])
        for row in document.get("entry", [])
    }


def rank_candidates(output: Path, minimum: int) -> None:
    proposal_path = Path("target/policy-proposed/no-panic-proposed-allowlist.toml")
    proposal = load_toml(proposal_path)
    counts: Counter[str] = Counter()
    families: defaultdict[str, set[str]] = defaultdict(set)
    for row in proposal.get("allow", []):
        count = int(row.get("count", 1))
        path = row["path"]
        counts[path] += count
        families[path].add(row["family"])

    candidates: list[dict] = []
    for path, findings in counts.items():
        parts = Path(path).parts
        if len(parts) != 4 or parts[0] != "crates" or parts[2] != "tests":
            continue
        if not path.endswith(".rs") or findings < minimum:
            continue
        if not families[path].issubset(PANIC_FAMILIES):
            continue
        source = Path(path)
        manifest = Path(parts[0]) / parts[1] / "Cargo.toml"
        if not source.is_file() or not manifest.is_file():
            continue
        source_text = source.read_text(encoding="utf-8")
        manifest_text = manifest.read_text(encoding="utf-8")
        if "uselesskey-test-support" not in manifest_text:
            continue
        if "TestResult" in source_text or "trait TestContext" in source_text:
            continue
        if any(marker in source_text for marker in ("#[tokio::test", "#[rstest", "#[proptest")):
            continue
        if "#[test]" not in source_text:
            continue
        candidates.append(
            {
                "path": path,
                "findings": findings,
                "families": sorted(families[path]),
                "crate_dir": str(Path(parts[0]) / parts[1]),
                "test_target": Path(path).stem,
            }
        )

    candidates.sort(key=lambda row: (-row["findings"], row["path"]))
    output.write_text(json.dumps(candidates, indent=2) + "\n", encoding="utf-8")
    for row in candidates[:30]:
        print(f"{row['findings']:4d} {row['path']}")


def skip_non_code(text: str, index: int) -> int | None:
    length = len(text)
    if text.startswith("//", index):
        end = text.find("\n", index + 2)
        return length if end < 0 else end + 1
    if text.startswith("/*", index):
        depth = 1
        cursor = index + 2
        while cursor < length and depth:
            if text.startswith("/*", cursor):
                depth += 1
                cursor += 2
            elif text.startswith("*/", cursor):
                depth -= 1
                cursor += 2
            else:
                cursor += 1
        if depth:
            raise ValueError("unterminated block comment")
        return cursor
    raw = re.match(r'(?:b?r)(?P<hashes>#{0,16})"', text[index:])
    if raw:
        delimiter = '"' + raw.group("hashes")
        end = text.find(delimiter, index + raw.end())
        if end < 0:
            raise ValueError("unterminated raw string")
        return end + len(delimiter)
    if text.startswith('b"', index) or text[index : index + 1] == '"':
        cursor = index + (2 if text.startswith('b"', index) else 1)
        while cursor < length:
            if text[cursor] == "\\":
                cursor += 2
                continue
            if text[cursor] == '"':
                return cursor + 1
            cursor += 1
        raise ValueError("unterminated string")
    if text[index : index + 1] == "'" and index + 2 < length:
        cursor = index + 1
        cursor += 2 if text[cursor] == "\\" else 1
        if cursor < length and text[cursor] == "'":
            return cursor + 1
    return None


def matching_brace(text: str, opening: int) -> int:
    depth = 0
    cursor = opening
    while cursor < len(text):
        skipped = skip_non_code(text, cursor)
        if skipped is not None:
            cursor = skipped
            continue
        if text[cursor] == "{":
            depth += 1
        elif text[cursor] == "}":
            depth -= 1
            if depth == 0:
                return cursor
        cursor += 1
    raise ValueError("unmatched function brace")


def quoted_argument(text: str, start: int) -> tuple[int, str] | None:
    cursor = start
    while cursor < len(text) and text[cursor].isspace():
        cursor += 1
    literal_start = cursor
    if text.startswith('b"', cursor):
        cursor += 1
    if cursor >= len(text) or text[cursor] != '"':
        return None
    cursor += 1
    while cursor < len(text):
        if text[cursor] == "\\":
            cursor += 2
            continue
        if text[cursor] == '"':
            literal_end = cursor + 1
            end = literal_end
            while end < len(text) and text[end].isspace():
                end += 1
            if end < len(text) and text[end] == ")":
                return end + 1, text[literal_start:literal_end]
            return None
        cursor += 1
    return None


def rewrite_body(body: str) -> tuple[str, int]:
    edits: list[tuple[int, int, str]] = []
    cursor = 0
    while cursor < len(body):
        skipped = skip_non_code(body, cursor)
        if skipped is not None:
            cursor = skipped
            continue

        if body.startswith(".unwrap_err()", cursor):
            edits.append(
                (
                    cursor,
                    cursor + len(".unwrap_err()"),
                    '.err().test_context("expected error")?',
                )
            )
            cursor += len(".unwrap_err()")
            continue
        if body.startswith(".unwrap()", cursor):
            prefix = body[:cursor].rstrip()
            replacement = '.test_context("test operation")?'
            if prefix.endswith(".join()"):
                replacement = '.ok().test_context("worker thread completed")?'
            edits.append((cursor, cursor + len(".unwrap()"), replacement))
            cursor += len(".unwrap()")
            continue

        matched = False
        for method, error_variant in ((".expect_err(", True), (".expect(", False)):
            if not body.startswith(method, cursor):
                continue
            parsed = quoted_argument(body, cursor + len(method))
            if parsed is None:
                raise ValueError(f"unsupported non-literal {method}")
            end, literal = parsed
            replacement = (
                f".err().test_context({literal})?"
                if error_variant
                else f".test_context({literal})?"
            )
            edits.append((cursor, end, replacement))
            cursor = end
            matched = True
            break
        if matched:
            continue
        cursor += 1

    result = body
    for start, end, replacement in reversed(edits):
        result = result[:start] + replacement + result[end:]
    return result, len(edits)


@dataclass(frozen=True)
class TestFunction:
    attributes_start: int
    brace_open: int
    brace_close: int
    name: str


def locate_plain_tests(source: str) -> list[TestFunction]:
    pattern = re.compile(
        r"(?m)(?P<attrs>(?:^[ \t]*#\[[^\n]+\][ \t]*\n)+)"
        r"(?P<indent>^[ \t]*)fn[ \t]+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
        r"[ \t]*\([ \t]*\)[ \t]*\{"
    )
    tests: list[TestFunction] = []
    for match in pattern.finditer(source):
        if "#[test]" not in match.group("attrs"):
            continue
        brace_open = source.find("{", match.end("name"))
        header = source[match.start("attrs") : brace_open]
        if "->" in header:
            continue
        tests.append(
            TestFunction(
                attributes_start=match.start("attrs"),
                brace_open=brace_open,
                brace_close=matching_brace(source, brace_open),
                name=match.group("name"),
            )
        )
    return tests


def insert_helper(source: str) -> str:
    helper = """use uselesskey_test_support::{TestResult, require_ok, require_some};

trait TestContext<T> {
    fn test_context(self, message: impl core::fmt::Display) -> TestResult<T>;
}

impl<T, E: core::fmt::Display> TestContext<T> for core::result::Result<T, E> {
    fn test_context(self, message: impl core::fmt::Display) -> TestResult<T> {
        require_ok(self, message)
    }
}

impl<T> TestContext<T> for core::option::Option<T> {
    fn test_context(self, message: impl core::fmt::Display) -> TestResult<T> {
        require_some(self, message)
    }
}

"""
    lines = source.splitlines(keepends=True)
    insert_at = 0
    while insert_at < len(lines):
        stripped = lines[insert_at].strip()
        if stripped.startswith("//!") or stripped.startswith("#!") or stripped == "":
            insert_at += 1
            continue
        break
    return "".join(lines[:insert_at]) + helper + "".join(lines[insert_at:])


def transform(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    tests = locate_plain_tests(source)
    if not tests:
        raise SystemExit("no supported plain test functions")

    result = source
    transformed = 0
    calls = 0
    for test in reversed(tests):
        body = result[test.brace_open + 1 : test.brace_close]
        try:
            rewritten, edits = rewrite_body(body)
        except ValueError:
            continue
        if edits == 0:
            continue
        if not rewritten.rstrip().endswith("Ok(())"):
            rewritten = rewritten.rstrip() + "\n    Ok(())\n"
        header = result[test.attributes_start : test.brace_open].rstrip()
        replacement = header + " -> TestResult<()> {" + rewritten + "}"
        result = (
            result[: test.attributes_start]
            + replacement
            + result[test.brace_close + 1 :]
        )
        transformed += 1
        calls += edits

    if transformed == 0:
        raise SystemExit("no test body could be converted")
    result = insert_helper(result)
    if result == source:
        raise SystemExit("conversion produced no source change")
    path.write_text(result, encoding="utf-8")
    print(json.dumps({"path": str(path), "tests": transformed, "calls": calls}))


def check_baseline(before_ref: str, path: str, expected: int | None) -> None:
    baseline_path = "policy/no-panic-baseline.toml"
    before = git_show_toml(before_ref, baseline_path)
    after = load_toml(Path(baseline_path))
    old = identities(before)
    new = identities(after)

    added = sorted(set(new) - set(old))
    increased = sorted(key for key in set(old) & set(new) if new[key] > old[key])
    if added or increased:
        raise SystemExit(
            f"refusing refresh regression: added={added[:3]} increased={increased[:3]}"
        )

    removed_by_key = {
        key: old[key] - new.get(key, 0)
        for key in old
        if old[key] > new.get(key, 0)
    }
    foreign = {key: count for key, count in removed_by_key.items() if key[0] != path}
    if foreign:
        raise SystemExit(f"refresh removed foreign identities: {list(foreign.items())[:3]}")
    removed = sum(removed_by_key.values())
    if removed <= 0:
        raise SystemExit("baseline did not decrease")
    if expected is not None and removed != expected:
        raise SystemExit(f"expected {expected} removed findings, observed {removed}")
    if any(key[0] == path for key in new):
        raise SystemExit(f"{path} remains represented after the integration-owner conversion")

    payload = {
        "path": path,
        "before": int(before["summary"]["total"]),
        "after": int(after["summary"]["total"]),
        "removed": removed,
        "added_identities": 0,
        "increased_identities": 0,
        "foreign_removed_identities": 0,
    }
    print(json.dumps(payload))


def package_name(manifest: Path) -> str:
    document = tomllib.loads(manifest.read_text(encoding="utf-8"))
    print(document["package"]["name"])
    return document["package"]["name"]


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    rank = subparsers.add_parser("rank")
    rank.add_argument("--output", type=Path, required=True)
    rank.add_argument("--minimum", type=int, default=3)

    convert = subparsers.add_parser("transform")
    convert.add_argument("--path", type=Path, required=True)

    check = subparsers.add_parser("check-baseline")
    check.add_argument("--before-ref", required=True)
    check.add_argument("--path", required=True)
    check.add_argument("--expected", type=int)

    package = subparsers.add_parser("package")
    package.add_argument("--manifest", type=Path, required=True)

    args = parser.parse_args(argv)
    if args.command == "rank":
        rank_candidates(args.output, args.minimum)
    elif args.command == "transform":
        transform(args.path)
    elif args.command == "check-baseline":
        check_baseline(args.before_ref, args.path, args.expected)
    elif args.command == "package":
        package_name(args.manifest)
    else:
        parser.error(f"unknown command {args.command}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
