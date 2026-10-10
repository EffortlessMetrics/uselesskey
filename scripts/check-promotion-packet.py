#!/usr/bin/env python3
"""Validate the exact-head promotion packet used by Uselesskey Ready admission."""

from __future__ import annotations

import argparse
import os
import re
import sys
import textwrap
import tomllib
from pathlib import Path
from typing import Any

START_MARKER = "<!-- uselesskey-promotion:v1 -->"
END_MARKER = "<!-- /uselesskey-promotion:v1 -->"
FENCE_RE = re.compile(r"```toml\s*(.*?)\s*```", re.DOTALL)
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

ALLOWED_SOURCE_REPOSITORIES = {
    "EffortlessMetrics/uselesskey-swarm",
    "uselesskey/uselesskey-swarm",
}

REQUIRED_FIELDS = {
    "schema_version",
    "promotion_head",
    "review_disposition",
    "known_blockers",
    "development",
}

DEVELOPMENT_FIELDS = {
    "repository",
    "pr",
    "head",
    "proof_head",
    "proof_receipt_sha256",
}


class PacketError(ValueError):
    """Promotion packet failed a bounded contract check."""


def _require_exact_keys(
    packet: dict[str, Any], required: set[str], *, context: str
) -> None:
    present = set(packet)
    missing = sorted(required - present)
    unknown = sorted(present - required)
    problems: list[str] = []
    if missing:
        problems.append(f"missing fields: {', '.join(missing)}")
    if unknown:
        problems.append(f"unknown fields: {', '.join(unknown)}")
    if problems:
        raise PacketError(f"{context}: {'; '.join(problems)}")


def _require_string(packet: dict[str, Any], name: str, *, context: str) -> str:
    value = packet[name]
    if not isinstance(value, str):
        raise PacketError(f"{context}.{name} must be a string")
    return value


def _require_sha40(packet: dict[str, Any], name: str, *, context: str) -> str:
    value = _require_string(packet, name, context=context)
    if not SHA40_RE.fullmatch(value):
        raise PacketError(
            f"{context}.{name} must be a lowercase 40-character Git SHA"
        )
    return value


def _extract_packet(body: str) -> dict[str, Any]:
    if body.count(START_MARKER) != 1:
        raise PacketError(f"expected exactly one {START_MARKER} marker")
    if body.count(END_MARKER) != 1:
        raise PacketError(f"expected exactly one {END_MARKER} marker")

    start = body.index(START_MARKER) + len(START_MARKER)
    end = body.index(END_MARKER)
    if end <= start:
        raise PacketError("promotion packet end marker appears before its start marker")

    packet_region = body[start:end]
    fenced_blocks = FENCE_RE.findall(packet_region)
    if len(fenced_blocks) != 1:
        raise PacketError("promotion packet must contain exactly one fenced TOML block")

    try:
        parsed = tomllib.loads(fenced_blocks[0])
    except tomllib.TOMLDecodeError as exc:
        raise PacketError(f"promotion packet TOML is invalid: {exc}") from exc

    if not isinstance(parsed, dict):
        raise PacketError("promotion packet TOML must decode to a table")
    return parsed


def _validate_development(entry: Any, index: int) -> dict[str, Any]:
    context = f"development[{index}]"
    if not isinstance(entry, dict):
        raise PacketError(f"{context} must be a TOML table")
    _require_exact_keys(entry, DEVELOPMENT_FIELDS, context=context)

    repository = _require_string(entry, "repository", context=context)
    if repository not in ALLOWED_SOURCE_REPOSITORIES:
        allowed = ", ".join(sorted(ALLOWED_SOURCE_REPOSITORIES))
        raise PacketError(f"{context}.repository must be one of: {allowed}")

    pr = entry["pr"]
    if type(pr) is not int or pr <= 0:
        raise PacketError(f"{context}.pr must be a positive integer")

    head = _require_sha40(entry, "head", context=context)
    proof_head = _require_sha40(entry, "proof_head", context=context)
    if proof_head != head:
        raise PacketError(f"{context}.proof_head must equal {context}.head")

    proof_receipt = _require_string(
        entry, "proof_receipt_sha256", context=context
    )
    if not SHA256_RE.fullmatch(proof_receipt):
        raise PacketError(
            f"{context}.proof_receipt_sha256 must be a lowercase "
            "64-character SHA-256 digest"
        )

    return entry


def validate_packet(body: str, expected_head: str | None = None) -> dict[str, Any]:
    """Validate one promotion packet and return the parsed bounded fields."""
    packet = _extract_packet(body)
    _require_exact_keys(packet, REQUIRED_FIELDS, context="packet")

    if type(packet["schema_version"]) is not int or packet["schema_version"] != 1:
        raise PacketError("packet.schema_version must be integer 1")

    promotion_head = _require_sha40(packet, "promotion_head", context="packet")
    if expected_head is not None:
        if not SHA40_RE.fullmatch(expected_head):
            raise PacketError("expected head must be a lowercase 40-character Git SHA")
        if promotion_head != expected_head:
            raise PacketError(
                f"packet.promotion_head {promotion_head} does not match "
                f"exact PR head {expected_head}"
            )

    disposition = _require_string(
        packet, "review_disposition", context="packet"
    )
    if disposition != "complete":
        raise PacketError('packet.review_disposition must be exactly "complete"')

    blockers = packet["known_blockers"]
    if not isinstance(blockers, list) or any(
        not isinstance(item, str) for item in blockers
    ):
        raise PacketError("packet.known_blockers must be an array of strings")
    if blockers:
        raise PacketError("packet.known_blockers must be empty before Ready")

    development = packet["development"]
    if not isinstance(development, list) or not development:
        raise PacketError("packet.development must contain at least one table")
    if len(development) > 50:
        raise PacketError("packet.development may contain at most 50 tables")

    seen: set[tuple[str, int]] = set()
    validated: list[dict[str, Any]] = []
    for index, entry in enumerate(development):
        item = _validate_development(entry, index)
        identity = (item["repository"], item["pr"])
        if identity in seen:
            raise PacketError(
                f"duplicate development PR: {identity[0]}#{identity[1]}"
            )
        seen.add(identity)
        validated.append(item)

    packet["development"] = validated
    return packet


def _development_block(
    *,
    repository: str,
    pr: int,
    head: str,
    proof_head: str,
    receipt: str,
    extra: str = "",
) -> str:
    return textwrap.dedent(
        f"""\
        [[development]]
        repository = "{repository}"
        pr = {pr}
        head = "{head}"
        proof_head = "{proof_head}"
        proof_receipt_sha256 = "{receipt}"
        {extra}
        """
    )


def _render_packet(
    *,
    promotion_head: str,
    developments: list[str],
    blockers: list[str] | None = None,
    top_extra: str = "",
) -> str:
    blocker_text = ", ".join(f'"{item}"' for item in (blockers or []))
    development_text = "\n".join(developments)
    return textwrap.dedent(
        f"""\
        ## Promotion packet

        {START_MARKER}
        ```toml
        schema_version = 1
        promotion_head = "{promotion_head}"
        review_disposition = "complete"
        known_blockers = [{blocker_text}]
        {top_extra}

        {development_text}
        ```
        {END_MARKER}
        """
    )


def self_test() -> None:
    first_head = "a" * 40
    second_head = "b" * 40
    promotion_head = "c" * 40
    first = _development_block(
        repository="uselesskey/uselesskey-swarm",
        pr=42,
        head=first_head,
        proof_head=first_head,
        receipt="d" * 64,
    )
    second = _development_block(
        repository="EffortlessMetrics/uselesskey-swarm",
        pr=43,
        head=second_head,
        proof_head=second_head,
        receipt="e" * 64,
    )
    valid = _render_packet(
        promotion_head=promotion_head,
        developments=[first, second],
    )
    validate_packet(valid, expected_head=promotion_head)

    rejected = {
        "missing marker": valid.replace(START_MARKER, ""),
        "stale promotion head": valid.replace(
            f'promotion_head = "{promotion_head}"',
            f'promotion_head = "{"f" * 40}"',
        ),
        "proof drift": valid.replace(
            f'proof_head = "{first_head}"',
            f'proof_head = "{"1" * 40}"',
            1,
        ),
        "known blocker": _render_packet(
            promotion_head=promotion_head,
            developments=[first],
            blockers=["integration proof is red"],
        ),
        "unknown top-level field": _render_packet(
            promotion_head=promotion_head,
            developments=[first],
            top_extra="unreviewed_override = true",
        ),
        "unknown development field": _render_packet(
            promotion_head=promotion_head,
            developments=[
                _development_block(
                    repository="uselesskey/uselesskey-swarm",
                    pr=42,
                    head=first_head,
                    proof_head=first_head,
                    receipt="d" * 64,
                    extra="unreviewed_override = true",
                )
            ],
        ),
        "duplicate development PR": _render_packet(
            promotion_head=promotion_head,
            developments=[first, first],
        ),
        "no development PR": _render_packet(
            promotion_head=promotion_head,
            developments=[],
        ),
    }
    for name, body in rejected.items():
        try:
            validate_packet(body, expected_head=promotion_head)
        except PacketError:
            continue
        raise AssertionError(f"self-test case unexpectedly passed: {name}")

    print(f"promotion packet self-test: ok ({1 + len(rejected)} cases)")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--body-file", help="Read the pull-request body from this file.")
    source.add_argument(
        "--body-env", help="Read the pull-request body from this environment variable."
    )
    source.add_argument(
        "--self-test", action="store_true", help="Run built-in accept/reject cases."
    )
    parser.add_argument(
        "--expected-head",
        help="Require promotion_head to equal this exact pull-request head SHA.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.self_test:
            self_test()
            return 0

        if args.body_file:
            body = Path(args.body_file).read_text(encoding="utf-8")
        else:
            body = os.environ.get(args.body_env)
            if body is None:
                raise PacketError(
                    f"environment variable {args.body_env!r} is not present"
                )

        packet = validate_packet(body, expected_head=args.expected_head)
        identities = ", ".join(
            f"{entry['repository']}#{entry['pr']}@{entry['head']}"
            for entry in packet["development"]
        )
        print(
            "promotion packet: ok "
            f"(development=[{identities}] "
            f"promotion_head={packet['promotion_head']})"
        )
        return 0
    except (OSError, UnicodeError, PacketError) as exc:
        print(f"promotion packet: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
