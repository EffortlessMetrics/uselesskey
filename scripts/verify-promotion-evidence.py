#!/usr/bin/env python3
"""Read-only promotion evidence verification; does not grant check or merge authority.

The manifest is an operator-controlled acceptance input, outside candidate authority.
This tool verifies live GitHub facts and immutable receipt bytes. It cannot establish
that an operator really made the recorded judgment or that arbitrary code executed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CANONICAL_ID = 1148729677
DEVELOPMENT_ID = 1243900627
TARGET_BRANCH = "main"
REPOSITORIES = {
    "EffortlessMetrics/uselesskey": CANONICAL_ID,
    "uselesskey/uselesskey": CANONICAL_ID,
    "EffortlessMetrics/uselesskey-swarm": DEVELOPMENT_ID,
    "uselesskey/uselesskey-swarm": DEVELOPMENT_ID,
}
LIMIT = 2 * 1024 * 1024
MAX_PAGES = 10
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class EvidenceError(ValueError):
    """A required fact is absent, inconsistent, or outside the bounded contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def sha(value: Any) -> str:
    require(isinstance(value, str) and bool(SHA.fullmatch(value)) and value != "0" * 40,
            "expected a nonzero full Git SHA")
    return value


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exact_keys(value: Any, required: set[str], optional: set[str] = frozenset()) -> None:
    require(isinstance(value, dict), "expected an evidence object")
    require(not (set(value) - required - optional) and not (required - set(value)),
            "unknown or missing evidence fields")


def body_digest(pr: dict[str, Any]) -> str:
    body = pr.get("body")
    require(body is None or isinstance(body, str), "PR body is not text")
    return digest((body or "").encode())


def pr_identity(pr: dict[str, Any]) -> dict[str, Any]:
    return {key: pr.get(key) for key in (
        "number", "state", "draft", "merged", "body", "merge_commit_sha", "changed_files"
    )} | {"head": {"sha": pr.get("head", {}).get("sha"),
                    "ref": pr.get("head", {}).get("ref"),
                    "repository_id": (pr.get("head", {}).get("repo") or {}).get("id")},
           "base": {"sha": pr.get("base", {}).get("sha"),
                    "ref": pr.get("base", {}).get("ref"),
                    "repository_id": (pr.get("base", {}).get("repo") or {}).get("id")}}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON field: {key}")
        result[key] = value
    return result


def invalid_constant(value):
    raise EvidenceError(f"non-finite JSON value: {value}")


def json_object(data: bytes) -> dict[str, Any]:
    require(len(data) <= LIMIT, "JSON exceeds bounded input size")
    try:
        value = json.loads(data, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    except (ValueError, UnicodeError) as exc:
        raise EvidenceError("invalid JSON input") from exc
    require(isinstance(value, dict), "expected a JSON object")
    return value


class GitHubReader:
    """Fixed-host, read-only REST and GraphQL reader. Never logs the token."""

    def __init__(self, token: str):
        require(bool(token), "GITHUB_TOKEN is required for live review-thread readback")
        self.token = token
        self.deadline = time.monotonic() + 300
        self.remaining_requests = 512

    def request(self, path: str, payload: dict[str, Any] | None = None) -> Any:
        require(path.startswith("/") and not path.startswith("//"), "invalid API path")
        require(self.remaining_requests > 0 and time.monotonic() < self.deadline,
                "live observation budget exhausted; retry with a smaller accepted candidate")
        self.remaining_requests -= 1
        body = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            "https://api.github.com" + path,
            data=body,
            headers={"Authorization": "Bearer " + self.token,
                     "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28",
                     "Content-Type": "application/json"},
        )
        # Refuse redirects rather than forwarding credentials to another host.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
                raw = response.read(LIMIT + 1)
        except (urllib.error.URLError, OSError) as exc:
            code = getattr(exc, "code", "unavailable")
            raise EvidenceError(f"GitHub read failed ({code}); no absence inferred") from exc
        require(len(raw) <= LIMIT, "GitHub response exceeds bounded input size")
        try:
            return json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)
        except (ValueError, UnicodeError) as exc:
            raise EvidenceError("GitHub returned invalid JSON") from exc

    def get(self, path: str) -> Any:
        return self.request(path)

    def pages(self, path: str) -> list[dict[str, Any]]:
        result = []
        for page in range(1, MAX_PAGES + 1):
            items = self.get(f"{path}?per_page=100&page={page}")
            require(isinstance(items, list), "incomplete paginated API response")
            result.extend(items)
            if len(items) < 100:
                return result
        raise EvidenceError("pagination bound reached; completeness unproved")

    def threads(self, repository: str, number: int) -> list[dict[str, Any]]:
        owner, name = repository.split("/")
        query = """query($owner:String!,$name:String!,$number:Int!,$after:String) {
          repository(owner:$owner,name:$name) { pullRequest(number:$number) {
            reviewThreads(first:100,after:$after) {
              nodes { id isResolved isOutdated }
              pageInfo { hasNextPage endCursor }
            }
          } }
        }"""
        result, cursor = [], None
        for _ in range(MAX_PAGES):
            response = self.request("/graphql", {"query": query, "variables": {
                "owner": owner, "name": name, "number": number, "after": cursor}})
            require(isinstance(response, dict) and not response.get("errors"),
                    "review-thread API returned errors")
            try:
                connection = response["data"]["repository"]["pullRequest"]["reviewThreads"]
                nodes, info = connection["nodes"], connection["pageInfo"]
            except (KeyError, TypeError) as exc:
                raise EvidenceError("review-thread response is incomplete") from exc
            require(isinstance(nodes, list) and type(info.get("hasNextPage")) is bool,
                    "review-thread pagination is incomplete")
            result.extend(nodes)
            if not info["hasNextPage"]:
                return result
            next_cursor = info.get("endCursor")
            require(isinstance(next_cursor, str) and next_cursor and next_cursor != cursor,
                    "review-thread pagination did not advance")
            cursor = next_cursor
        raise EvidenceError("review-thread pagination bound reached")


def repository_identity(reader: GitHubReader, repository: str, expected_id: int) -> None:
    require(REPOSITORIES.get(repository) == expected_id, "repository is outside this family")
    current = reader.get(f"/repos/{repository}")
    require(current.get("id") == expected_id and current.get("full_name") == repository,
            "repository identity changed; refresh the accepted manifest")


def review_surface(reader: GitHubReader, repository: str, number: int) -> dict[str, Any]:
    prefix = f"/repos/{repository}"
    surface = {
        "threads": reader.threads(repository, number),
        "reviews": reader.pages(f"{prefix}/pulls/{number}/reviews"),
        "inline_comments": reader.pages(f"{prefix}/pulls/{number}/comments"),
        "discussion": reader.pages(f"{prefix}/issues/{number}/comments"),
    }
    for rows in surface.values():
        require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows),
                "review surface is incomplete")
        require(all(type(row.get("id")) in {int, str} for row in rows),
                "review object identity is missing")
        require(len({row["id"] for row in rows}) == len(rows),
                "duplicate review object across pages")
        rows.sort(key=lambda item: str(item["id"]))
    return surface


def review_digest(surface: dict[str, Any]) -> str:
    return digest(json.dumps(surface, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode())


def check_reviews(reader: GitHubReader, repository: str, number: int,
                  expected_digest: str) -> dict[str, Any]:
    surface = review_surface(reader, repository, number)
    current_digest = review_digest(surface)
    require(current_digest == expected_digest,
            "review surface changed after operator acceptance")
    threads = surface["threads"]
    require(all(thread.get("isResolved") is True for thread in threads),
            "unresolved review thread, including outdated threads")
    # Comments/dismissed reviews do not erase another undismissed verdict.
    latest: dict[int, str] = {}
    require(all(type(review.get("id")) is int for review in surface["reviews"]),
            "review submission identity is invalid")
    for review in sorted(surface["reviews"], key=lambda item: item["id"]):
        state = review.get("state")
        require(state in {"APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED", "PENDING"},
                "unknown review state")
        require(state != "PENDING", "unfinished review")
        actor = review.get("user", {}).get("id")
        require(type(actor) is int, "review actor identity missing")
        if state in {"APPROVED", "CHANGES_REQUESTED"}:
            latest[actor] = state
    require("CHANGES_REQUESTED" not in latest.values(), "current changes-requested review")
    return {"sha256": current_digest, "review_threads": len(threads),
            "current_review_verdicts": latest}


def changed_paths(reader: GitHubReader, repository: str, pr: dict[str, Any]) -> list[str]:
    files = reader.pages(f"/repos/{repository}/pulls/{pr['number']}/files")
    count = pr.get("changed_files")
    require(type(count) is int and count > 0 and len(files) == count,
            "PR file list is absent or incomplete")
    filenames, paths = set(), set()
    for item in files:
        require(isinstance(item, dict), "invalid PR file record")
        path = item.get("filename")
        require(isinstance(path, str) and bool(path) and path not in filenames,
                "missing or duplicate PR filename")
        require(item.get("status") in {"added", "removed", "modified", "renamed", "copied", "changed"},
                "unknown PR file status")
        filenames.add(path)
        paths.add(path)
        if item["status"] == "renamed":
            previous = item.get("previous_filename")
            require(isinstance(previous, str) and bool(previous), "rename origin missing")
            paths.add(previous)
    return sorted(paths)


def comparison_base(reader: GitHubReader, repository: str, base: str, head: str) -> str:
    comparison = reader.get(f"/repos/{repository}/compare/{sha(base)}...{sha(head)}")
    return sha(comparison.get("merge_base_commit", {}).get("sha"))


def proof_bytes(reader: GitHubReader, repository: str, proof: dict[str, Any]) -> bytes:
    blob = sha(proof.get("git_blob"))
    expected_digest = proof.get("sha256")
    require(isinstance(expected_digest, str) and bool(DIGEST.fullmatch(expected_digest)),
            "missing proof SHA-256")
    response = reader.get(f"/repos/{repository}/git/blobs/{blob}")
    require(response.get("sha") == blob and response.get("encoding") == "base64",
            "wrong blob identity or encoding")
    try:
        raw = base64.b64decode("".join(response["content"].split()), validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise EvidenceError("invalid proof blob") from exc
    require(len(raw) <= LIMIT and response.get("size") == len(raw), "proof blob size mismatch")
    require(digest(raw) == expected_digest, "proof receipt SHA-256 mismatch")
    # Verify Git's content-addressed identity independently of the JSON response.
    git_id = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
    require(git_id == blob, "proof Git blob identity mismatch")
    return raw


def verify_development(receipt_bytes: bytes, proof: dict[str, Any], head: str,
                       tree: str, expected_base: str, paths: list[str]) -> None:
    # Vendored, reviewed pure contract; never fetch/import candidate source.
    import development_proof_contract as contract
    try:
        receipt = contract.validate_envelope(receipt_bytes)
    except contract.ProofError as exc:
        raise EvidenceError(f"development receipt rejected: {exc}") from exc
    require(receipt["subject"] == {"head": head, "tree": tree, "base": expected_base},
            "development proof subject mismatch")
    require(receipt["invocation_id"] == proof.get("invocation_id"),
            "development invocation mismatch")
    require(receipt["plan"]["sha256"] == proof.get("plan_sha256"),
            "proof plan does not match accepted plan")
    require(receipt["classification"]["changed_paths"] == paths,
            "development proof does not cover the complete native PR change range")


def verify_proof(reader: GitHubReader, repository: str, proof: dict[str, Any],
                 head: str, tree: str, expected_base: str, paths: list[str]) -> None:
    common = {"kind", "git_blob", "sha256", "invocation_id"}
    if proof.get("kind") == "development":
        exact_keys(proof, common | {"plan_sha256"})
    elif proof.get("kind") == "integration":
        exact_keys(proof, common | {"control_sha256", "policy_sha256"})
    else:
        raise EvidenceError("unknown proof kind")
    raw = proof_bytes(reader, repository, proof)
    receipt = json_object(raw)
    if proof.get("kind") == "development":
        verify_development(raw, proof, head, tree, expected_base, paths)
    elif proof.get("kind") == "integration":
        path = Path(__file__).with_name("run-integration-proof.py")
        spec = importlib.util.spec_from_file_location("integration_proof_control", path)
        require(spec is not None and spec.loader is not None, "integration control missing")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        try:
            module.verify_receipt(receipt, expected_sha=head,
                invocation_id=proof["invocation_id"],
                expected_control_sha256=proof["control_sha256"],
                expected_policy_sha256=proof["policy_sha256"],
                subject_kind="manual", expected_base=expected_base)
        except (module.ProofError, AttributeError, KeyError, ValueError) as exc:
            raise EvidenceError(f"integration receipt rejected: {exc}") from exc
        require(receipt["source"]["before"]["tree"] == tree,
                "integration receipt tree differs from live Git subject")
    else:
        raise EvidenceError("unknown proof kind")


def maintenance_path(path: str) -> bool:
    return (path in {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml"}
            or path.startswith((".github/", "scripts/", "policy/", "docs/ci/", "docs/release/"))
            or bool(re.fullmatch(r"crates/[^/]+/Cargo.toml", path)))


def verify_manifest(reader: GitHubReader, manifest: dict[str, Any], repository: str,
                    number: int, expected_head: str, expected_base: str,
                    *, now_ms: int | None = None) -> dict[str, Any]:
    head, base = sha(expected_head), sha(expected_base)
    require(type(number) is int and number > 0, "invalid promotion PR number")
    exact_keys(manifest, {
        "schema_version", "kind", "profile", "repository_id", "pull_request", "head", "base",
        "body_sha256", "review_sha256", "accepted_at_ms", "operator_acceptance",
        "promotion_proof", "development",
    }, {"accepted_paths"})
    require(type(manifest.get("schema_version")) is int and manifest["schema_version"] == 1 and manifest.get("kind") ==
            "uselesskey-promotion-evidence", "unsupported evidence manifest")
    require(type(manifest.get("repository_id")) is int and manifest["repository_id"] == CANONICAL_ID and
            type(manifest.get("pull_request")) is int and manifest["pull_request"] == number and manifest.get("head") == head
            and manifest.get("base") == base, "accepted promotion identity mismatch")
    now = int(time.time() * 1000) if now_ms is None else now_ms
    accepted = manifest.get("accepted_at_ms")
    require(type(accepted) is int and 0 < accepted <= now,
            "operator acceptance timestamp is missing or future-dated")
    decision = manifest.get("operator_acceptance", {})
    exact_keys(decision, {"review_disposition", "known_blockers", "composition_reviewed",
                          "plans_reviewed", "actor", "evidence"})
    require(decision.get("review_disposition") == "complete" and
            decision.get("known_blockers") == [] and decision.get("composition_reviewed") is True
            and decision.get("plans_reviewed") is True
            and isinstance(decision.get("actor"), str) and bool(decision["actor"].strip())
            and isinstance(decision.get("evidence"), list) and bool(decision["evidence"])
            and all(isinstance(item, str) and item.strip() for item in decision["evidence"]),
            "missing explicit operator acceptance of review, plan, and composition")
    repository_identity(reader, repository, CANONICAL_ID)
    prefix = f"/repos/{repository}/pulls/{number}"
    promotion = reader.get(prefix)
    require(promotion.get("number") == number and promotion.get("state") == "open"
            and promotion.get("draft") is False and promotion.get("merged") is False,
            "promotion is not an open Ready candidate")
    require(promotion.get("head", {}).get("sha") == head and
            promotion.get("base", {}).get("sha") == base and
            promotion["base"].get("ref") == TARGET_BRANCH and
            promotion["head"].get("repo", {}).get("id") == CANONICAL_ID and
            promotion["base"].get("repo", {}).get("id") == CANONICAL_ID,
            "live promotion head/base/repository mismatch")
    require(body_digest(promotion) == manifest.get("body_sha256"),
            "accepted PR body changed")
    commit = reader.get(f"/repos/{repository}/commits/{head}")
    require(commit.get("sha") == head, "promotion commit does not exist")
    tree = sha(commit.get("commit", {}).get("tree", {}).get("sha"))
    require(comparison_base(reader, repository, base, head) == base,
            "canonical candidate does not include the accepted current base")
    promotion_paths = changed_paths(reader, repository, promotion)
    reviews = check_reviews(reader, repository, number, manifest["review_sha256"])
    verify_proof(reader, repository, manifest["promotion_proof"], head, tree, base, promotion_paths)
    developments = manifest.get("development")
    require(isinstance(developments, list) and len(developments) <= 50,
            "development list is missing or exceeds bound")
    profile = manifest.get("profile")
    if profile == "canonical-maintenance":
        require(not developments, "maintenance may not smuggle development provenance")
        require(promotion_paths == manifest.get("accepted_paths") and
                all(maintenance_path(path) for path in promotion_paths),
                "canonical maintenance path set is not accepted or exceeds scope")
    else:
        require(profile == "development-promotion" and bool(developments),
                "development promotion requires accepted source work")
    identities = set()
    source_prs = {}
    for entry in developments:
        exact_keys(entry, {"repository", "pr", "head", "base", "pr_base", "body_sha256",
                           "review_sha256", "proof"})
        repo, pr, source_head = entry["repository"], entry["pr"], sha(entry["head"])
        require(type(pr) is int and pr > 0 and (repo, pr) not in identities,
                "invalid or duplicate development identity")
        identities.add((repo, pr))
        repository_identity(reader, repo, DEVELOPMENT_ID)
        source = reader.get(f"/repos/{repo}/pulls/{pr}")
        source_prs[(repo, pr)] = pr_identity(source)
        require(source.get("number") == pr and source.get("merged") is True and
                source.get("state") == "closed" and source.get("head", {}).get("sha") == source_head
                and source.get("base", {}).get("ref") == TARGET_BRANCH
                and source.get("base", {}).get("repo", {}).get("id") == DEVELOPMENT_ID,
                "development PR is absent, unmerged, or at a different subject")
        require(source.get("base", {}).get("sha") == sha(entry["pr_base"]),
                "development PR base differs from accepted native range")
        require(body_digest(source) == entry["body_sha256"],
                "accepted development PR body changed")
        source_commit = reader.get(f"/repos/{repo}/commits/{source_head}")
        require(source_commit.get("sha") == source_head, "source commit is absent")
        source_tree = sha(source_commit.get("commit", {}).get("tree", {}).get("sha"))
        source_base = sha(entry["base"])
        base_commit = reader.get(f"/repos/{repo}/commits/{source_base}")
        require(base_commit.get("sha") == source_base, "development proof base is absent")
        require(comparison_base(reader, repo, entry["pr_base"], source_head) == source_base,
                "development proof base is not the native PR comparison base")
        source_paths = changed_paths(reader, repo, source)
        check_reviews(reader, repo, pr, entry["review_sha256"])
        require(entry["proof"].get("kind") == "development",
                "source development proof cannot be replaced by integration proof")
        verify_proof(reader, repo, entry["proof"], source_head, source_tree, source_base, source_paths)
    # Bound races with a second complete review read and PR identity/body read.
    # This is still a snapshot, never an atomic GitHub merge authorization.
    check_reviews(reader, repository, number, manifest["review_sha256"])
    for entry in developments:
        check_reviews(reader, entry["repository"], entry["pr"], entry["review_sha256"])
        identity = (entry["repository"], entry["pr"])
        source_final = reader.get(f"/repos/{entry['repository']}/pulls/{entry['pr']}")
        require(pr_identity(source_final) == source_prs[identity],
                "development PR changed during verification")
    # Bound races by rereading mutable PR identity/body after all network reads.
    final = reader.get(prefix)
    require(pr_identity(final) == pr_identity(promotion), "promotion changed during verification")
    return {"schema_version": 1, "kind": "uselesskey-promotion-verification",
            "mechanical_verification": "success", "authority": "none",
            "operator_acceptance": decision, "repository": repository,
            "repository_id": CANONICAL_ID, "pull_request": number,
            "head": head, "base": base, "tree": tree, "profile": profile,
            "development_count": len(developments), "reviews": reviews,
            "control_sha256": {name: digest(Path(__file__).with_name(name).read_bytes())
                for name in ("verify-promotion-evidence.py", "development_proof_contract.py",
                             "run-integration-proof.py")},
            "verified_at_ms": now,
            "limits": ["operator acceptance and plan adequacy are trusted inputs",
                       "receipt identity is not execution attestation",
                       "review state is a snapshot; recheck before queue admission",
                       "no check-writing, dispatch, queue, or merge authority"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, choices=sorted(REPOSITORIES))
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-base", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--manifest", type=Path)
    mode.add_argument("--capture-review-state", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        # Refuse existing output; initialize this new observation as incomplete.
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as output:
            output.write(json.dumps({"mechanical_verification": "incomplete", "authority": "none"}) + "\n")
        reader = GitHubReader(os.environ.get("GITHUB_TOKEN", ""))
        if args.capture_review_state:
            repository_identity(reader, args.repository, REPOSITORIES[args.repository])
            pr = reader.get(f"/repos/{args.repository}/pulls/{args.pr}")
            require(pr.get("head", {}).get("sha") == sha(args.expected_head) and
                    pr.get("base", {}).get("sha") == sha(args.expected_base) and
                    pr.get("base", {}).get("ref") == TARGET_BRANCH,
                    "capture subject differs from expected PR identity")
            surface = review_surface(reader, args.repository, args.pr)
            paths = changed_paths(reader, args.repository, pr)
            pr_comparison_base = comparison_base(reader, args.repository, args.expected_base, args.expected_head)
            report = {"schema_version": 1, "kind": "uselesskey-review-observation",
                "authority": "none", "repository": args.repository,
                "pull_request": args.pr, "head": args.expected_head,
                "head_ref": pr.get("head", {}).get("ref"), "base_ref": TARGET_BRANCH,
                "base": args.expected_base, "observed_at_ms": int(time.time() * 1000),
                "comparison_base": pr_comparison_base, "changed_paths": paths,
                "body_sha256": body_digest(pr),
                "review_sha256": review_digest(surface), "review_surface": surface}
            args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"review snapshot captured; not accepted: {args.output}")
            return 0
        raw = args.manifest.read_bytes()
        report = verify_manifest(reader,
            json_object(raw), args.repository, args.pr, args.expected_head, args.expected_base)
        report["manifest_sha256"] = digest(raw)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"mechanical verification succeeded; no merge authority: {args.output}")
        return 0
    except (EvidenceError, OSError, KeyError, TypeError, ValueError, AttributeError) as exc:
        print(f"promotion evidence refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
