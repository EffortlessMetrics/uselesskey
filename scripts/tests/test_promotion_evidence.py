"""Synthetic API/receipt fixtures. These tests do not establish native CI proof."""

import base64
import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "verify-promotion-evidence.py"
sys.dont_write_bytecode = True
sys.path.insert(0, str(SCRIPT.parent))
import development_proof_contract as CONTRACT
SPEC = importlib.util.spec_from_file_location("promotion_evidence", SCRIPT)
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)
INTEGRATION_SPEC = importlib.util.spec_from_file_location("integration_adapter_fixture", SCRIPT.with_name("run-integration-proof.py"))
INTEGRATION = importlib.util.module_from_spec(INTEGRATION_SPEC)
INTEGRATION_SPEC.loader.exec_module(INTEGRATION)
CANONICAL = "EffortlessMetrics/uselesskey"
DEVELOPMENT = "EffortlessMetrics/uselesskey-swarm"
HEAD, BASE, TREE = "a" * 40, "b" * 40, "c" * 40
SOURCE, SOURCE_BASE, SOURCE_TREE = "d" * 40, "e" * 40, "f" * 40


def envelope(head, base, tree, paths=None, focused=False):
    classification = CONTRACT.classify_paths(paths or ["crates/demo/src/lib.rs"])
    profile = classification["profile"]
    plan = f'schema_version = 1\nprofile = "{profile}"\nrequired_steps = ["tests"]\n'
    command = None
    if profile == "docs":
        command = ["cargo", "xtask", "docs-sync", "--check"]
    elif profile == "control":
        command = ["python3", "-B", "-m", "unittest", "discover", "-s", "scripts/tests"]
    elif focused:
        command = ["cargo", "test", "-p", "demo", "regression"]
    if command:
        plan += f'[[focused]]\nname = "regression"\nkind = "{profile}"\ncommand = {json.dumps(command)}\n'
    raw = json.dumps({"schema_version": 2, "git_sha": head, "timestamp": 1500,
        "crate_set": "pr:1",
        "steps": [{"name": "detect-changes", "status": "ok", "details": f"base_ref={base}, files=1"},
                  {"name": "public-surface", "status": "ok"},
                  {"name": "spec-check", "status": "ok"},
                  {"name": "tests", "status": "ok"}],
        "feature_matrix": [], "bdd_matrix": []})
    outcomes = []
    if command:
        outcomes.append({"name": "focused:regression", "command": command,
            "started_at_ms": 1100, "finished_at_ms": 1200, "return_code": 0})
    outcomes.append({"name": "xtask-pr", "command": ["cargo", "xtask", "pr"],
        "started_at_ms": 1300, "finished_at_ms": 1900, "return_code": 0})
    return {"schema_version": 1, "kind": "uselesskey-development-proof",
        "subject": {"head": head, "base": base, "tree": tree},
        "invocation_id": "9" * 32, "conclusion": "success",
        "started_at_ms": 1000, "finished_at_ms": 2000,
        "plan": {"toml": plan, "sha256": MOD.digest(plan.encode())},
        "xtask_receipt": {"utf8": raw, "sha256": MOD.digest(raw.encode())},
        "classification": classification, "outcomes": outcomes}


def integration_receipt():
    """Unsigned synthetic bytes exercise the current consumer, not execution."""
    at = "1970-01-01T00:00:01+00:00"
    source = {"sha": HEAD, "tree": TREE, "tracked_clean": True}
    return {"schema_version": INTEGRATION.SCHEMA_VERSION, "invocation_id": "99999999-9999-4999-8999-999999999999",
        "complete": True, "conclusion": "success",
        "subject": {"kind": "manual", "expected_sha": HEAD, "expected_base": BASE},
        "source": {"before": source, "after": source.copy(), "base_is_ancestor": True},
        "control": {"script": "scripts/run-integration-proof.py", "sha256": "1" * 64,
            "git_sha": BASE, "git_tree": TREE},
        "policy": {**INTEGRATION.policy(), "sha256": INTEGRATION.policy_digest()},
        "inputs": {name: {"sha256": "2" * 64} for name in INTEGRATION.INPUT_PATHS},
        "toolchain": {name: {"command": [name, "-vV"], "version": "synthetic fixture"}
            for name in ("rustc", "cargo")},
        "started_at": at, "finished_at": at,
        "commands": [{"name": name, "command": list(argv), "conclusion": "success",
            "return_code": 0, "started_at": at, "finished_at": at, "duration_seconds": 0}
            for name, argv in INTEGRATION.COMMANDS]}


class FakeReader:
    def __init__(self):
        self.objects, self.review_threads, self.review_rows, self.files = {}, {}, {}, {}
        self.reads = []
        self.last_pr = None
        self.last_source = None
        self.last_reviews = None
        self.page_reads = []

    def get(self, path):
        self.reads.append(path)
        if self.last_pr and path == f"/repos/{CANONICAL}/pulls/77" and self.reads.count(path) > 1:
            return copy.deepcopy(self.last_pr)
        if self.last_source and path == f"/repos/{DEVELOPMENT}/pulls/12" and self.reads.count(path) > 1:
            return copy.deepcopy(self.last_source)
        if path not in self.objects:
            raise MOD.EvidenceError("GitHub read failed (404); no absence inferred")
        return copy.deepcopy(self.objects[path])

    def pages(self, path):
        self.page_reads.append(path)
        if self.last_reviews and path == f"/repos/{CANONICAL}/pulls/77/reviews" and self.page_reads.count(path) > 1:
            return copy.deepcopy(self.last_reviews)
        return copy.deepcopy(self.files.get(path, self.review_rows.get(path, [])))

    def threads(self, repository, number):
        return copy.deepcopy(self.review_threads.get((repository, number), []))

    def add_proof(self, repository, receipt):
        raw = json.dumps(receipt, sort_keys=True).encode()
        blob = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
        self.objects[f"/repos/{repository}/git/blobs/{blob}"] = {
            "sha": blob, "encoding": "base64", "size": len(raw),
            "content": base64.b64encode(raw).decode()}
        common = {"git_blob": blob, "sha256": MOD.digest(raw), "invocation_id": receipt["invocation_id"]}
        if receipt.get("kind") == "uselesskey-development-proof":
            return {**common, "kind": "development", "plan_sha256": receipt["plan"]["sha256"]}
        return {**common, "kind": "integration", "control_sha256": receipt["control"]["sha256"],
                "policy_sha256": receipt["policy"]["sha256"]}


class PromotionEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.reader = FakeReader()
        for repo, repo_id in [(CANONICAL, MOD.CANONICAL_ID), (DEVELOPMENT, MOD.DEVELOPMENT_ID)]:
            self.reader.objects[f"/repos/{repo}"] = {"id": repo_id, "full_name": repo}
        self.pr = {"number": 77, "state": "open", "draft": False, "merged": False,
            "body": "reviewed promotion", "head": {"sha": HEAD, "ref": "candidate", "repo": {"id": MOD.CANONICAL_ID}},
            "base": {"sha": BASE, "ref": "main", "repo": {"id": MOD.CANONICAL_ID}}, "changed_files": 1}
        self.reader.objects[f"/repos/{CANONICAL}/pulls/77"] = self.pr
        self.reader.objects[f"/repos/{CANONICAL}/commits/{HEAD}"] = {
            "sha": HEAD, "commit": {"tree": {"sha": TREE}}}
        self.reader.objects[f"/repos/{CANONICAL}/compare/{BASE}...{HEAD}"] = {
            "merge_base_commit": {"sha": BASE}}
        self.reader.objects[f"/repos/{DEVELOPMENT}/pulls/12"] = {"number": 12,
            "state": "closed", "merged": True, "head": {"sha": SOURCE}, "body": "reviewed source",
            "base": {"sha": SOURCE_BASE, "ref": "main", "repo": {"id": MOD.DEVELOPMENT_ID}}, "changed_files": 1}
        self.reader.objects[f"/repos/{DEVELOPMENT}/commits/{SOURCE}"] = {
            "sha": SOURCE, "commit": {"tree": {"sha": SOURCE_TREE}}}
        self.reader.objects[f"/repos/{DEVELOPMENT}/commits/{SOURCE_BASE}"] = {"sha": SOURCE_BASE}
        self.reader.objects[f"/repos/{DEVELOPMENT}/compare/{SOURCE_BASE}...{SOURCE}"] = {
            "merge_base_commit": {"sha": SOURCE_BASE}}
        for repository, number in [(CANONICAL, 77), (DEVELOPMENT, 12)]:
            self.reader.files[f"/repos/{repository}/pulls/{number}/files"] = [
                {"filename": "crates/demo/src/lib.rs", "status": "added"}]
        empty_digest = MOD.review_digest({"threads": [], "reviews": [], "inline_comments": [], "discussion": []})
        self.manifest = {"schema_version": 1, "kind": "uselesskey-promotion-evidence",
            "profile": "development-promotion", "repository_id": MOD.CANONICAL_ID,
            "pull_request": 77, "head": HEAD, "base": BASE,
            "body_sha256": MOD.digest(self.pr["body"].encode()), "accepted_at_ms": 2500,
            "review_sha256": empty_digest,
            "operator_acceptance": {"actor": "test-operator", "review_disposition": "complete",
                "composition_reviewed": True, "plans_reviewed": True, "known_blockers": [],
                "evidence": ["synthetic fixture; no real acceptance"]},
            "promotion_proof": self.reader.add_proof(CANONICAL, envelope(HEAD, BASE, TREE)),
            "development": [{"repository": DEVELOPMENT, "pr": 12, "head": SOURCE,
                "base": SOURCE_BASE, "pr_base": SOURCE_BASE,
                "body_sha256": MOD.digest(b"reviewed source"), "review_sha256": empty_digest,
                "proof": self.reader.add_proof(DEVELOPMENT,
                    envelope(SOURCE, SOURCE_BASE, SOURCE_TREE))}]}

    def verify(self):
        return MOD.verify_manifest(self.reader, self.manifest, CANONICAL, 77, HEAD, BASE, now_ms=3000)

    def reject(self, message=None):
        with self.assertRaisesRegex(MOD.EvidenceError, message or ".+"):
            self.verify()

    def accept_reviews(self, repository=CANONICAL, number=77):
        fingerprint = MOD.review_digest(MOD.review_surface(self.reader, repository, number))
        if repository == CANONICAL:
            self.manifest["review_sha256"] = fingerprint
        else:
            self.manifest["development"][0]["review_sha256"] = fingerprint
        self.reader.page_reads.clear()

    def replace_promotion(self, receipt):
        self.manifest["promotion_proof"] = self.reader.add_proof(CANONICAL, receipt)

    def test_valid_product_verifies_facts_without_granting_authority(self):
        result = self.verify()
        self.assertEqual(result["mechanical_verification"], "success")
        self.assertEqual(result["authority"], "none")
        self.assertEqual(result["development_count"], 1)

    def test_nonexistent_pr_cannot_be_a_well_formed_declaration(self):
        self.manifest["development"][0]["pr"] = 2147483647
        self.reject()

    def test_zero_sha_fails(self):
        self.manifest["development"][0]["head"] = "0" * 40
        self.reject()

    def test_unmerged_development_fails(self):
        self.reader.objects[f"/repos/{DEVELOPMENT}/pulls/12"]["merged"] = False
        self.reject()

    def test_live_candidate_drift(self):
        for key in ("draft", "body", "head", "base"):
            with self.subTest(key=key):
                old = copy.deepcopy(self.pr[key])
                self.pr[key] = True if key == "draft" else "changed"
                if key in ("head", "base"):
                    self.pr[key] = {"sha": "1" * 40, "repo": {"id": MOD.CANONICAL_ID}}
                self.reject()
                self.pr[key] = old

    def test_changed_during_readback_fails(self):
        self.reader.last_pr = {**self.pr, "body": "edited during fetch"}
        self.reject()

    def test_same_sha_target_branch_change_is_not_the_same_promotion(self):
        self.pr["base"]["ref"] = "other-target"
        self.reject("live promotion head/base/repository mismatch")
        self.pr["base"]["ref"] = "main"
        self.reader.reads.clear()
        self.reader.last_pr = copy.deepcopy(self.pr)
        self.reader.last_pr["base"]["ref"] = "other-target"
        self.reject("promotion changed during verification")

    def test_source_pr_must_have_merged_into_development_main(self):
        self.reader.objects[f"/repos/{DEVELOPMENT}/pulls/12"]["base"]["ref"] = "unaccepted-topic"
        self.reject("development PR is absent, unmerged")

    def test_wrong_repository_identity(self):
        self.reader.objects[f"/repos/{DEVELOPMENT}"]["id"] = 42
        self.reject()

    def test_wrong_receipt_digest(self):
        self.manifest["promotion_proof"]["sha256"] = "0" * 64
        self.reject()

    def test_blob_response_must_match_git_object_hash(self):
        proof = self.manifest["promotion_proof"]
        raw = json.dumps(envelope(HEAD, BASE, TREE)).encode()
        blob = self.reader.objects[f"/repos/{CANONICAL}/git/blobs/{proof['git_blob']}"]
        blob["content"], blob["size"] = base64.b64encode(raw).decode(), len(raw)
        proof["sha256"] = MOD.digest(raw)
        self.reject()

    def test_wrong_plan_and_invocation(self):
        for key in ("plan_sha256", "invocation_id"):
            with self.subTest(key=key):
                previous = self.manifest["promotion_proof"][key]
                self.manifest["promotion_proof"][key] = "0" * len(previous)
                self.reject()
                self.manifest["promotion_proof"][key] = previous

    def test_incomplete_success_shaped_envelope(self):
        receipt = envelope(HEAD, BASE, TREE)
        receipt["outcomes"] = []
        self.replace_promotion(receipt)
        self.reject()

    def test_stale_raw_receipt(self):
        receipt = envelope(HEAD, BASE, TREE)
        raw = json.loads(receipt["xtask_receipt"]["utf8"])
        raw["timestamp"] = 500
        text = json.dumps(raw)
        receipt["xtask_receipt"] = {"utf8": text, "sha256": MOD.digest(text.encode())}
        self.replace_promotion(receipt)
        self.reject()

    def test_required_step_missing_even_with_valid_hashes(self):
        receipt = envelope(HEAD, BASE, TREE)
        raw = json.loads(receipt["xtask_receipt"]["utf8"])
        raw["steps"] = [{"name": "detect-changes", "status": "ok"}]
        text = json.dumps(raw)
        receipt["xtask_receipt"] = {"utf8": text, "sha256": MOD.digest(text.encode())}
        self.replace_promotion(receipt)
        self.reject()

    def test_unresolved_outdated_thread_blocks(self):
        self.reader.review_threads[(CANONICAL, 77)] = [{"id": "thread-1", "isResolved": False, "isOutdated": True}]
        self.accept_reviews()
        self.reject("unresolved review thread")

    def test_changes_requested_blocks_comments_do_not_clear(self):
        self.reader.review_rows[f"/repos/{CANONICAL}/pulls/77/reviews"] = [
            {"id": 1, "user": {"id": 1}, "state": "CHANGES_REQUESTED"},
            {"id": 2, "user": {"id": 1}, "state": "COMMENTED"}]
        self.accept_reviews()
        self.reject("changes-requested review")

    def test_missing_composition_acceptance(self):
        self.manifest["operator_acceptance"]["composition_reviewed"] = False
        self.reject()

    def test_maintenance_profile_has_exact_bounded_paths(self):
        self.manifest.update(profile="canonical-maintenance", development=[],
                             accepted_paths=["docs/ci/policy.md"])
        self.reader.files[f"/repos/{CANONICAL}/pulls/77/files"] = [
            {"filename": "docs/ci/policy.md", "status": "added"}]
        self.replace_promotion(envelope(HEAD, BASE, TREE, ["docs/ci/policy.md"]))
        self.assertEqual(self.verify()["profile"], "canonical-maintenance")
        self.reader.files[f"/repos/{CANONICAL}/pulls/77/files"] = [
            {"filename": "crates/uselesskey/src/lib.rs", "status": "added"}]
        self.manifest["accepted_paths"] = ["crates/uselesskey/src/lib.rs"]
        self.replace_promotion(envelope(HEAD, BASE, TREE, self.manifest["accepted_paths"]))
        self.reject("maintenance path set")

    def test_wrong_proof_base_fails(self):
        receipt = envelope(HEAD, "7" * 40, TREE)
        self.replace_promotion(receipt)
        self.reject()

    def test_nonancestor_source_base_fails(self):
        self.reader.objects[f"/repos/{DEVELOPMENT}/compare/{SOURCE_BASE}...{SOURCE}"] = {
            "merge_base_commit": {"sha": "7" * 40}}
        self.reject()

    def test_focused_commands_use_the_producers_actual_order(self):
        receipt = envelope(HEAD, BASE, TREE, focused=True)
        self.replace_promotion(receipt)
        self.assertEqual(self.verify()["mechanical_verification"], "success")
        receipt["outcomes"].reverse()
        self.replace_promotion(receipt)
        self.reject("command outcome differs")

    def test_new_commented_review_invalidates_operator_acceptance(self):
        self.reader.review_rows[f"/repos/{CANONICAL}/pulls/77/reviews"] = [
            {"id": 1, "user": {"id": 1}, "state": "COMMENTED", "body": "Unresolved correctness concern"}]
        self.reject("review surface changed")

    def test_edited_inline_and_general_comments_invalidate_acceptance(self):
        for endpoint in ("pulls/77/comments", "issues/77/comments"):
            with self.subTest(endpoint=endpoint):
                rows = [{"id": 9, "body": "Reviewed observation"}]
                self.reader.review_rows[f"/repos/{CANONICAL}/{endpoint}"] = rows
                self.accept_reviews()
                rows[0]["body"] = "Edited substantive objection"
                self.reject("review surface changed")

    def test_review_activity_during_verification_is_rechecked(self):
        self.reader.last_reviews = [
            {"id": 1, "user": {"id": 1}, "state": "COMMENTED", "body": "New concern"}]
        self.reject("review surface changed")

    def test_missing_baseline_obligation_and_unreviewed_skip_are_rejected(self):
        for mode in ("missing-baseline", "unreviewed-skip"):
            with self.subTest(mode=mode):
                receipt = envelope(HEAD, BASE, TREE)
                raw = json.loads(receipt["xtask_receipt"]["utf8"])
                if mode == "missing-baseline":
                    raw["steps"] = [row for row in raw["steps"] if row["name"] != "spec-check"]
                else:
                    raw["steps"].append({"name": "fmt", "status": "skipped", "details": "not selected"})
                encoded = json.dumps(raw)
                receipt["xtask_receipt"] = {"utf8": encoded, "sha256": MOD.digest(encoded.encode())}
                self.replace_promotion(receipt)
                self.reject("development receipt rejected")

    def test_absent_or_false_path_classification_cannot_satisfy_contract(self):
        for mode in ("missing", "false-profile", "wrong-range"):
            with self.subTest(mode=mode):
                receipt = envelope(HEAD, BASE, TREE)
                if mode == "missing":
                    del receipt["classification"]
                elif mode == "false-profile":
                    receipt["classification"]["classes"] = ["docs"]
                    receipt["classification"]["profile"] = "docs"
                else:
                    receipt = envelope(HEAD, BASE, TREE, ["README.md"])
                self.replace_promotion(receipt)
                self.reject()

    def test_intermediate_ancestor_cannot_narrow_the_source_pr_range(self):
        narrowed = "8" * 40
        self.reader.objects[f"/repos/{DEVELOPMENT}/commits/{narrowed}"] = {"sha": narrowed}
        self.reader.objects[f"/repos/{DEVELOPMENT}/compare/{narrowed}...{SOURCE}"] = {
            "merge_base_commit": {"sha": narrowed}}
        self.manifest["development"][0]["base"] = narrowed
        self.manifest["development"][0]["proof"] = self.reader.add_proof(
            DEVELOPMENT, envelope(SOURCE, narrowed, SOURCE_TREE))
        self.reject("not the native PR comparison base")

    def test_diverged_pr_base_uses_its_independent_merge_base(self):
        moved = "8" * 40
        self.reader.objects[f"/repos/{DEVELOPMENT}/pulls/12"]["base"]["sha"] = moved
        self.manifest["development"][0]["pr_base"] = moved
        self.reader.objects[f"/repos/{DEVELOPMENT}/compare/{moved}...{SOURCE}"] = {
            "merge_base_commit": {"sha": SOURCE_BASE}}
        self.assertEqual(self.verify()["mechanical_verification"], "success")

    def test_changed_native_source_base_or_body_invalidates_acceptance(self):
        source = self.reader.objects[f"/repos/{DEVELOPMENT}/pulls/12"]
        source["body"] = "Edited after acceptance"
        self.reject("development PR body changed")
        source["body"] = "reviewed source"
        source["base"]["sha"] = "8" * 40
        self.reject("development PR base differs")

    def test_source_pr_is_reread_before_success(self):
        self.reader.last_source = {**self.reader.objects[f"/repos/{DEVELOPMENT}/pulls/12"],
                                   "body": "Changed while verifying"}
        self.reject("development PR changed during")

    def test_current_canonical_base_must_be_in_the_tested_candidate(self):
        self.reader.objects[f"/repos/{CANONICAL}/compare/{BASE}...{HEAD}"] = {
            "merge_base_commit": {"sha": "7" * 40}}
        self.reject("does not include the accepted current base")

    def test_rename_cannot_hide_product_source_in_maintenance(self):
        paths = ["crates/demo/src/lib.rs", "docs/ci/lib.md"]
        self.manifest.update(profile="canonical-maintenance", development=[], accepted_paths=paths)
        self.reader.files[f"/repos/{CANONICAL}/pulls/77/files"] = [
            {"filename": "docs/ci/lib.md", "status": "renamed", "previous_filename": paths[0]}]
        self.replace_promotion(envelope(HEAD, BASE, TREE, paths))
        self.reject("maintenance path set")
        # An otherwise valid product envelope omitting the rename destination fails too.
        self.replace_promotion(envelope(HEAD, BASE, TREE))
        self.reject("complete native PR change range")

    def test_rename_origin_is_in_the_native_path_set(self):
        self.reader.files[f"/repos/{CANONICAL}/pulls/77/files"] = [
            {"filename": "docs/ci/policy.md", "status": "renamed", "previous_filename": "README.md"}]
        self.assertEqual(MOD.changed_paths(self.reader, CANONICAL, self.pr),
                         ["README.md", "docs/ci/policy.md"])

    def test_incomplete_or_duplicate_file_listing_is_rejected(self):
        self.pr["changed_files"] = 2
        self.reject("file list is absent or incomplete")
        self.reader.files[f"/repos/{CANONICAL}/pulls/77/files"] *= 2
        self.reject("duplicate PR filename")

    def test_integration_cannot_replace_source_development_proof(self):
        self.manifest["development"][0]["proof"]["kind"] = "integration"
        self.reject("source development proof cannot be replaced")

    def test_complete_manual_integration_can_prove_composed_head(self):
        self.replace_promotion(integration_receipt())
        result = self.verify()
        self.assertEqual(result["mechanical_verification"], "success")
        self.assertEqual(result["authority"], "none")

    def test_integration_adapter_rejects_wrong_tree_and_incomplete_portfolio(self):
        receipt = integration_receipt()
        receipt["source"]["before"]["tree"] = "7" * 40
        receipt["source"]["after"]["tree"] = "7" * 40
        self.replace_promotion(receipt)
        self.reject("tree differs from live Git subject")
        receipt = integration_receipt()
        receipt["commands"].pop()
        self.replace_promotion(receipt)
        self.reject("incomplete command portfolio")

    def test_strict_json_rejects_duplicate_keys_nonfinite_values_and_wrong_shape(self):
        for raw in (b'{"head": 1, "head": 2}', b'{"value": NaN}', b'{"value": Infinity}', b'[]'):
            with self.subTest(raw=raw), self.assertRaises(MOD.EvidenceError):
                MOD.json_object(raw)

    def test_embedded_xtask_json_also_rejects_nonfinite_values(self):
        for token in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(token=token):
                receipt = envelope(HEAD, BASE, TREE)
                raw = receipt["xtask_receipt"]["utf8"][:-1] + ', "bdd_counts": {"passed": ' + token + '}}'
                receipt["xtask_receipt"] = {"utf8": raw, "sha256": MOD.digest(raw.encode())}
                self.replace_promotion(receipt)
                self.reject("non-finite JSON")

    def test_manifest_rejects_unknown_override_fields_and_boolean_identities(self):
        self.manifest["override_green"] = True
        self.reject("unknown or missing evidence fields")
        del self.manifest["override_green"]
        self.manifest["schema_version"] = True
        self.reject("unsupported evidence manifest")

    def test_acceptance_must_cover_plan_adequacy_and_cannot_be_future_dated(self):
        self.manifest["operator_acceptance"]["plans_reviewed"] = False
        self.reject("missing explicit operator acceptance")
        self.manifest["operator_acceptance"]["plans_reviewed"] = True
        self.manifest["accepted_at_ms"] = 4000
        self.reject("future-dated")

    def test_pages_refuse_unproved_completeness(self):
        class InfiniteReader(MOD.GitHubReader):
            def __init__(self):
                pass
            def get(self, path):
                return [{}] * 100
        with self.assertRaisesRegex(MOD.EvidenceError, "pagination bound"):
            InfiniteReader().pages("/repos/a/b/pulls/1/reviews")

    def test_missing_token_leaves_incomplete_new_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, output = root / "input.json", root / "output.json"
            manifest.write_text(json.dumps(self.manifest))
            from unittest.mock import patch
            with patch.dict("os.environ", {}, clear=True):
                self.assertEqual(MOD.main(["--repository", CANONICAL, "--pr", "77",
                    "--expected-head", HEAD, "--expected-base", BASE,
                    "--manifest", str(manifest), "--output", str(output)]), 1)
            self.assertEqual(json.loads(output.read_text())["mechanical_verification"], "incomplete")

    def test_capture_produces_observation_not_operator_acceptance(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "observation.json"
            with patch.object(MOD, "GitHubReader", return_value=self.reader):
                result = MOD.main(["--repository", CANONICAL, "--pr", "77",
                    "--expected-head", HEAD, "--expected-base", BASE,
                    "--capture-review-state", "--output", str(output)])
            self.assertEqual(result, 0)
            report = json.loads(output.read_text())
            self.assertEqual(report["kind"], "uselesskey-review-observation")
            self.assertEqual(report["comparison_base"], BASE)
            self.assertEqual(report["base_ref"], "main")
            self.assertNotIn("operator_acceptance", report)
            self.assertNotIn("mechanical_verification", report)


if __name__ == "__main__":
    unittest.main()
