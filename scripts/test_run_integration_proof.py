#!/usr/bin/env python3
"""Failure-oriented tests for the integration wrapper; no Rust portfolio is run."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("run-integration-proof.py")
SPEC = importlib.util.spec_from_file_location("integration_proof", SCRIPT)
assert SPEC and SPEC.loader
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)
REAL_RUN = subprocess.run


class IntegrationProofTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "source"
        self.root.mkdir()
        (self.root / "scripts").mkdir()
        self.script = self.root / "scripts" / SCRIPT.name
        shutil.copyfile(SCRIPT, self.script)
        for name, content in {
            "Cargo.toml": "[workspace]\n",
            "Cargo.lock": "# test lock identity\nversion = 4\n",
            "rust-toolchain.toml": '[toolchain]\nchannel = "1.95"\n',
            "tracked.txt": "original\n",
            ".gitignore": "/target/\n",
        }.items():
            (self.root / name).write_text(content, encoding="utf-8")
        self.git("init", "-q")
        self.git("config", "user.name", "Integration Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")
        self.head = self.git("rev-parse", "HEAD")
        self.invocation = str(uuid.uuid4())
        self.receipt_path = self.root / "target/integration-proof" / self.invocation / "receipt.json"
        self.calls: list[tuple[str, ...]] = []
        self.on_command = None
        self.tool_failure = False
        self.module_file = patch.object(PROOF, "__file__", str(self.script))
        self.module_file.start()
        self.runner = patch.object(PROOF.subprocess, "run", side_effect=self.command)
        self.runner.start()

    def tearDown(self) -> None:
        self.runner.stop()
        self.module_file.stop()
        self.temporary.cleanup()

    def git(self, *args: str) -> str:
        completed = REAL_RUN(
            ("git", *args), cwd=self.root, check=True, text=True,
            capture_output=True, env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
        )
        return completed.stdout.strip()

    def command(self, argv, **kwargs):
        argv = tuple(argv)
        if argv[0] in ("rustc", "cargo") and argv[1:] == ("-vV",):
            return subprocess.CompletedProcess(
                argv, 1 if self.tool_failure else 0,
                stdout=f"{argv[0]} 1.95.0 fixture\nhost: fixture-target\n", stderr="",
            )
        if argv[:2] == ("cargo", "xtask"):
            self.calls.append(argv)
            code = self.on_command(argv) if self.on_command else 0
            return subprocess.CompletedProcess(argv, code)
        return REAL_RUN(argv, **kwargs)

    def execute(self, **overrides) -> int:
        values = {
            "expected_sha": self.head, "invocation_id": self.invocation,
            **overrides,
        }
        return PROOF.run_proof(self.root, self.receipt_path, **values)

    def receipt(self) -> dict:
        return PROOF.read_receipt(self.receipt_path)

    def verify(self, value: dict, **overrides) -> None:
        values = {
            "expected_sha": self.head, "invocation_id": self.invocation,
            "expected_control_sha256": PROOF.sha256_file(self.script),
            "expected_policy_sha256": PROOF.policy_digest(), **overrides,
        }
        PROOF.verify_receipt(value, **values)

    def test_complete_proof_binds_subject_controls_inputs_and_all_commands(self) -> None:
        self.assertEqual(self.execute(), 0)
        receipt = self.receipt()
        self.verify(receipt)
        self.assertEqual(receipt["source"]["before"]["tree"], self.git("rev-parse", "HEAD^{tree}"))
        self.assertEqual(receipt["source"]["before"], receipt["source"]["after"])
        self.assertEqual(len(receipt["commands"]), 16)
        self.assertEqual(receipt["inputs"]["Cargo.lock"]["sha256"], PROOF.sha256_file(self.root / "Cargo.lock"))
        self.assertEqual(receipt["toolchain"]["rustc"]["command"], ["rustc", "-vV"])
        self.assertEqual(receipt["subject"]["kind"], "manual")

    def test_wrong_subject_is_rejected_before_any_product_command(self) -> None:
        self.assertEqual(self.execute(expected_sha="f" * 40), 2)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.receipt()["conclusion"], "error")

    def test_dirty_worktree_and_dirty_index_are_rejected(self) -> None:
        for staged in (False, True):
            with self.subTest(staged=staged):
                (self.root / "tracked.txt").write_text("changed\n", encoding="utf-8")
                if staged:
                    self.git("add", "tracked.txt")
                self.assertEqual(self.execute(), 2)
                self.assertEqual(self.calls, [])
                self.assertFalse(self.receipt()["complete"])
                self.git("reset", "--hard", "-q", "HEAD")
                self.invocation = str(uuid.uuid4())
                self.receipt_path = self.root / "target/integration-proof" / self.invocation / "receipt.json"

    def test_assume_unchanged_cannot_hide_dirty_tracked_input(self) -> None:
        self.git("update-index", "--assume-unchanged", "tracked.txt")
        (self.root / "tracked.txt").write_text("hidden change\n", encoding="utf-8")
        self.assertEqual(self.execute(), 2)
        self.assertEqual(self.calls, [])
        self.assertIn("assume-unchanged", self.receipt()["error"]["message"])

    def test_changed_source_between_commands_blocks_remaining_portfolio(self) -> None:
        def modify(_):
            (self.root / "tracked.txt").write_text("generated change\n", encoding="utf-8")
            return 0
        self.on_command = modify
        self.assertEqual(self.execute(), 2)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.receipt()["conclusion"], "error")

    def test_same_tree_new_head_cannot_receive_original_head_credit(self) -> None:
        def commit(_):
            self.git("commit", "--allow-empty", "-qm", "changed identity")
            return 0
        self.on_command = commit
        self.assertEqual(self.execute(), 2)
        self.assertEqual(len(self.calls), 1)
        self.assertIn("HEAD", self.receipt()["error"]["message"])

    def test_last_product_command_cannot_leave_a_changed_lockfile(self) -> None:
        def modify_last(argv):
            if argv[2] == "spec-check":
                (self.root / "Cargo.lock").write_text("# changed\nversion = 4\n", encoding="utf-8")
            return 0
        self.on_command = modify_last
        self.assertEqual(self.execute(), 2)
        self.assertNotEqual(self.receipt()["conclusion"], "success")

    def test_untracked_control_checkout_does_not_fail_tracked_clean_contract(self) -> None:
        nested = self.root / ".integration-control"
        nested.mkdir()
        (nested / "untracked-control.txt").write_text("not product tracked source\n", encoding="utf-8")
        self.assertEqual(self.execute(), 0)
        self.verify(self.receipt())

    def test_nonzero_command_stops_proof_and_cannot_verify(self) -> None:
        self.on_command = lambda argv: 7 if argv[2] == "clippy" else 0
        self.assertEqual(self.execute(), 7)
        receipt = self.receipt()
        self.assertEqual(len(receipt["commands"]), 2)
        self.assertEqual(receipt["commands"][-1]["return_code"], 7)
        self.assertEqual(receipt["conclusion"], "failure")
        with self.assertRaises(PROOF.ProofError):
            self.verify(receipt)

    def test_interruption_records_current_cancelled_attempt(self) -> None:
        def interrupt(_):
            raise KeyboardInterrupt
        self.on_command = interrupt
        self.assertEqual(self.execute(), 130)
        receipt = self.receipt()
        self.assertEqual(receipt["conclusion"], "cancelled")
        self.assertEqual(receipt["commands"][0]["conclusion"], "cancelled")
        self.assertFalse(receipt["complete"])

    def test_toolchain_failure_does_not_start_product_commands(self) -> None:
        self.tool_failure = True
        self.assertEqual(self.execute(), 2)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.receipt()["conclusion"], "error")

    def test_missing_tracked_lockfile_is_rejected(self) -> None:
        self.git("rm", "-q", "Cargo.lock")
        self.git("commit", "-qm", "remove lock")
        self.head = self.git("rev-parse", "HEAD")
        self.assertEqual(self.execute(), 2)
        self.assertEqual(self.calls, [])

    def test_merge_group_requires_explicit_ancestor_base(self) -> None:
        self.assertEqual(self.execute(subject_kind="merge-group"), 2)
        self.invocation = str(uuid.uuid4())
        self.receipt_path = self.root / "target/integration-proof" / self.invocation / "receipt.json"
        self.assertEqual(self.execute(subject_kind="merge-group", expected_base=self.head), 0)
        self.verify(self.receipt(), subject_kind="merge-group", expected_base=self.head)
        with self.assertRaises(PROOF.ProofError):
            self.verify(self.receipt())

    def test_nonancestor_base_is_rejected(self) -> None:
        tree = self.git("rev-parse", "HEAD^{tree}")
        alien = self.git("commit-tree", tree, "-m", "unrelated")
        self.assertEqual(self.execute(subject_kind="merge-group", expected_base=alien), 2)
        self.assertEqual(self.calls, [])

    def test_old_uuid_output_is_never_overwritten(self) -> None:
        self.assertEqual(self.execute(), 0)
        old_bytes = self.receipt_path.read_bytes()
        with self.assertRaisesRegex(PROOF.ProofError, "already exists"):
            self.execute()
        self.assertEqual(self.receipt_path.read_bytes(), old_bytes)
        old_receipt = self.receipt()
        with self.assertRaisesRegex(PROOF.ProofError, "another invocation"):
            self.verify(old_receipt, invocation_id=str(uuid.uuid4()))

    def test_wrong_control_or_policy_cannot_be_credited(self) -> None:
        self.assertEqual(self.execute(), 0)
        for override in (
            {"expected_control_sha256": "a" * 64},
            {"expected_policy_sha256": "b" * 64},
        ):
            with self.subTest(override=override), self.assertRaises(PROOF.ProofError):
                self.verify(self.receipt(), **override)

    def test_running_control_digest_is_checked_before_product_commands(self) -> None:
        self.assertEqual(self.execute(expected_control_sha256="c" * 64), 2)
        self.assertEqual(self.calls, [])
        self.assertIn("control digest", self.receipt()["error"]["message"])

    def test_incomplete_or_misleading_green_receipts_are_rejected(self) -> None:
        self.assertEqual(self.execute(), 0)
        good = self.receipt()
        mutations = {
            "missing command": lambda value: value["commands"].pop(),
            "duplicate command": lambda value: value["commands"].__setitem__(1, value["commands"][0]),
            "changed argv": lambda value: value["commands"][0]["command"].append("--fix"),
            "skipped success": lambda value: value["commands"][0].update(conclusion="skipped"),
            "false zero": lambda value: value["commands"][0].update(return_code=False),
            "missing lock": lambda value: value["inputs"].pop("Cargo.lock"),
            "missing toolchain": lambda value: value.pop("toolchain"),
            "missing end": lambda value: value.update(finished_at=None),
            "overlapping times": lambda value: value["commands"][1].update(started_at=value["started_at"]),
            "dirty post-state": lambda value: value["source"]["after"].update(tracked_clean=False),
            "nan duration": lambda value: value["commands"][0].update(duration_seconds=float("nan")),
            "missing completeness": lambda value: value.pop("complete"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                value = copy.deepcopy(good)
                mutate(value)
                with self.assertRaises(PROOF.ProofError):
                    self.verify(value)

    def test_duplicate_json_fields_and_nonfinite_json_are_rejected(self) -> None:
        self.receipt_path.parent.mkdir(parents=True)
        for text in ('{"conclusion":"error","conclusion":"success"}', '{"duration":NaN}'):
            self.receipt_path.write_text(text, encoding="utf-8")
            with self.assertRaises(PROOF.ProofError):
                self.receipt()

    def test_missing_persisted_receipt_cannot_return_success(self) -> None:
        with patch.object(PROOF, "read_receipt", side_effect=PROOF.ProofError("receipt disappeared")):
            self.assertEqual(self.execute(), 2)
        self.assertEqual(self.receipt()["conclusion"], "error")
        self.assertFalse(self.receipt()["complete"])

    def test_failed_final_receipt_write_cannot_return_success(self) -> None:
        real_write = PROOF.atomic_write_json
        def write(path, value):
            if value["conclusion"] == "success":
                raise OSError("no space for final receipt")
            real_write(path, value)
        with patch.object(PROOF, "atomic_write_json", side_effect=write):
            self.assertEqual(self.execute(), 2)
        self.assertEqual(self.receipt()["conclusion"], "error")

    def test_subject_is_mandatory_but_control_only_modes_work(self) -> None:
        for arguments in (["--list"], ["--self-test"], ["--policy-digest"]):
            self.assertEqual(PROOF.main(arguments), 0)
        with self.assertRaisesRegex(PROOF.ProofError, "--expected-sha"):
            PROOF.main(["--workspace", str(self.root)])

    def test_verification_requires_external_identity_arguments(self) -> None:
        with self.assertRaisesRegex(PROOF.ProofError, "--invocation-id"):
            PROOF.main(["--verify-receipt", "--expected-sha", self.head])
        with self.assertRaisesRegex(PROOF.ProofError, "--expected-control-sha256"):
            PROOF.main(["--verify-receipt", "--expected-sha", self.head, "--invocation-id", self.invocation])

    def test_cli_verifies_only_the_selected_current_receipt(self) -> None:
        self.assertEqual(self.execute(), 0)
        args = [
            sys.executable, str(self.script), "--verify-receipt",
            "--workspace", str(self.root), "--expected-sha", self.head,
            "--invocation-id", self.invocation,
            "--expected-control-sha256", PROOF.sha256_file(self.script),
            "--expected-policy-sha256", PROOF.policy_digest(),
        ]
        verified = REAL_RUN(args, check=False, text=True, capture_output=True)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        args[args.index("--invocation-id") + 1] = str(uuid.uuid4())
        stale = REAL_RUN(args, check=False, text=True, capture_output=True)
        self.assertEqual(stale.returncode, 2)
        self.assertIn("cannot read complete receipt", stale.stderr)


if __name__ == "__main__":
    unittest.main()
