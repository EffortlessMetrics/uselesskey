"""Real OpenSSH signatures and synthetic API state; no production signing keys."""

import base64
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import promotion_acceptance as ACCEPTANCE
import test_promotion_evidence as FIXTURE


def load_cli(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SIGN = load_cli("sign-promotion-acceptance")
VERIFY = load_cli("verify-signed-promotion")


class SignedPromotionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("ssh-keygen") is None:
            raise RuntimeError("OpenSSH is required; signature tests must not silently skip")
        cls.keys = tempfile.TemporaryDirectory(prefix="uselesskey-signature-tests-")
        cls.key = Path(cls.keys.name) / "operator"
        cls.other_key = Path(cls.keys.name) / "other"
        for key in (cls.key, cls.other_key):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                           check=True, capture_output=True, timeout=10)
        public_key = cls.key.with_suffix(".pub").read_text().split()
        cls.signers = (f'test-operator namespaces="{ACCEPTANCE.NAMESPACE}" '
                       f'{public_key[0]} {public_key[1]}\n').encode()
        cls.pin = ACCEPTANCE.EVIDENCE.digest(cls.signers)

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        fixture = FIXTURE.PromotionEvidenceTests()
        fixture.setUp()
        self.reader, self.manifest = fixture.reader, fixture.manifest
        self.bundle = ACCEPTANCE.sign_acceptance(self.manifest, "test-operator", self.key,
                                                  60, current_ms=3000)
        self.raw = ACCEPTANCE.canonical_bytes(self.bundle)

    def sign(self):
        self.bundle = ACCEPTANCE.sign_acceptance(self.manifest, "test-operator", self.key,
                                                  60, current_ms=3000)
        self.raw = ACCEPTANCE.canonical_bytes(self.bundle)

    def verify(self, *, source=None, clock=lambda: 3500):
        return ACCEPTANCE.verify_live_acceptance(
            self.reader, self.raw, self.signers, self.pin, FIXTURE.CANONICAL, 77,
            FIXTURE.HEAD, FIXTURE.BASE, source=source, clock=clock)

    def refuse(self, pattern=".+"):
        with self.assertRaisesRegex(ValueError, pattern):
            self.verify()

    def expose_git_bundle(self):
        path = ACCEPTANCE.acceptance_path(77, FIXTURE.HEAD, FIXTURE.BASE)
        revision = "1" * 40
        self.ref_path = f"/repos/{FIXTURE.CANONICAL}/git/ref/heads/ci-acceptance"
        self.content_path = f"/repos/{FIXTURE.CANONICAL}/contents/{path}?ref={revision}"
        blob = hashlib.sha1(f"blob {len(self.raw)}\0".encode() + self.raw).hexdigest()
        self.reader.objects[self.ref_path] = {
            "ref": ACCEPTANCE.ACCEPTANCE_REF, "object": {"type": "commit", "sha": revision}}
        self.reader.objects[self.content_path] = {"type": "file", "path": path,
            "sha": blob, "size": len(self.raw), "encoding": "base64",
            "content": base64.b64encode(self.raw).decode()}
        return ACCEPTANCE.fetch_acceptance(self.reader, FIXTURE.CANONICAL, 77,
                                           FIXTURE.HEAD, FIXTURE.BASE)

    def test_real_signature_and_complete_live_evidence_pass(self):
        result = self.verify()
        self.assertEqual(result["mechanical_verification"], "success")
        self.assertEqual(result["acceptance"]["authentication"], "openssh-signature")
        self.assertEqual(result["acceptance"]["allowed_signers_sha256"], self.pin)
        self.assertEqual(result["authority"], "none")

    def test_signature_tampering_cannot_pass(self):
        self.bundle["payload"]["manifest"]["operator_acceptance"]["evidence"] = ["tampered"]
        self.raw = ACCEPTANCE.canonical_bytes(self.bundle)
        self.refuse("OpenSSH")
        self.assertEqual(self.reader.reads, [])

    def test_different_signing_key_cannot_pass(self):
        self.bundle = ACCEPTANCE.sign_acceptance(self.manifest, "test-operator", self.other_key,
                                                  60, current_ms=3000)
        self.raw = ACCEPTANCE.canonical_bytes(self.bundle)
        self.refuse("OpenSSH")

    def test_wrong_namespace_cannot_pass(self):
        self.bundle["signature"] = ACCEPTANCE.ssh_keygen(
            ["-Y", "sign", "-f", str(self.key), "-n", "unrelated-namespace"],
            ACCEPTANCE.canonical_bytes(self.bundle["payload"]), signing=True).decode()
        self.raw = ACCEPTANCE.canonical_bytes(self.bundle)
        self.refuse("OpenSSH")

    def test_changed_signer_pin_cannot_pass(self):
        self.pin = "0" * 64
        self.refuse("independent pin")

    def test_missing_signer_pin_cannot_pass(self):
        self.pin = ""
        self.refuse("digest is missing")

    def test_identity_must_match_allowed_signers(self):
        self.manifest["operator_acceptance"]["actor"] = "other-operator"
        self.bundle = ACCEPTANCE.sign_acceptance(self.manifest, "other-operator", self.key,
                                                  60, current_ms=3000)
        self.raw = ACCEPTANCE.canonical_bytes(self.bundle)
        self.refuse("OpenSSH")

    def test_signer_cannot_claim_a_different_decision_actor(self):
        with self.assertRaisesRegex(ValueError, "acceptance actor"):
            ACCEPTANCE.sign_acceptance(self.manifest, "someone-else", self.key,
                                        60, current_ms=3000)

    def test_principal_patterns_and_argument_syntax_are_rejected(self):
        for value in ("*", "test,other", "-I", "test\nother", "", "x" * 129):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ACCEPTANCE.principal(value)

    def test_expired_acceptance_cannot_pass(self):
        with self.assertRaisesRegex(ValueError, "expired"):
            self.verify(clock=lambda: 63000)

    def test_future_signature_cannot_pass(self):
        with self.assertRaisesRegex(ValueError, "future-dated"):
            self.verify(clock=lambda: 2999)

    def test_expiry_is_rechecked_after_api_reads(self):
        times = iter((3500, 3500, 63000))
        with self.assertRaisesRegex(ValueError, "expired"):
            self.verify(clock=lambda: next(times))
        self.assertTrue(self.reader.reads)

    def test_validity_cannot_extend_old_acceptance(self):
        with self.assertRaisesRegex(ValueError, "one day"):
            ACCEPTANCE.sign_acceptance(self.manifest, "test-operator", self.key,
                                        86400, current_ms=3000)

    def test_boolean_or_unbounded_validity_is_rejected(self):
        for validity in (True, False, 0, -1, 86401):
            with self.subTest(validity=validity), self.assertRaises(ValueError):
                ACCEPTANCE.sign_acceptance(self.manifest, "test-operator", self.key,
                                            validity, current_ms=3000)

    def test_boolean_timestamp_is_rejected(self):
        self.bundle["payload"]["expires_at_ms"] = True
        self.raw = ACCEPTANCE.canonical_bytes(self.bundle)
        self.refuse("integer milliseconds")

    def test_changed_control_bytes_cannot_consume_acceptance(self):
        controls = ACCEPTANCE.control_digests()
        controls["verify-promotion-evidence.py"] = "0" * 64
        with mock.patch.object(ACCEPTANCE, "control_digests", return_value=controls):
            self.refuse("different admission controls")

    def test_unknown_bundle_field_is_rejected(self):
        self.bundle["override"] = True
        self.raw = ACCEPTANCE.canonical_bytes(self.bundle)
        self.refuse("unknown or missing")

    def test_duplicate_json_key_is_rejected(self):
        self.raw = b'{"payload":{},"payload":{},"signature":""}'
        self.refuse("invalid JSON")

    def test_nonfinite_json_is_rejected_before_signature(self):
        for value in (float("inf"), float("nan"), float("-inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ACCEPTANCE.canonical_bytes({"value": value})

    def test_signature_does_not_waive_changed_live_head(self):
        self.reader.objects[f"/repos/{FIXTURE.CANONICAL}/pulls/77"]["head"]["sha"] = "2" * 40
        self.refuse("head/base")

    def test_signature_does_not_waive_changed_live_body(self):
        self.reader.objects[f"/repos/{FIXTURE.CANONICAL}/pulls/77"]["body"] = "new instructions"
        self.refuse("body changed")

    def test_signature_does_not_waive_draft_state(self):
        self.reader.objects[f"/repos/{FIXTURE.CANONICAL}/pulls/77"]["draft"] = True
        self.refuse("Ready candidate")

    def test_signature_does_not_waive_review_activity(self):
        self.reader.review_rows[f"/repos/{FIXTURE.CANONICAL}/issues/77/comments"] = [
            {"id": 8, "body": "new finding"}]
        self.refuse("review surface changed")

    def test_signature_does_not_waive_absent_proof(self):
        self.manifest["promotion_proof"]["git_blob"] = "9" * 40
        self.sign()
        self.refuse("404")

    def test_signature_for_another_pr_cannot_pass(self):
        self.manifest["pull_request"] = 88
        self.sign()
        self.refuse("identity mismatch")

    def test_signed_bundle_is_bound_to_canonical_repository(self):
        self.manifest["repository_id"] = ACCEPTANCE.EVIDENCE.DEVELOPMENT_ID
        with self.assertRaisesRegex(ValueError, "different repository"):
            self.sign()

    def test_git_retention_path_and_blob_are_verified(self):
        raw, provenance = self.expose_git_bundle()
        self.assertEqual(raw, self.raw)
        self.assertEqual(provenance["path"], f"acceptances/77/{FIXTURE.HEAD}/{FIXTURE.BASE}.json")
        self.assertEqual(self.verify(source=provenance)["acceptance"]["source"], provenance)

    def test_ref_movement_during_verification_is_rejected(self):
        _, provenance = self.expose_git_bundle()
        self.reader.objects[self.ref_path]["object"]["sha"] = "2" * 40
        with self.assertRaisesRegex(ValueError, "ref changed"):
            self.verify(source=provenance)

    def test_tag_or_other_ref_cannot_replace_acceptance_branch(self):
        self.expose_git_bundle()
        self.reader.objects[self.ref_path]["ref"] = "refs/heads/candidate"
        with self.assertRaisesRegex(ValueError, "ref is absent"):
            ACCEPTANCE.fetch_acceptance(self.reader, FIXTURE.CANONICAL, 77,
                                         FIXTURE.HEAD, FIXTURE.BASE)

    def test_content_identity_and_type_are_enforced(self):
        self.expose_git_bundle()
        value = self.reader.objects[self.content_path]
        for key, bad in (("sha", "0" * 40), ("path", "other.json"), ("size", True),
                         ("encoding", "utf-8"), ("type", "symlink"), ("content", "not base64")):
            with self.subTest(key=key):
                saved = value[key]
                value[key] = bad
                with self.assertRaises(ValueError):
                    ACCEPTANCE.fetch_acceptance(self.reader, FIXTURE.CANONICAL, 77,
                                                 FIXTURE.HEAD, FIXTURE.BASE)
                value[key] = saved

    def test_signing_and_verification_do_not_inherit_api_tokens(self):
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "not-forwarded",
                                          "LD_PRELOAD": "/untrusted.so",
                                          "SSH_AUTH_SOCK": "/operator-agent"}):
            for signing in (False, True):
                env = ACCEPTANCE.ssh_environment(signing=signing)
                self.assertNotIn("GITHUB_TOKEN", env)
                self.assertNotIn("LD_PRELOAD", env)
                self.assertEqual("SSH_AUTH_SOCK" in env, signing)

    def test_missing_openssh_refuses_instead_of_waiving_signature(self):
        with mock.patch.object(ACCEPTANCE.shutil, "which", return_value=None):
            self.refuse("OpenSSH")

    def test_failed_signature_subprocess_refuses(self):
        result = subprocess.CompletedProcess([], 1, b"", b"failure")
        with mock.patch.object(ACCEPTANCE.subprocess, "run", return_value=result):
            self.refuse("OpenSSH")

    def test_cli_verifies_real_signature_and_keeps_new_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, signers, output = root / "bundle.json", root / "allowed_signers", root / "report.json"
            bundle.write_bytes(self.raw)
            signers.write_bytes(self.signers)
            with mock.patch.object(ACCEPTANCE.EVIDENCE, "GitHubReader", return_value=self.reader), \
                 mock.patch.object(ACCEPTANCE, "verify_live_acceptance", wraps=lambda *a, **kw:
                    ACCEPTANCE_VERIFY_LIVE(*a, **kw, clock=lambda: 3500)):
                code = VERIFY.main(["--repository", FIXTURE.CANONICAL, "--pr", "77",
                    "--expected-head", FIXTURE.HEAD, "--expected-base", FIXTURE.BASE,
                    "--bundle", str(bundle), "--allowed-signers", str(signers),
                    "--expected-signers-sha256", self.pin, "--output", str(output)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.read_text())["mechanical_verification"], "success")

    def test_cli_missing_bundle_cannot_leave_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            signers, output = root / "allowed_signers", root / "report.json"
            signers.write_bytes(self.signers)
            with mock.patch.object(ACCEPTANCE.EVIDENCE, "GitHubReader", return_value=self.reader):
                code = VERIFY.main(["--repository", FIXTURE.CANONICAL, "--pr", "77",
                    "--expected-head", FIXTURE.HEAD, "--expected-base", FIXTURE.BASE,
                    "--bundle", str(root / "absent"), "--allowed-signers", str(signers),
                    "--expected-signers-sha256", self.pin, "--output", str(output)])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output.read_text())["mechanical_verification"], "incomplete")

    def test_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "existing.json"
            output.write_text("keep me")
            with self.assertRaises(FileExistsError):
                ACCEPTANCE.initialize_output(output)
            self.assertEqual(output.read_text(), "keep me")

    def test_changed_parent_cannot_redirect_output_to_another_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent, moved, other = root / "current", root / "moved", root / "other"
            parent.mkdir()
            other.mkdir()
            unrelated = other / "report.json"
            unrelated.write_text("unrelated report")
            with ACCEPTANCE.initialize_output(parent / "report.json") as reservation:
                parent.rename(moved)
                parent.symlink_to(other, target_is_directory=True)
                with self.assertRaisesRegex(ValueError, "output parent changed"):
                    ACCEPTANCE.finish_output(reservation, {"mechanical_verification": "success"})
                self.assertEqual(unrelated.read_text(), "unrelated report")
                self.assertEqual(json.loads((moved / "report.json").read_text())[
                    "mechanical_verification"], "incomplete")

    def test_replaced_or_missing_reservation_is_refused(self):
        for replacement in ("file", "symlink", "missing"):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output, other = root / "report.json", root / "other.json"
                other.write_text("unrelated report")
                with ACCEPTANCE.initialize_output(output) as reservation:
                    output.unlink()
                    if replacement == "file":
                        output.write_text("replacement report")
                    elif replacement == "symlink":
                        output.symlink_to(other)
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        ACCEPTANCE.finish_output(reservation, {"mechanical_verification": "success"})
                    self.assertEqual(other.read_text(), "unrelated report")
                    if replacement == "file":
                        self.assertEqual(output.read_text(), "replacement report")

    def test_replacement_during_write_never_overwrites_the_later_occupant(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, moved = root / "report.json", root / "original.json"
            write = os.write
            with ACCEPTANCE.initialize_output(output) as reservation:
                def replace_then_write(descriptor, data):
                    output.rename(moved)
                    output.write_text("later report")
                    return write(descriptor, data)
                with mock.patch.object(ACCEPTANCE.os, "write", side_effect=replace_then_write):
                    with self.assertRaisesRegex(ValueError, "output reservation changed"):
                        ACCEPTANCE.finish_output(reservation, {"mechanical_verification": "success"})
                self.assertEqual(output.read_text(), "later report")

    def test_fresh_output_is_private_and_descriptors_close(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with ACCEPTANCE.initialize_output(output) as reservation:
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                ACCEPTANCE.finish_output(reservation, {"mechanical_verification": "success"})
            self.assertIsNone(reservation.output_fd)
            self.assertIsNone(reservation.directory_fd)

    def test_real_signing_cli_creates_only_public_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, output = root / "manifest.json", root / "bundle.json"
            manifest.write_bytes(ACCEPTANCE.canonical_bytes(self.manifest))
            with mock.patch.object(ACCEPTANCE, "now_ms", return_value=3000):
                code = SIGN.main(["--manifest", str(manifest), "--identity", "test-operator",
                                  "--key", str(self.key), "--valid-for-seconds", "60",
                                  "--output", str(output)])
            self.assertEqual(code, 0)
            bundle = ACCEPTANCE.EVIDENCE.json_object(output.read_bytes())
            ACCEPTANCE.verify_signature(bundle, self.signers, self.pin, current_ms=3500)
            self.assertNotIn(b"PRIVATE KEY", output.read_bytes())


ACCEPTANCE_VERIFY_LIVE = ACCEPTANCE.verify_live_acceptance

if __name__ == "__main__":
    unittest.main()
