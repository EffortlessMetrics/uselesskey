"""Authenticate operator acceptance with OpenSSH, then verify live evidence.

The signing key stays with the operator. Public signer pins and these controls
must be supplied outside candidate authority. A signature authenticates the
acceptance; it does not attest that the referenced commands actually executed.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

_SPEC = importlib.util.spec_from_file_location(
    "signed_acceptance_evidence", Path(__file__).with_name("verify-promotion-evidence.py")
)
assert _SPEC is not None and _SPEC.loader is not None
EVIDENCE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(EVIDENCE)
AcceptanceError = EVIDENCE.EvidenceError
require = EVIDENCE.require

NAMESPACE = "promotion-acceptance@uselesskey.org"
KIND = "uselesskey-signed-promotion-acceptance"
ACCEPTANCE_REF = "refs/heads/ci-acceptance"
MAX_VALIDITY_SECONDS = 24 * 60 * 60
SIGNERS_LIMIT = 32 * 1024
SIGNATURE_LIMIT = 16 * 1024
PRINCIPAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@+-]{0,127}\Z")
CONTROL_FILES = (
    "promotion_acceptance.py",
    "sign-promotion-acceptance.py",
    "verify-signed-promotion.py",
    "verify-promotion-evidence.py",
    "development_proof_contract.py",
    "run-integration-proof.py",
)


def canonical_bytes(value: Any) -> bytes:
    try:
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (ValueError, TypeError, RecursionError) as exc:
        raise AcceptanceError("acceptance is not bounded finite JSON") from exc
    require(len(raw) <= EVIDENCE.LIMIT, "acceptance exceeds bounded input size")
    return raw


def read_bounded(path: Path, limit: int = EVIDENCE.LIMIT) -> bytes:
    with path.open("rb") as source:
        raw = source.read(limit + 1)
    require(len(raw) <= limit, "input exceeds bounded size")
    return raw


def control_digests() -> dict[str, str]:
    result = {name: EVIDENCE.digest(read_bounded(Path(__file__).with_name(name)))
              for name in CONTROL_FILES}
    workflow = Path(__file__).resolve().parents[1] / ".github/workflows/required.yml"
    result[".github/workflows/required.yml"] = EVIDENCE.digest(read_bounded(workflow))
    return result


def principal(value: Any) -> str:
    require(isinstance(value, str) and bool(PRINCIPAL.fullmatch(value)),
            "signer identity must be a single explicit principal")
    return value


def now_ms() -> int:
    return int(time.time() * 1000)


def manifest_subject(manifest: dict[str, Any]) -> tuple[int, str, str]:
    require(type(manifest.get("schema_version")) is int
            and manifest["schema_version"] == 1
            and manifest.get("kind") == "uselesskey-promotion-evidence",
            "unsupported promotion manifest")
    require(type(manifest.get("repository_id")) is int
            and manifest["repository_id"] == EVIDENCE.CANONICAL_ID,
            "acceptance is for a different repository")
    number = manifest.get("pull_request")
    require(type(number) is int and number > 0, "invalid promotion PR number")
    return number, EVIDENCE.sha(manifest.get("head")), EVIDENCE.sha(manifest.get("base"))


def acceptance_path(number: int, head: str, base: str) -> str:
    require(type(number) is int and number > 0, "invalid promotion PR number")
    return f"acceptances/{number}/{EVIDENCE.sha(head)}/{EVIDENCE.sha(base)}.json"


def validate_payload(payload: dict[str, Any], *, current_ms: int) -> dict[str, Any]:
    EVIDENCE.exact_keys(payload, {
        "schema_version", "kind", "signer", "signed_at_ms", "expires_at_ms",
        "controls", "manifest",
    })
    require(type(payload["schema_version"]) is int and payload["schema_version"] == 1
            and payload["kind"] == KIND, "unsupported signed acceptance")
    signer = principal(payload["signer"])
    manifest = payload["manifest"]
    require(isinstance(manifest, dict), "signed manifest is missing")
    manifest_subject(manifest)
    accepted = manifest.get("accepted_at_ms")
    signed, expires = payload["signed_at_ms"], payload["expires_at_ms"]
    require(type(accepted) is int and type(signed) is int and type(expires) is int,
            "acceptance timestamps must be integer milliseconds")
    require(0 < accepted <= signed <= current_ms < expires,
            "acceptance is future-dated or expired")
    require(expires - accepted <= MAX_VALIDITY_SECONDS * 1000,
            "acceptance validity exceeds one day from the accepted decision")
    decision = manifest.get("operator_acceptance")
    require(isinstance(decision, dict) and decision.get("actor") == signer,
            "signed principal differs from the acceptance actor")
    require(payload["controls"] == control_digests(),
            "acceptance names different admission controls")
    canonical_bytes(payload)
    return manifest


def ssh_environment(*, signing: bool) -> dict[str, str]:
    # The signature process does not need API credentials or arbitrary inherited
    # loader/provider settings. An existing agent may supply the signing key.
    env = {"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C",
           "SSH_ASKPASS_REQUIRE": "never"}
    if signing and os.environ.get("SSH_AUTH_SOCK"):
        env["SSH_AUTH_SOCK"] = os.environ["SSH_AUTH_SOCK"]
    return env


def ssh_keygen(arguments: list[str], message: bytes, *, signing: bool) -> bytes:
    executable = shutil.which("ssh-keygen")
    require(executable is not None, "OpenSSH ssh-keygen is required")
    try:
        result = subprocess.run([executable, *arguments], input=message,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=30, check=False,
                                env=ssh_environment(signing=signing))
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AcceptanceError("OpenSSH signature operation unavailable") from exc
    require(result.returncode == 0, "OpenSSH signature operation refused")
    require(len(result.stdout) <= SIGNATURE_LIMIT, "OpenSSH output exceeds bound")
    return result.stdout


def sign_acceptance(manifest: dict[str, Any], signer: str, key: Path,
                    valid_for_seconds: int, *, current_ms: int | None = None) -> dict[str, Any]:
    current = now_ms() if current_ms is None else current_ms
    require(type(valid_for_seconds) is int and 0 < valid_for_seconds <= MAX_VALIDITY_SECONDS,
            "signature validity must be between one second and one day")
    require(key.is_file(), "explicit signing key or agent public key is missing")
    payload = {"schema_version": 1, "kind": KIND, "signer": principal(signer),
               "signed_at_ms": current,
               "expires_at_ms": current + valid_for_seconds * 1000,
               "controls": control_digests(), "manifest": manifest}
    validate_payload(payload, current_ms=current)
    signature = ssh_keygen(["-Y", "sign", "-f", str(key.resolve()),
                            "-n", NAMESPACE, "-O", "hashalg=sha512"],
                           canonical_bytes(payload), signing=True)
    bundle = {"payload": payload, "signature": signature.decode("ascii")}
    canonical_bytes(bundle)
    return bundle


def verify_signer_pin(signers: bytes, expected_signers_sha256: str) -> None:
    require(isinstance(expected_signers_sha256, str)
            and bool(EVIDENCE.DIGEST.fullmatch(expected_signers_sha256)),
            "trusted public signer digest is missing")
    require(0 < len(signers) <= SIGNERS_LIMIT
            and EVIDENCE.digest(signers) == expected_signers_sha256,
            "public signer bytes differ from the independent pin")


def verify_signature(bundle: dict[str, Any], signers: bytes, expected_signers_sha256: str,
                     *, current_ms: int | None = None) -> dict[str, Any]:
    current = now_ms() if current_ms is None else current_ms
    EVIDENCE.exact_keys(bundle, {"payload", "signature"})
    verify_signer_pin(signers, expected_signers_sha256)
    manifest = validate_payload(bundle["payload"], current_ms=current)
    signature = bundle["signature"]
    require(isinstance(signature, str) and signature.isascii()
            and 0 < len(signature) <= SIGNATURE_LIMIT
            and signature.startswith("-----BEGIN SSH SIGNATURE-----\n")
            and signature.endswith("-----END SSH SIGNATURE-----\n"),
            "invalid OpenSSH signature envelope")
    # Verify the already-hashed signer bytes, not a path that may change after
    # its digest check. Signature material is data; it is never executed.
    with tempfile.TemporaryDirectory(prefix="uselesskey-acceptance-") as directory:
        root = Path(directory)
        signer_file, signature_file = root / "allowed_signers", root / "acceptance.sig"
        signer_file.write_bytes(signers)
        signature_file.write_text(signature, encoding="ascii")
        ssh_keygen(["-Y", "verify", "-f", str(signer_file),
                    "-I", bundle["payload"]["signer"], "-n", NAMESPACE,
                    "-s", str(signature_file)], canonical_bytes(bundle["payload"]), signing=False)
    return manifest


def ref_head(reader, repository: str) -> str:
    value = reader.get(f"/repos/{repository}/git/ref/heads/ci-acceptance")
    require(isinstance(value, dict) and value.get("ref") == ACCEPTANCE_REF
            and isinstance(value.get("object"), dict)
            and value["object"].get("type") == "commit", "acceptance ref is absent or not a commit")
    return EVIDENCE.sha(value["object"].get("sha"))


def fetch_acceptance(reader, repository: str, number: int, head: str, base: str
                     ) -> tuple[bytes, dict[str, str]]:
    EVIDENCE.repository_identity(reader, repository, EVIDENCE.CANONICAL_ID)
    revision = ref_head(reader, repository)
    path = acceptance_path(number, head, base)
    value = reader.get(f"/repos/{repository}/contents/{path}?ref={revision}")
    require(isinstance(value, dict) and value.get("type") == "file"
            and value.get("path") == path and value.get("encoding") == "base64",
            "acceptance is not the expected Git file")
    try:
        raw = base64.b64decode("".join(value["content"].split()), validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise AcceptanceError("acceptance Git content is malformed") from exc
    require(len(raw) <= EVIDENCE.LIMIT and type(value.get("size")) is int
            and value["size"] == len(raw), "acceptance Git size mismatch")
    blob = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
    require(value.get("sha") == blob, "acceptance Git blob identity mismatch")
    return raw, {"ref": ACCEPTANCE_REF, "commit": revision, "path": path,
                 "blob": blob, "sha256": EVIDENCE.digest(raw)}


def verify_live_acceptance(reader, raw: bytes, signers: bytes, pin: str,
                           repository: str, number: int, head: str, base: str,
                           *, source: dict[str, str] | None = None,
                           clock=now_ms) -> dict[str, Any]:
    bundle = EVIDENCE.json_object(raw)
    manifest = verify_signature(bundle, signers, pin, current_ms=clock())
    report = EVIDENCE.verify_manifest(reader, manifest, repository, number, head, base,
                                      now_ms=clock())
    if source is not None:
        require(ref_head(reader, repository) == source["commit"],
                "acceptance ref changed during verification")
    # Network observations may take several minutes; expiry is checked again.
    validate_payload(bundle["payload"], current_ms=clock())
    report.update({"kind": "uselesskey-signed-promotion-verification",
                   "manifest_sha256": EVIDENCE.digest(canonical_bytes(manifest)),
                   "acceptance": {"authentication": "openssh-signature",
                       "namespace": NAMESPACE, "signer": bundle["payload"]["signer"],
                       "signed_at_ms": bundle["payload"]["signed_at_ms"],
                       "expires_at_ms": bundle["payload"]["expires_at_ms"],
                       "bundle_sha256": EVIDENCE.digest(raw),
                       "allowed_signers_sha256": pin, "source": source,
                       "controls": bundle["payload"]["controls"]}})
    report["limits"] = ["signature authenticates operator acceptance, not command execution",
                        "public signer pins and controls require independent custody",
                        "live state is a bounded observation; native invalidation remains required",
                        "no check-writing, dispatch, queue, or merge authority"]
    return report


class OutputReservation:
    """Write only the fresh inode this invocation owns, never a later path occupant.

    Keep the directory and file descriptors across network/signature operations.
    An interrupted write is not accepted output; callers require both complete
    JSON and successful CLI completion. This is not an atomic-reader interface.
    """

    def __init__(self, path: Path):
        self.path = path.absolute()
        self.directory_fd = self.output_fd = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.directory_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.output_fd = os.open(self.path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600, dir_fd=self.directory_fd)
            self.directory_identity = os.fstat(self.directory_fd)
            self.output_identity = os.fstat(self.output_fd)
            self.write(b'{"mechanical_verification":"incomplete","authority":"none"}\n')
        except BaseException:
            self.close()
            raise

    @staticmethod
    def same_inode(left, right):
        return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)

    def check_identity(self):
        parent = os.stat(self.path.parent, follow_symlinks=False)
        target = os.stat(self.path.name, dir_fd=self.directory_fd, follow_symlinks=False)
        require(stat.S_ISDIR(parent.st_mode) and self.same_inode(parent, self.directory_identity),
                "output parent changed during this invocation")
        require(stat.S_ISREG(target.st_mode) and self.same_inode(target, self.output_identity),
                "output reservation changed during this invocation")

    def write(self, data: bytes):
        self.check_identity()
        os.lseek(self.output_fd, 0, os.SEEK_SET)
        remaining = memoryview(data)
        while remaining:
            count = os.write(self.output_fd, remaining)
            require(count > 0, "output write made no progress")
            remaining = remaining[count:]
        os.ftruncate(self.output_fd, len(data))
        os.fsync(self.output_fd)
        self.check_identity()

    def close(self):
        for field in ("output_fd", "directory_fd"):
            descriptor = getattr(self, field)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, field, None)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def initialize_output(path: Path) -> OutputReservation:
    return OutputReservation(path)


def finish_output(reservation: OutputReservation, value: dict[str, Any]) -> None:
    reservation.write(canonical_bytes(value))
