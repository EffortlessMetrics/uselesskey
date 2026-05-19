# Test TLS chain validation with scanner-safe fixtures

Use this guide when a downstream TLS verifier, hostname check, or
chain-of-trust path needs deterministic fixtures that look like real PEM
certificates, cover the standard rejection paths, and never commit
usable private key material.

The `uselesskey bundle --profile tls` workflow emits six certificate
fixtures plus receipts and an evidence doc. The pack is deterministic
from the bundle seed: re-running it produces byte-identical files.

## Generate the bundle

```bash
uselesskey bundle \
  --profile tls \
  --out target/tls-fixtures

uselesskey verify-bundle \
  --path target/tls-fixtures

uselesskey inspect-bundle \
  --path target/tls-fixtures
```

From a repo checkout while changing the CLI, prefix those subcommands with
`cargo run -p uselesskey-cli --`.

The profile writes:

- `certs/valid-leaf.pem`
- `certs/valid-chain.pem` — leaf + intermediate + root
- `certs/negative-expired-leaf.pem`
- `certs/negative-not-yet-valid.pem`
- `certs/negative-wrong-hostname.pem`
- `certs/negative-untrusted-root.pem`
- `evidence/tls-profile.md`
- `receipts/materialization.json`
- `receipts/audit-surface.json`
- `receipts/bundle-verification.json`
- `receipts/scanner-safety.json`
- `receipts/negative-coverage.json`
- `manifest.json`

`inspect-bundle` prints the profile, artifact count, scanner-safety
posture, and receipt kinds. It does not print PEM payloads.

## Hostnames

The bundle's evidence doc records the documented hostnames the verifier
should compare against:

| Role | Hostname |
| --- | --- |
| Expected hostname | `valid.tls.uselesskey.test` |
| Hostname-mismatch wrong hostname | `wrong.tls.uselesskey.test` |

Use the expected hostname when asking your verifier to validate the
happy-path fixtures. Use the wrong hostname only as a reference when
asserting on the wrong-hostname negative case.

## Valid path

`certs/valid-leaf.pem` is a leaf signed by the bundle's intermediate.
`certs/valid-chain.pem` concatenates leaf, intermediate, and root in
standard PEM order. Configure your verifier with the bundle's root as a
trust anchor and validate against `valid.tls.uselesskey.test`.

What this proves:

- The verifier constructs a chain through an intermediate to a trust
  anchor in the chain blob.
- The verifier accepts a SAN/CN that matches the expected hostname.

What this does not prove:

- Real CA trust-store behavior, browser-trust-store simulation, or
  pinning.
- Revocation, OCSP, OCSP stapling, or CT log presence.
- ALPN, SNI routing, or cipher suite negotiation.

## Expired-leaf negative

`certs/negative-expired-leaf.pem` is a leaf whose `notAfter` is fixed
in the past. The verifier should reject it on a date-bounds check,
returning the rustls / webpki / verifier-equivalent expired-certificate
error.

What this proves:

- The verifier enforces `notAfter`.

What this does not prove:

- Off-by-one second boundaries, leap-second handling, or other
  date-edge cases.

## Not-yet-valid leaf negative

`certs/negative-not-yet-valid.pem` is a leaf whose `notBefore` is fixed
in the future. The verifier should reject it as not yet valid where the
verifier exposes that distinction.

What this proves:

- The verifier enforces `notBefore`.

What this does not prove:

- Clock-skew tolerance configuration or grace-window behavior beyond
  exact date bounds.

## Wrong-hostname leaf negative

`certs/negative-wrong-hostname.pem` is a cryptographically valid leaf
whose SAN/CN is `wrong.tls.uselesskey.test` rather than the expected
`valid.tls.uselesskey.test`. The verifier should reject it with a
hostname-mismatch error path when asked to validate against the
expected hostname.

What this proves:

- The verifier ties chain validation to the expected-hostname check.

What this does not prove:

- Wildcard SAN evaluation, IP-SAN handling, IDN normalization, or
  alternative-name precedence beyond this single wrong-hostname case.

## Untrusted-root leaf negative

`certs/negative-untrusted-root.pem` is a leaf signed by a CA that is
not in `valid-chain.pem`. The verifier should reject it as having an
unknown issuer when only the bundle's primary root is configured as a
trust anchor.

What this proves:

- The verifier rejects chains that do not terminate in a trusted root.

What this does not prove:

- Trust-store merging, system-trust fallback, cross-signed chain
  handling, or pinning behavior.

## Adapter helpers

Tests that prefer typed Rust values over re-parsing PEM should use the
adapter crates. `uselesskey-rustls` exposes helpers that turn the
bundle into rustls trust-store and per-leaf material plus accessors for
each negative fixture. `uselesskey-tonic` re-exports the same negative
accessors so a tonic-using test crate does not need to depend on
`uselesskey-rustls` directly. The adapters do not add new verifier
behavior; the rejection paths are the verifier's own.

## Evidence

Repo-checkout proof that the bundle still reproduces:

```bash
cargo xtask bundle-proof --profile tls --out target/release-evidence/tls
cargo xtask no-blob
cargo test -p uselesskey-cli tls_profile --all-features
```

`bundle-proof` writes `tls-contract-pack-proof.json` and
`tls-contract-pack-proof.md` under `target/release-evidence/tls/`.

## Scanner-safety note

The PEM bytes in this bundle are scanner-safe by construction:
generated deterministically from the bundle seed, never reused, never
production key material. As with the OIDC and scanner-safe packs, keep
generated cert exports under `target/` rather than committing them. See
[`../release/publish-recovery.md`](../release/publish-recovery.md) for
the registry-truth analogue and
[`../release/v0.8.0-tls-profile-design.md`](../release/v0.8.0-tls-profile-design.md)
for the full out-of-scope list.

## What this does not prove

- It does not prove mTLS client-cert chains.
- It does not prove revocation handling, OCSP, OCSP stapling, or CRL
  consumption.
- It does not prove CT log fixtures or browser-trust-store simulation.
- It does not prove production CA custody or any production crypto
  guarantee.
- It does not replace adapter-specific tests when native downstream
  types matter.

## See also

- [`test-oidc-jwks-validation.md`](test-oidc-jwks-validation.md) — the
  OIDC analogue for JWKS validation.
- [`generate-scanner-safe-k8s-secret.md`](generate-scanner-safe-k8s-secret.md)
  — Kubernetes Secret export workflow.
- [`../release/v0.8.0-tls-profile-design.md`](../release/v0.8.0-tls-profile-design.md)
  — design doc with per-fixture spec, adapter contracts, and evidence
  routing.
