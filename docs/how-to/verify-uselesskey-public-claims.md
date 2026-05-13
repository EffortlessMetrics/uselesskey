# Verify `uselesskey` Public Claims

Use this guide when you need to show a reviewer what `uselesskey` claims, which
commands prove those claims, and where the receipts are written.

The quick rule:

```text
README badge -> public claim -> proof command -> receipt -> boundary
```

## 1. Read the Claim Index

Start with the human-facing claim index:

```text
docs/status/PUBLIC_CLAIMS.md
```

Then generate the machine-readable report from the ledger:

```bash
cargo xtask claim-report
```

The command writes:

```text
target/claim-report/public-claims.md
target/claim-report/public-claims.json
```

For a single claim:

```bash
cargo xtask claim-report --claim scanner-safe-fixtures
```

## 2. Check the Human Page Against the Ledger

`docs/status/PUBLIC_CLAIMS.md` is hand-written so it can stay readable. The
ledger under `policy/claim-ledger.toml` is the parser target.

Check that the page still matches the ledger:

```bash
cargo xtask claim-report --check-public-claims
```

This fails if a stable ledger claim is missing from the page, if the page
references an unknown claim id, if status drifted, if proof commands are not
visible, or if a boundary cell is empty.

## 3. Verify README Badge Claims

The README badge row is a front panel. The generated endpoint JSON is the public
receipt.

```bash
cargo xtask badges --check
```

This checks:

```text
badges/ripr-plus.json
badges/scanner-safe.json
```

`ripr+` is repo-scoped static evidence plus test-efficiency debt. It is not
coverage, runtime mutation proof, or correctness proof.

`scanner-safe fixtures` means repository policy found no committed
secret-shaped fixture blobs. It does not mean every generated export is safe to
commit.

## 4. Verify Scanner-Safe Fixture Claims

Run the scanner-safe reference checks:

```bash
cargo xtask scanner-safe-reference --check
cargo xtask no-blob
cargo xtask badges --check
```

Use these when the reviewer is asking whether the repo has committed
secret-shaped fixture blobs under the configured policy.

Do not use this as proof of production key safety, scanner evasion, or
cryptographic assurance.

## 5. Verify the TLS Contract Pack

Run the TLS bundle proof:

```bash
cargo xtask bundle-proof --profile tls --out target/release-evidence/tls
```

Attach these receipts:

```text
target/release-evidence/tls/tls-contract-pack-proof.md
target/release-evidence/tls/tls-contract-pack-proof.json
```

This proves the documented generated TLS fixtures, receipts, and negative
validation paths. It does not prove mTLS, revocation, certificate transparency,
browser trust-store behavior, production CA custody, or downstream verifier
correctness.

## 6. Verify the Published Install Path

For the current published release:

```bash
cargo xtask cratesio-smoke --version 0.8.0
```

For a future release, replace `0.8.0` with the version under review.

This proves an external crates.io install path for that version. It does not
prove every downstream feature combination, docs.rs completion, or future
registry state.

## 7. Attach Review Evidence

For a security, platform, or release review, attach:

```text
target/claim-report/public-claims.md
target/claim-report/public-claims.json
target/release-evidence/tls/tls-contract-pack-proof.md
target/release-evidence/tls/tls-contract-pack-proof.json
```

Also include the commands you ran and the exact version, branch, or commit under
review.

## Boundaries to Keep Visible

- Public claims are command-backed, not trust-by-README.
- README badges are repo-scoped public markers, not PR evidence.
- PR `ripr` artifacts are diff-scoped and advisory.
- Scanner-safe fixture material is not production key management.
- Contract packs prove documented fixture paths, not complete downstream
  security behavior.
