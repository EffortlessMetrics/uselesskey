# Share a `uselesskey` Verification Pack

Use a verification pack when a security, platform, or release reviewer needs
the public-claim receipts without reading the whole repository.

Until `cargo xtask verification-pack` lands, assemble the same evidence from the
existing commands in this guide.

## 1. Generate the Claim Index

```bash
cargo xtask claim-report
```

Attach:

```text
target/claim-report/public-claims.md
target/claim-report/public-claims.json
```

These files explain which claims exist, which commands prove them, which docs
teach them, and which boundaries apply.

## 2. Generate Claim Proof Receipts

For scanner-safe fixtures:

```bash
cargo xtask claim-proof --claim scanner-safe-fixtures
```

For the TLS contract pack:

```bash
cargo xtask claim-proof --claim tls-contract-pack
```

Attach:

```text
target/claim-proof/scanner-safe-fixtures/receipt.md
target/claim-proof/scanner-safe-fixtures/receipt.json
target/claim-proof/tls-contract-pack/receipt.md
target/claim-proof/tls-contract-pack/receipt.json
```

For all stable supported claims:

```bash
cargo xtask claim-proof --all-stable
```

Do not use `--all-stable` as crates.io release proof. Registry smoke remains a
version-explicit release check.

## 3. Generate Contract-Pack Receipts

```bash
cargo xtask contract-packs --check
cargo xtask contract-packs --format json
```

Attach:

```text
target/contract-packs/contract-packs.md
target/contract-packs/contract-packs.json
```

These files show which contract packs are stable, which claim each pack backs,
which proof command owns it, and which behavior is out of scope.

## 4. Check Badge Endpoints

```bash
cargo xtask badges --check
```

Attach the committed endpoint JSON:

```text
badges/ripr-plus.json
badges/scanner-safe.json
```

Badges are the README front panel. They are not a substitute for the claim
report or claim-proof receipts.

## 5. Add a Short Cover Note

Include the branch, commit, and commands run:

```text
Repository: EffortlessMetrics/uselesskey
Commit: <git sha>
Commands:
  cargo xtask claim-report
  cargo xtask claim-proof --claim scanner-safe-fixtures
  cargo xtask claim-proof --claim tls-contract-pack
  cargo xtask contract-packs --check
  cargo xtask badges --check
```

Keep the boundaries visible:

```text
scanner-safe fixtures do not mean every derived export is safe to commit
TLS contract-pack proof does not prove production PKI or downstream verifier correctness
ripr+ is static evidence and test-efficiency debt, not correctness proof
```

## What Not to Attach

Do not attach generated fixture payloads:

```text
*.pem
*.der
*.key
*.pkcs8
*.jwt
target/release-evidence/*/bundle/
target/scanner-safe-reference/bundle/
```

Attach receipts and metadata instead. The reviewer needs proof of the claim,
not copied secret-shaped test material.
