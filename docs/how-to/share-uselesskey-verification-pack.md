# Share a `uselesskey` Verification Pack

Use a verification pack when a security, platform, or release reviewer needs
the public-claim receipts without reading the whole repository.

Build the default pack:

```bash
cargo xtask verification-pack --out target/uselesskey-verification
```

Build a claim-filtered pack:

```bash
cargo xtask verification-pack --out target/uselesskey-verification-scanner-safe --claim scanner-safe-fixtures
```

The command writes receipts and metadata only. It does not copy generated
secret-shaped fixture payloads into the review pack.

## 1. Read the Pack

Start with:

```text
target/uselesskey-verification/README.md
```

The README records the commit, commands, included claims, and boundaries. Attach
the whole directory if your review system accepts folders, or attach the files
listed below.

## 2. Include the Claim Index

Attach:

```text
target/uselesskey-verification/public-claims.md
target/uselesskey-verification/public-claims.json
```

These files explain which claims exist, which commands prove them, which docs
teach them, and which boundaries apply.

## 3. Include Claim Proof Receipts

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
target/uselesskey-verification/claim-proof/scanner-safe-fixtures/receipt.md
target/uselesskey-verification/claim-proof/scanner-safe-fixtures/receipt.json
target/uselesskey-verification/claim-proof/tls-contract-pack/receipt.md
target/uselesskey-verification/claim-proof/tls-contract-pack/receipt.json
```

For all stable supported claims:

```bash
cargo xtask claim-proof --all-stable
```

Do not use `--all-stable` as crates.io release proof. Registry smoke remains a
version-explicit release check.

## 4. Include Contract-Pack Receipts

```bash
cargo xtask contract-packs --check
cargo xtask contract-packs --format json
```

Attach:

```text
target/uselesskey-verification/contract-packs.md
target/uselesskey-verification/contract-packs.json
```

These files show which contract packs are stable, which claim each pack backs,
which proof command owns it, and which behavior is out of scope.

## 5. Include Badge Endpoints

```bash
cargo xtask badges --check
```

Attach the committed endpoint JSON:

```text
target/uselesskey-verification/badges/ripr-plus.json
target/uselesskey-verification/badges/scanner-safe.json
```

Badges are the README front panel. They are not a substitute for the claim
report or claim-proof receipts.

## 6. Add a Short Cover Note

Include the branch, commit, and commands run:

```text
Repository: EffortlessMetrics/uselesskey
Commit: <git sha>
Commands:
  cargo xtask verification-pack --out target/uselesskey-verification
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
