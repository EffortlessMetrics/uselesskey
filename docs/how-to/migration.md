# Migrating from Committed Key Fixtures to Runtime Generation

This guide helps you replace committed PEM/DER files with runtime-generated fixtures using `uselesskey`.

## Why Migrate

Secret scanners (GitHub, GitGuardian) now evaluate **every commit** in a PR, not just the final state. This means:

- Committing a key and later removing it still triggers an incident
- Path-based ignores require ongoing maintenance and documentation
- Each suppression must be justified to security reviewers

`uselesskey` eliminates this friction: keys exist only in memory during test runs.

## Replace Committed Key Files

### Identifying fixtures to replace

Look for files matching these patterns:
- `*.pem`, `*.key`, `*.der` in `tests/`, `fixtures/`, or `testdata/`
- Base64 blobs in test source files
- `const` or `static` byte arrays that look like keys

### Before: committed fixture

```rust
// tests/fixtures/issuer.pem checked into git
const ISSUER_KEY: &str = include_str!("fixtures/issuer.pem");

#[test]
fn verify_jwt() {
    let key = parse_pem(ISSUER_KEY);
    // ...
}
```

### After: runtime generation

```rust
use uselesskey::{Factory, RsaSpec, RsaFactoryExt};

#[test]
fn verify_jwt() {
    let fx = Factory::random();
    let issuer = fx.rsa("issuer", RsaSpec::rs256());

    let key = parse_pem(issuer.private_key_pkcs8_pem());
    // ...
}
```

### When you need file paths

Some libraries require `Path` arguments:

```rust
#[test]
fn load_key_from_file() {
    let fx = Factory::random();
    let server = fx.rsa("server", RsaSpec::rs256());

    let keyfile = server.write_private_key_pkcs8_pem().unwrap();
    let pubfile = server.write_public_key_spki_pem().unwrap();

    // Files are cleaned up when handles are dropped
    configure_tls(keyfile.path(), pubfile.path());
}
```

## Dealing with Existing Leaked History Findings

If you already have scanner incidents from committed fixtures, you have three options:

### Option 1: Rewrite git history

**When to use:** Pre-release or private repo with few collaborators.

```bash
# Remove fixtures from all history
git filter-repo --path tests/fixtures/keys/ --invert-paths

# Force push (coordinate with team)
git push --force-with-lease
```

Pros: Clean history, scanner finds nothing.
Cons: Rewrites commit hashes, disrupts collaborators.

### Option 2: Mark as false positive

**When to use:** Public repo where history rewrite is impractical.

Create a `.gitguardian.yaml` or configure your scanner to ignore specific paths or commit ranges. Document why these are test fixtures.

Pros: No history disruption.
Cons: Requires ongoing maintenance, security team review.

### Option 3: Accept the incident, prevent future ones

**When to use:** When the key material was truly never secret (test-only).

Acknowledge the incident, document that it was a test fixture, and add `uselesskey` to prevent recurrence.

Pros: Honest approach, minimal disruption.
Cons: Incident remains on record.

## Deterministic Mode Setup

Deterministic mode ensures tests produce identical keys across runs, useful for:
- Debugging flaky tests
- Reproducing CI failures locally
- Snapshot testing

### Seed sources

**Environment variable (recommended for CI):**

```rust
let fx = Factory::deterministic_from_env("USELESSKEY_SEED")
    .unwrap_or_else(Factory::random);
```

```yaml
# GitHub Actions
env:
  USELESSKEY_SEED: ci-stable-seed

# Or use a secret for more randomness
env:
  USELESSKEY_SEED: ${{ secrets.USELESSKEY_SEED }}
```

**Hardcoded seed (for specific tests):**

```rust
use uselesskey::{Factory, Seed};

// Human-readable strings are hashed to 32 bytes
let fx = Factory::deterministic(Seed::from_env_value("my-test-seed").unwrap());

// Or explicit 32-byte hex
let fx = Factory::deterministic(Seed::from_env_value(
    "0x0000000000000000000000000000000000000000000000000000000000000042"
).unwrap());
```

### Reproducibility guarantees

With the same seed:
- Same `(label, spec)` produces identical keys regardless of call order
- Adding new fixtures does not change existing ones
- Results are stable across `uselesskey` patch versions

Derivation algorithm changes (if any) will bump the crate's derivation version.

## Common Migration Patterns

### JWT testing

```rust
use uselesskey::{Factory, RsaSpec, RsaFactoryExt};

fn test_jwt_roundtrip() {
    let fx = Factory::random();
    let issuer = fx.rsa("issuer", RsaSpec::rs256());

    // Sign with private key
    let token = sign_jwt(issuer.private_key_pkcs8_pem(), claims);

    // Verify with public key
    let verified = verify_jwt(issuer.public_key_spki_pem(), &token);
    assert!(verified.is_ok());
}

fn test_jwt_wrong_key_rejected() {
    let fx = Factory::random();
    let issuer = fx.rsa("issuer", RsaSpec::rs256());
    let attacker = fx.rsa("attacker", RsaSpec::rs256());

    let token = sign_jwt(issuer.private_key_pkcs8_pem(), claims);

    // Verification with wrong key should fail
    let result = verify_jwt(attacker.public_key_spki_pem(), &token);
    assert!(result.is_err());
}
```

With the `jwk` feature enabled:

```rust
fn test_jwks_endpoint() {
    let fx = Factory::random();
    let issuer = fx.rsa("issuer", RsaSpec::rs256());

    // Serve this from a mock JWKS endpoint
    let jwks = issuer.public_jwks();

    mock_server.respond_with(jwks.to_string());
}
```

### TLS/mTLS testing

With X.509 certificate chains and the `uselesskey-rustls` adapter:

```rust
use uselesskey::{Factory, X509FactoryExt, ChainSpec};
use uselesskey_rustls::{RustlsServerConfigExt, RustlsClientConfigExt};

fn test_tls_handshake() {
    let fx = Factory::random();
    let chain = fx.x509_chain("my-service", ChainSpec::new("test.example.com"));

    // One-liner config builders
    let server_config = chain.server_config_rustls();
    let client_config = chain.client_config_rustls();

    // Test handshake
    assert!(handshake(&server_config, &client_config).is_ok());
}
```

Or with raw key files for libraries that need paths:

```rust
fn test_tls_with_files() {
    let fx = Factory::random();

    let server = fx.rsa("server", RsaSpec::rs256());
    let client = fx.rsa("client", RsaSpec::rs256());

    let server_key = server.write_private_key_pkcs8_pem().unwrap();
    let client_key = client.write_private_key_pkcs8_pem().unwrap();

    // Configure TLS with file paths
    let server_config = tls_config(server_key.path());
    let client_config = tls_config(client_key.path());

    // Test handshake
    assert!(handshake(&server_config, &client_config).is_ok());
}
```

### X.509 certificate validation testing

```rust
use uselesskey::{Factory, X509FactoryExt, ChainSpec};

fn test_expired_cert_rejected() {
    let fx = Factory::random();
    let chain = fx.x509_chain("my-service", ChainSpec::new("test.example.com"));

    let expired = chain.expired_leaf();
    // Use expired cert in TLS setup — handshake should fail
    assert!(verify_cert(expired.leaf_cert_pem()).is_err());
}

fn test_hostname_mismatch_rejected() {
    let fx = Factory::random();
    let chain = fx.x509_chain("my-service", ChainSpec::new("test.example.com"));

    let wrong = chain.hostname_mismatch("wrong.example.com");
    // SAN doesn't match expected hostname
    assert!(verify_hostname(wrong.leaf_cert_pem(), "test.example.com").is_err());
}

fn test_unknown_ca_rejected() {
    let fx = Factory::random();
    let chain = fx.x509_chain("my-service", ChainSpec::new("test.example.com"));

    let unknown = chain.unknown_ca();
    // Root CA not in trust store
    assert!(verify_chain(unknown.chain_pem(), &trusted_roots).is_err());
}

fn test_revoked_cert_rejected() {
    let fx = Factory::random();
    let chain = fx.x509_chain("my-service", ChainSpec::new("test.example.com"));

    let revoked = chain.revoked_leaf();
    let crl = revoked.crl_pem().expect("CRL present");
    // Leaf appears in CRL
    assert!(check_revocation(revoked.leaf_cert_pem(), &crl).is_err());
}
```

### Key corruption testing (error paths)

```rust
use uselesskey::negative::CorruptPem;

fn test_corrupt_pem_rejected() {
    let fx = Factory::random();
    let issuer = fx.rsa("issuer", RsaSpec::rs256());

    // Various corruption types
    let bad_header = issuer.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    let bad_base64 = issuer.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    let truncated_pem = issuer.private_key_pkcs8_pem_corrupt(
        CorruptPem::Truncate { bytes: 50 }
    );

    assert!(parse_key(&bad_header).is_err());
    assert!(parse_key(&bad_base64).is_err());
    assert!(parse_key(&truncated_pem).is_err());
}

fn test_truncated_der_rejected() {
    let fx = Factory::random();
    let issuer = fx.rsa("issuer", RsaSpec::rs256());

    let truncated = issuer.private_key_pkcs8_der_truncated(32);
    assert!(parse_der(&truncated).is_err());
}

fn test_mismatched_keypair_rejected() {
    let fx = Factory::random();
    let issuer = fx.rsa("issuer", RsaSpec::rs256());

    // Sign with private key
    let signature = sign(issuer.private_key_pkcs8_der(), data);

    // Attempt verify with a different (but valid) public key
    let wrong_pub = issuer.mismatched_public_key_spki_der();
    assert!(verify(&wrong_pub, data, &signature).is_err());
}
```

## Checklist

- [ ] Add `uselesskey` as a dev-dependency
- [ ] Replace `include_str!`/`include_bytes!` with `Factory` calls
- [ ] Delete committed fixture files from the repo
- [ ] Set up `USELESSKEY_SEED` in CI if you need determinism
- [ ] Update `.gitignore` to exclude any remaining key patterns (belt and suspenders)
- [ ] Address existing scanner incidents per your chosen approach
