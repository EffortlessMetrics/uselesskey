# Use PKCS#11 mock fixtures for HSM-shaped tests

You're testing code that pretends to talk to an HSM through PKCS#11 — token
labels, slot IDs, key handles, mechanism choices. You need deterministic
fixtures that match what a real cryptoki library would expose, without
depending on softhsm, yubihsm, or an actual device.

The `uselesskey-pkcs11-mock` crate provides a tiny in-memory provider that
exposes slot/token metadata, one or more key handles, a `sign` / `verify`
pair, and a placeholder DER certificate per key. The shape is what your code
under test consumes; the cryptography is deliberately mock.

## Provision the mock slot

```toml
[dev-dependencies]
uselesskey-core = { version = "0.7", default-features = false }
uselesskey-pkcs11-mock = { version = "0.7" }
```

```rust
use uselesskey_core::{Factory, Seed};
use uselesskey_pkcs11_mock::{Pkcs11MockFactoryExt, Pkcs11MockSpec};

let fx = Factory::deterministic(Seed::from_env_value("pkcs11-test").unwrap());
let provider = fx.pkcs11_mock("test-slot", Pkcs11MockSpec::basic("HSM-A"));

let slot = provider.slot_info();
assert_eq!(slot.token_label, "HSM-A");

let handle = provider.key_handles()[0];
let sig = provider.sign(handle, b"hello").expect("known handle");
assert!(provider.verify(handle, b"hello", &sig));
```

`Factory::deterministic(seed)` makes every field below — slot ID, serial
number, key secret — a stable function of `seed + label + spec`. Re-running
the test produces byte-identical provider state. `Factory::random()` is
available for tests that only care about the shape.

## What the fixture provides

`Pkcs11MockSpec::basic(token_label)` is the canonical entry point. It seeds
a spec with `manufacturer_id = "uselesskey"`, `model = "UK-PKCS11-MOCK"`,
and a single key labelled `signing-key`. Override `key_labels` to provision
additional keys:

```rust
let mut spec = Pkcs11MockSpec::basic("HSM-MULTI");
spec.key_labels = vec![
    "signing-key".to_string(),
    "verification-key".to_string(),
];
let provider = fx.pkcs11_mock("multi", spec);
assert_eq!(provider.key_handles().len(), 2);
```

The provider exposes:

| Method | Returns | Notes |
| --- | --- | --- |
| `slot_info()` | `SlotTokenInfo` | `slot_id`, `token_label`, `manufacturer_id`, `model`, `serial_number` |
| `key_handles()` | `Vec<KeyHandle>` | 1-based, sorted, stable order |
| `key_label(handle)` | `Option<&str>` | `None` for unknown handles |
| `certificate_der(handle)` | `Option<&[u8]>` | DER-looking bytes, not a parseable X.509 |
| `sign(handle, msg)` | `Option<Vec<u8>>` | `None` for unknown handles |
| `verify(handle, msg, sig)` | `bool` | `false` for unknown handles or wrong signature |
| `next_sign_count()` | `u64` | Monotonic counter for "did the HSM see this call?" assertions |

Key handles are sequential `u64` values starting at 1. Slot IDs and
serial numbers are derived from the seed and stable across runs in
deterministic mode.

## Use the fixture in your test

Your code under test almost certainly talks to PKCS#11 through some
abstraction — a trait, a `Provider` interface, or a `dyn`-erased session
type. Wire `MockPkcs11Provider` behind that abstraction so the mock answers
the questions your code actually asks:

```rust
trait HsmSession {
    fn token_label(&self) -> String;
    fn list_keys(&self) -> Vec<u64>;
    fn sign(&self, handle: u64, msg: &[u8]) -> Result<Vec<u8>, HsmError>;
}

struct MockSession(uselesskey_pkcs11_mock::MockPkcs11Provider);

impl HsmSession for MockSession {
    fn token_label(&self) -> String {
        self.0.slot_info().token_label
    }

    fn list_keys(&self) -> Vec<u64> {
        self.0.key_handles().into_iter().map(|h| h.0).collect()
    }

    fn sign(&self, handle: u64, msg: &[u8]) -> Result<Vec<u8>, HsmError> {
        use uselesskey_pkcs11_mock::KeyHandle;
        self.0
            .sign(KeyHandle(handle), msg)
            .ok_or(HsmError::ObjectHandleInvalid)
    }
}
```

That is the boundary the fixture is designed for. Your code's PKCS#11
parsing, handle bookkeeping, and error mapping run against a mock that
behaves predictably.

## Test failure paths

The provider gives you three direct negatives without needing extra spec
variants:

- **Unknown key handle.** Build an arbitrary `KeyHandle(9999)` and pass it
  to `sign` or `key_label`. Both return `None`. Map that to your
  PKCS#11 abstraction's `CKR_OBJECT_HANDLE_INVALID` equivalent and assert
  on it.
- **Wrong slot or token label.** Provision the mock with one
  `token_label`, then have the system under test request a different one.
  Your slot-lookup code should fail before it ever asks for a handle.
- **Signature mismatch.** Call `verify(handle, msg, &tampered)` with a
  signature that does not match the input. The provider returns `false`.

For mechanism-mismatch coverage — for example, your code under test asks
for RSA-PSS on what should be an ECDSA key — drive the negative on your
code's side: the mock's `sign` is mechanism-agnostic, so the rejection has
to come from the trait or session layer that decides which mechanism a
handle supports. Encode that policy in your `HsmSession` impl rather than
expecting the fixture to enforce it.

## What this proves

- Your code handles PKCS#11 shapes correctly: slot metadata, token labels,
  key handles, and signature byte buffers move through your abstraction
  without surprises.
- Your code routes signing requests to the correct key handle and
  surfaces a useful error when the handle is unknown.
- Your code interprets monotonic call counters and per-call response
  shapes — useful for "did the HSM see this request?" assertions.

## What this does not prove

- The mock is not a real PKCS#11 implementation. There is no cryptoki
  library, no C ABI, no `pkcs11.h`-conformant return-code surface.
- No FIPS validation. Mock signatures are SHA-256 over `secret || alg ||
  msg`, not RSA, ECDSA, or any production algorithm.
- No real HSM behavior under load: no session limits, no concurrent-login
  semantics, no PIN policy, no rate limits.
- No attestation, key wrapping, key unwrapping, or attestation-statement
  contents beyond the mock's `certificate_der` placeholder.
- The DER-looking bytes from `certificate_der` are not parseable as
  X.509. Use `uselesskey-x509` for tests that need real certificate
  fixtures.

## Scanner-safety boundary

Mock keys are deterministic test material derived from the factory seed.
Don't commit serialised handles, the bytes from `certificate_der`, or any
exported representation of the mock's key secret. Treat the mock the same
way you treat any other uselesskey fixture: generate at test time, keep
generated artefacts under `target/`, and rely on `cargo xtask no-blob` to
catch accidental commits.

## See also

- [`../../crates/uselesskey-pkcs11-mock/README.md`](../../crates/uselesskey-pkcs11-mock/README.md)
  — crate-level overview.
- [`test-oidc-jwks-validation.md`](test-oidc-jwks-validation.md) — the
  JWKS analogue for OIDC validators.
- [`test-tls-chain-validation.md`](test-tls-chain-validation.md) — TLS
  chain validation with the bundled fixture profile.
