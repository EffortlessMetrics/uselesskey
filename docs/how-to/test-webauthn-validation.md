# Test WebAuthn ceremony validation with scanner-safe fixtures

You are testing a WebAuthn registration flow or assertion verifier and need
deterministic creation responses, authenticator data, and `clientDataJSON`
payloads — but the COSE credential public keys, attestation objects, and
challenge values must not trigger high-entropy scanners. The
`uselesskey-webauthn` crate produces fixture shapes that match the
WebAuthn ceremony wire format closely enough for parser-and-verifier
tests, while staying deterministic from a seed.

## Generate a WebAuthn fixture

Add the crate as a dev-dependency alongside the core factory:

```toml
[dev-dependencies]
uselesskey-core = "0.9.0"
uselesskey-webauthn = "0.9.0"
```

Then derive a registration and an assertion fixture from the same seed
and spec:

```rust
use uselesskey_core::{Factory, Seed};
use uselesskey_webauthn::{WebAuthnFactoryExt, WebAuthnSpec};

let fx = Factory::deterministic(Seed::from_env_value("webauthn-doctest").unwrap());
let spec = WebAuthnSpec::packed("example.com", b"server-issued-challenge");

let registration = fx.webauthn_registration("user-alice", spec.clone());
let assertion = fx.webauthn_assertion("user-alice", spec);
```

`WebAuthnSpec::packed(rp_id, challenge)` builds the default packed
attestation spec. To produce a self-attestation variant instead, set
`spec.attestation_mode = AttestationMode::SelfAttestation` before
calling the factory. The `(rp_id, challenge, credential_id,
authenticator_model, attestation_mode)` tuple is hashed into the
deterministic cache key, so the same inputs always yield byte-identical
fixtures.

## What the fixture contains

`RegistrationFixture` mirrors the fields a server would extract from an
authenticator response after CBOR-decoding the attestation object:

- `client_data_json: Vec<u8>` — serialized JSON with `type` set to
  `"webauthn.create"`, the base64url-encoded `challenge`, an `origin`
  of `https://<rp_id>`, and `crossOrigin: false`.
- `authenticator_data: Vec<u8>` — RP ID hash (32 bytes), flags byte
  (`0x41` for user-present + attested credential data included),
  big-endian `sign_count` (4 bytes), AAGUID (16 bytes), credential ID
  length and bytes, and the COSE credential public key.
- `attestation_object: Vec<u8>` — CBOR map with `fmt` (`"packed"` or
  `"self"`), `attStmt` (an `alg: -7` plus a deterministic `sig` byte
  string), and `authData`.
- `rp_id_hash: [u8; 32]` — SHA-256 of the RP ID, surfaced for direct
  comparison without re-hashing.
- `sign_count: u32` — derived from the first four bytes of the
  SHA-256 of the spec; stable across reruns.
- `aaguid: [u8; 16]` — derived from the derived seed and
  `authenticator_model`.

`AssertionFixture` carries the same shape minus the attestation object,
plus a `signature: Vec<u8>` computed over the concatenation of
`authenticator_data` and `client_data_json`. The assertion `sign_count`
is `registration.sign_count + 1`, so a monotonic-counter check can be
exercised end-to-end.

The credential public key embedded in `authenticator_data` is a COSE
EC2 map with `kty: 2`, `alg: -7` (ES256), `crv: 1` (P-256), and 32-byte
`x`/`y` byte strings derived from the seed.

## Verify the ceremony in your validator

Feed the fixture bytes through the same parser path your server uses for
real authenticator responses:

1. Parse `client_data_json` as UTF-8 JSON, assert `type ==
   "webauthn.create"` (or `"webauthn.get"` for assertions), and compare
   the decoded `challenge` against the server-issued challenge bytes.
2. Assert `origin == "https://example.com"` (or whatever RP ID you
   passed to `WebAuthnSpec::packed`).
3. CBOR-decode `attestation_object`, extract `authData`, and confirm
   the first 32 bytes equal SHA-256 of the expected RP ID.
4. Decode the COSE credential public key from `authData`, then verify
   that `signature` from the assertion fixture is consistent with the
   bytes the validator hashed (`authenticator_data ||
   sha256(client_data_json)`).

The `signature` field is a deterministic SHA-256 over
`(seed || context || authenticator_data || client_data_json)` — it is
not a real ECDSA signature. Use it to exercise *signature-shape*
plumbing (length, base64url-decode in transport wrappers, mismatch
rejection) rather than cryptographic verification.

## Test failure paths

Build adjacent fixtures by mutating the spec or the output bytes:

- **Wrong RP ID:** call `fx.webauthn_registration("user-alice",
  WebAuthnSpec::packed("attacker.example", challenge))`. The
  `rp_id_hash` will not match the server's expected hash.
- **Wrong origin:** parse `client_data_json`, replace `origin`, and feed
  the mutated JSON. The validator should reject the origin string.
- **Wrong challenge:** generate the fixture with a different challenge
  payload; the base64url-encoded `challenge` field in
  `client_data_json` will not match the server's outstanding challenge.
- **Tampered authenticator data:** flip a byte in
  `assertion.authenticator_data` (for example, a bit in the flags
  byte). The signature check then fails because the recomputed digest
  no longer matches.
- **Replayed sign count:** reuse the registration `sign_count` for an
  assertion check; the monotonic-counter rule should reject it.

Because the fixture is deterministic, each negative case is reproducible
in CI without committing the mutated bytes — regenerate them in the test
itself.

## What this proves

- Your validator parses `clientDataJSON` and rejects unexpected `type`,
  `origin`, or `challenge` values.
- Your validator CBOR-decodes the attestation object, extracts
  `authData`, and applies RP-ID-hash and flags checks.
- Your validator decodes the COSE EC2 credential public key shape and
  surfaces it to the assertion-verification path.
- Your validator rejects mutated authenticator data and replayed sign
  counts.

## What this does NOT prove

- This is **not** an authenticator simulator. It does not implement
  CTAP, USB HID, NFC, or platform-authenticator semantics.
- The `attStmt.sig` and `AssertionFixture.signature` are SHA-256
  digests, not ECDSA signatures. Real cryptographic verification
  against the COSE public key will fail by design.
- No real attestation trust path: packed and self-attestation fixtures
  here do not chain to any FIDO Metadata Service entry, AAGUID
  registry, or real authenticator vendor.
- No coverage of extension outputs, user-verification flag policy
  beyond the fixture's fixed flags byte, or resident-credential
  semantics.

## Scanner-safety boundary

The credential public key, AAGUID, sign counter, and signature bytes
are all derived deterministically from `Seed +
(domain, label, spec, variant)`. No real authenticator secrets are
involved. The COSE public key bytes are not high-entropy keys in any
production sense and do not match registered AAGUIDs. Regenerate
fixtures inside `target/` or in-process during tests rather than
committing the byte payloads — the same scanner-safety posture used by
the OIDC and TLS profiles applies here.

## See also

- [`../../crates/uselesskey-webauthn/README.md`](../../crates/uselesskey-webauthn/README.md)
  — crate-level overview and supported attestation modes.
- [`test-oidc-jwks-validation.md`](test-oidc-jwks-validation.md) — the
  analogous validation-flow how-to for OIDC JWKS, including the
  positive-plus-negative-case structure this guide mirrors.
- [`test-tls-chain-validation.md`](test-tls-chain-validation.md) — the
  TLS chain analogue for cert-shaped validation.
