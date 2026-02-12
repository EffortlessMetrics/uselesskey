# Gemini Context: uselesskey

## Project Overview
**uselesskey** is a Rust workspace designed to generate deterministic and random cryptographic key fixtures (RSA, ECDSA, Ed25519, HMAC) and X.509 certificates for testing purposes. Its primary goal is to prevent the commitment of sensitive material (PEM/DER blobs) to version control systems, thereby avoiding issues with secret scanners like GitGuardian.

**Key Features:**
*   **Order-independent determinism:** `seed + artifact_id -> derived_seed -> artifact`.
*   **Cache-by-identity:** Efficient caching to avoid expensive key generation (especially RSA) during tests.
*   **Negative Fixtures:** Generates corrupt PEMs, truncated DERs, mismatched keys, and invalid certificates (expired, revoked, etc.) for robust error handling tests.
*   **Adapter Pattern:** Separate crates adapt fixtures to popular libraries like `jsonwebtoken`, `rustls`, `ring`, and `aws-lc-rs`.

## Architecture
The project follows a modular workspace structure:
*   **`crates/uselesskey`**: Public facade crate.
*   **`crates/uselesskey-core`**: Core logic (factory, derivation, caching).
*   **`crates/uselesskey-{rsa,ecdsa,ed25519,hmac,x509}`**: Implementation of specific key/cert types.
*   **`crates/uselesskey-{jsonwebtoken,rustls,ring,...}`**: Adapter crates for third-party libraries.
*   **`xtask`**: Automation tool for build, test, and maintenance tasks.

## Building and Running
The project uses `cargo xtask` for most operations.

### Key Commands
*   **Full CI Pipeline:** `cargo xtask ci` (Runs fmt, clippy, tests, feature checks, etc.)
*   **Tests:** `cargo xtask test` (Runs all tests with all features)
*   **Formatting:** `cargo xtask fmt --fix`
*   **Linting:** `cargo xtask clippy`
*   **BDD Tests:** `cargo xtask bdd` (Runs Cucumber scenarios)
*   **Fuzzing:** `cargo xtask fuzz` (Requires `cargo-fuzz`)
*   **Mutation Testing:** `cargo xtask mutants` (Requires `cargo-mutants`)
*   **Check Publish:** `cargo xtask publish-check`
*   **Secret Check:** `cargo xtask no-blob` (Ensures no secret-shaped blobs are in the repo)

### Running Specific Tests
```bash
cargo test -p uselesskey-core
cargo test -p uselesskey-rsa test_name
```

## Development Conventions
*   **Safety:** `#![forbid(unsafe_code)]` is enforced across crates.
*   **Determinism:** Stability of the deterministic derivation algorithms is critical. Do not change them without a version bump.
*   **Security:** Debug implementations must **never** leak key material.
*   **Testing:**
    *   Unit tests use standard `#[test]`.
    *   Property-based tests use `proptest`.
    *   Parameterized tests use `rstest`.
    *   Behavior-driven tests use `cucumber` (in `uselesskey-bdd`).
*   **Dependencies:** External libraries are adapted in separate crates to avoid strict version coupling.

## Key Files
*   `Cargo.toml`: Workspace configuration.
*   `xtask/src/main.rs`: Entry point for automation tasks.
*   `AGENTS.md` / `CLAUDE.md`: Detailed context and design philosophy (highly recommended reading).
*   `.github/workflows/ci.yml`: CI definitions.
