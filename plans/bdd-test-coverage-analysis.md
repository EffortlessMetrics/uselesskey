# BDD Test Coverage Analysis & Improvement Plan

## Executive Summary

This document analyzes the current BDD test structure in the uselesskey project, identifies gaps in test coverage, and provides a comprehensive plan for expanding the BDD matrix and improving overall test coverage.

## Current BDD Test Structure

### Feature Files Overview

The project has 12 BDD feature files in [`crates/uselesskey-bdd/features/`](../crates/uselesskey-bdd/features/):

| Feature File | Scenarios | Key Coverage Areas |
|-------------|------------|-------------------|
| [`rsa.feature`](../crates/uselesskey-bdd/features/rsa.feature) | 12 | Determinism, random mode, key formats (PKCS8/SPKI PEM/DER), mismatched keys |
| [`ecdsa.feature`](../crates/uselesskey-bdd/features/ecdsa.feature) | 23 | ES256/ES384 variants, determinism, formats, mismatched keys, corruption, JWK support |
| [`ed25519.feature`](../crates/uselesskey-bdd/features/ed25519.feature) | 17 | Determinism, formats, mismatched keys, corruption, JWK support |
| [`hmac.feature`](../crates/uselesskey-bdd/features/hmac.feature) | 4 | Determinism, JWK/JWKS support |
| [`jwk.feature`](../crates/uselesskey-bdd/features/jwk.feature) | 6 | Public/private JWK fields, JWKS structure, kid determinism |
| [`jwks.feature`](../crates/uselesskey-bdd/features/jwks.feature) | 18 | Multi-key JWKS, key type filtering, deterministic ordering, JSON format |
| [`negative.feature`](../crates/uselesskey-bdd/features/negative.feature) | 8 | Corrupted PEM variants, truncated DER |
| [`seed.feature`](../crates/uselesskey-bdd/features/seed.feature) | 7 | Hex seeds (with/without 0x), string seeds, various lengths |
| [`tempfile.feature`](../crates/uselesskey-bdd/features/tempfile.feature) | 2 | Private/public key tempfile writing |
| [`x509.feature`](../crates/uselesskey-bdd/features/x509.feature) | 27 | Determinism, formats, metadata, expired/not-yet-valid variants, corruption, tempfiles |
| [`chain.feature`](../crates/uselesskey-bdd/features/chain.feature) | 15 | Certificate chains (Root → Intermediate → Leaf), SANs, private key matching, negative variants |
| [`cross_key.feature`](../crates/uselesskey-bdd/features/cross_key.feature) | 11 | Key type differences, kid uniqueness, algorithm mismatches, key size differences, JWKS mixing |

**Total BDD Scenarios: ~150**

### BDD Implementation

The BDD tests are implemented in [`crates/uselesskey-bdd/tests/bdd.rs`](../crates/uselesskey-bdd/tests/bdd.rs) using the Cucumber framework:

- **World Structure**: [`UselessWorld`](../crates/uselesskey-bdd/tests/bdd.rs:9) struct maintains state across scenario steps
- **Step Definitions**: Given/When/Then steps for each key type and operation
- **Execution**: Run via `cargo xtask bdd`

### Unit Test Coverage

| Crate | Test Files | Coverage Focus |
|-------|------------|----------------|
| [`uselesskey-core`](../crates/uselesskey-core/tests/) | 3 files | Factory behavior, determinism, seed parsing, negative fixtures |
| [`uselesskey-rsa`](../crates/uselesskey-rsa/tests/) | 1 file | RSA key generation, parsing, determinism, spec validation |
| [`uselesskey-ecdsa`](../crates/uselesskey-ecdsa/tests/) | 2 files | ECDSA key generation, JWK private keys |
| [`uselesskey-ed25519`](../crates/uselesskey-ed25519/tests/) | 2 files | Ed25519 key generation, JWK private keys |
| [`uselesskey-x509`](../crates/uselesskey-x509/tests/) | 0 files | **No unit tests** |
| [`uselesskey-hmac`](../crates/uselesskey-hmac/tests/) | 0 files | **No unit tests** |
| [`uselesskey-jwk`](../crates/uselesskey-jwk/tests/) | 0 files | **No unit tests** |
| [`uselesskey-jsonwebtoken`](../crates/uselesskey-jsonwebtoken/tests/) | 0 files | **No unit tests** |
| [`uselesskey-rustls`](../crates/uselesskey-rustls/tests/) | 0 files | **No unit tests** |
| Adapter crates | 0 files | **No integration tests** |

## Identified Gaps

### 1. Missing BDD Scenarios

#### RSA Feature Gaps
- **RSA-384 and RSA-512 variants**: Only RS256 (2048-bit) is tested
- **RSA key size variations**: No tests for 3072, 4096 bit keys in BDD
- **RSA JWK private fields**: Tests exist in [`jwk.feature`](../crates/uselesskey-bdd/features/jwk.feature) but not in [`rsa.feature`](../crates/uselesskey-bdd/features/rsa.feature)
- **RSA negative fixtures**: Missing BadBase64, Truncate, ExtraBlankLine variants (only in [`negative.feature`](../crates/uselesskey-bdd/features/negative.feature))

#### HMAC Feature Gaps
- **HS384 and HS512 variants**: Only HS256 is tested
- **HMAC negative fixtures**: No corruption or truncation tests
- **HMAC determinism across variants**: No tests for HS384/HS512
- **HMAC formats**: No tests for raw bytes output

#### X.509 Feature Gaps
- **CRL (Certificate Revocation List) support**: [`chain_negative.rs`](../crates/uselesskey-x509/src/chain_negative.rs:24) defines `RevokedLeaf` variant but no BDD tests
- **Hostname mismatch chain variant**: Defined in code but no BDD tests
- **Expired intermediate variant**: Only one BDD scenario, could be expanded
- **X.509 chain negative variants**: Missing tests for `RevokedLeaf`, `HostnameMismatch`

#### JWKS Feature Gaps
- **JWKS with multiple keys of same type**: No tests for multiple RSA keys
- **JWKS rotation scenarios**: No tests for key rotation workflows
- **JWKS filtering**: No tests for filtering by algorithm or key type
- **JWKS from chain fixtures**: No tests for building JWKS from X.509 chains

#### Cross-Crate Integration Gaps
- **jsonwebtoken adapter**: No BDD tests for JWT signing/verification
- **rustls adapter**: No BDD tests for TLS server/client config
- **ring/aws-lc-rs adapters**: No BDD tests for crypto provider integration

#### Edge Case Gaps
- **Empty labels**: No tests for empty string labels
- **Special characters in labels**: No tests for labels with special chars
- **Very long labels**: No tests for label length limits
- **Concurrent factory usage**: No tests for thread safety
- **Cache eviction**: No tests for cache size limits
- **Derivation version changes**: No tests for version migration

### 2. Missing Unit Tests

| Crate | Missing Tests |
|-------|---------------|
| [`uselesskey-x509`](../crates/uselesskey-x509/) | Certificate parsing, chain validation, SAN handling, CRL generation |
| [`uselesskey-hmac`](../crates/uselesskey-hmac/) | Secret generation, JWK conversion, spec validation |
| [`uselesskey-jwk`](../crates/uselesskey-jwk/) | JWKS builder, key serialization, kid generation |
| [`uselesskey-jsonwebtoken`](../crates/uselesskey-jsonwebtoken/) | Encoding/decoding key conversion, algorithm matching |
| [`uselesskey-rustls`](../crates/uselesskey-rustls/) | DER conversion, config building, mTLS scenarios |

### 3. Missing Integration Tests

- **JWT signing/verification with jsonwebtoken**: End-to-end tests
- **TLS handshake with rustls**: Server/client config tests
- **Multi-key JWKS rotation**: Key rollover scenarios
- **Cross-crate compatibility**: Ensuring adapters work together

### 4. Missing Negative Fixture Coverage

| Negative Type | Current Coverage | Missing |
|---------------|------------------|---------|
| PEM Corruption | BadHeader, BadFooter, BadBase64, Truncate, ExtraBlankLine | Missing for HMAC, X.509 specific variants |
| DER Truncation | Tested for all key types | Edge cases (0 bytes, 1 byte, exact length) |
| Mismatched Keys | Tested for all key types | Multi-key mismatch scenarios |
| Expired Certs | Tested for X.509 | Not tested for chains (only intermediate) |
| Hostname Mismatch | Defined in code | No BDD tests |
| Revoked Certs | Defined in code | No BDD tests |
| Unknown CA | Tested in chain.feature | Could expand |

## Proposed Improvements

### Phase 1: Expand Existing BDD Features

#### 1.1 RSA Feature Expansion
- Add RS384 (3072-bit) and RS512 (4096-bit) variant scenarios
- Add key size comparison scenarios
- Add RSA negative fixture scenarios (BadBase64, Truncate, ExtraBlankLine)
- Add RSA JWK private key field validation scenarios

#### 1.2 HMAC Feature Expansion
- Add HS384 and HS512 variant scenarios
- Add HMAC negative fixture scenarios
- Add HMAC format output scenarios (raw bytes)
- Add HMAC determinism across variants

#### 1.3 X.509 Feature Expansion
- Add CRL (revoked leaf) scenarios
- Add hostname mismatch chain scenarios
- Add chain negative variant scenarios (RevokedLeaf, HostnameMismatch)
- Add X.509 chain SAN validation scenarios

#### 1.4 JWKS Feature Expansion
- Add multi-key same-type JWKS scenarios
- Add JWKS rotation scenarios
- Add JWKS filtering scenarios
- Add JWKS from X.509 chain scenarios

### Phase 2: New BDD Features

#### 2.1 JWT Integration Feature
- JWT signing with RSA/ECDSA/Ed25519/HMAC
- JWT verification with JWKS
- JWT algorithm mismatch scenarios
- JWT expired/not-yet-valid scenarios

#### 2.2 TLS Integration Feature
- TLS server config with X.509 chains
- TLS client config with root CA
- mTLS scenarios (client cert validation)
- TLS negative scenarios (expired, unknown CA, hostname mismatch)

#### 2.3 Edge Cases Feature
- Empty label handling
- Special characters in labels
- Very long labels
- Concurrent factory usage
- Cache eviction scenarios
- Derivation version migration

### Phase 3: Unit Test Expansion

#### 3.1 uselesskey-x509 Unit Tests
- Certificate parsing validation
- Chain structure validation
- SAN handling tests
- CRL generation tests
- Negative fixture generation tests

#### 3.2 uselesskey-hmac Unit Tests
- Secret generation validation
- JWK conversion tests
- Spec validation tests
- Property-based tests for determinism

#### 3.3 uselesskey-jwk Unit Tests
- JWKS builder tests
- Key serialization tests
- Kid generation tests
- Multi-key JWKS tests

#### 3.4 Adapter Crate Tests
- jsonwebtoken: Encoding/decoding key conversion
- rustls: DER conversion, config building
- ring/aws-lc-rs: Crypto provider integration

### Phase 4: Integration Tests

#### 4.1 JWT Integration Tests
- End-to-end JWT signing/verification
- Multi-issuer JWKS scenarios
- Key rotation with cached JWKS

#### 4.2 TLS Integration Tests
- Full TLS handshake tests
- mTLS handshake tests
- Certificate validation error scenarios

#### 4.3 Cross-Crate Compatibility
- Adapter interoperability tests
- Multi-adapter scenarios

## Implementation Priority

### High Priority (Core Functionality)
1. RSA RS384/RS512 variant BDD tests
2. HMAC HS384/HS512 variant BDD tests
3. X.509 CRL/revoked leaf BDD tests
4. X.509 hostname mismatch BDD tests
5. uselesskey-x509 unit tests
6. uselesskey-hmac unit tests

### Medium Priority (Integration & Edge Cases)
7. JWT integration BDD feature
8. TLS integration BDD feature
9. JWKS rotation scenarios
10. Edge cases BDD feature
11. Adapter crate unit tests

### Low Priority (Nice to Have)
12. Concurrent factory usage tests
13. Cache eviction tests
14. Derivation version migration tests
15. Cross-crate compatibility tests

## Test Coverage Goals

| Metric | Current | Target |
|--------|----------|--------|
| BDD Scenarios | ~150 | 250+ |
| BDD Feature Files | 12 | 15+ |
| Crates with Unit Tests | 4/12 | 12/12 |
| Adapter Crate Tests | 0 | 100% |
| Integration Test Scenarios | 0 | 20+ |

## Success Criteria

1. All new BDD scenarios pass with `cargo xtask bdd`
2. All unit tests pass with `cargo xtask test`
3. Property-based tests cover critical paths
4. Integration tests demonstrate real-world usage
5. Test coverage report shows >90% line coverage for core crates

## Notes

- BDD tests should remain focused on user-facing behavior
- Unit tests should cover implementation details and edge cases
- Integration tests should verify cross-crate compatibility
- Property-based tests should complement deterministic tests
- Negative fixtures should be first-class citizens in testing
