# BDD Scenarios Implementation Plan

This document provides detailed BDD scenarios to implement for expanding the test coverage in the uselesskey project.

## Phase 1: Expand Existing BDD Features

### 1.1 RSA Feature Expansion (`rsa.feature`)

#### New Scenarios for RS384 and RS512

```gherkin
# --- RSA variants ---

Scenario: deterministic RS384 fixtures are stable
  Given a deterministic factory seeded with "rs384-seed"
  When I generate an RSA key for label "rs384-issuer" with spec RS384
  And I generate an RSA key for label "rs384-issuer" with spec RS384 again
  Then the PKCS8 PEM should be identical

Scenario: deterministic RS512 fixtures are stable
  Given a deterministic factory seeded with "rs512-seed"
  When I generate an RSA key for label "rs512-issuer" with spec RS512
  And I generate an RSA key for label "rs512-issuer" with spec RS512 again
  Then the PKCS8 PEM should be identical

Scenario: RSA RS256 and RS384 produce different keys for same label
  Given a deterministic factory seeded with "rsa-variant-test"
  When I generate an RSA key for label "shared-label" with spec RS256
  And I generate another RSA key for label "shared-label" with spec RS384
  Then the keys should have different moduli

Scenario: RSA RS384 and RS512 produce different keys for same label
  Given a deterministic factory seeded with "rsa-variant-test-2"
  When I generate an RSA key for label "shared-label" with spec RS384
  And I generate another RSA key for label "shared-label" with spec RS512
  Then the keys should have different moduli

# --- RSA key sizes ---

Scenario: RSA 2048-bit key has correct modulus size
  Given a deterministic factory seeded with "rsa-size-test"
  When I generate an RSA key for label "rsa-2048" with spec 2048
  Then the RSA modulus should have 256 bytes

Scenario: RSA 3072-bit key has correct modulus size
  Given a deterministic factory seeded with "rsa-size-test"
  When I generate an RSA key for label "rsa-3072" with spec 3072
  Then the RSA modulus should have 384 bytes

Scenario: RSA 4096-bit key has correct modulus size
  Given a deterministic factory seeded with "rsa-size-test"
  When I generate an RSA key for label "rsa-4096" with spec 4096
  Then the RSA modulus should have 512 bytes

# --- RSA JWK private fields ---

Scenario: RSA private JWK has all required parameters
  Given a deterministic factory seeded with "rsa-jwk-priv-test"
  When I generate an RSA key for label "rsa-priv"
  Then the RSA private JWK should have d parameter
  And the RSA private JWK should have p parameter
  And the RSA private JWK should have q parameter
  And the RSA private JWK should have dp parameter
  And the RSA private JWK should have dq parameter
  And the RSA private JWK should have qi parameter

# --- RSA negative fixtures ---

Scenario: RSA corrupted PEM with BadBase64
  Given a deterministic factory seeded with "rsa-badbase64-test"
  When I generate an RSA key for label "rsa-corrupt"
  And I corrupt the PKCS8 PEM with BadBase64
  Then the corrupted PEM should contain "THIS_IS_NOT_BASE64"
  And the corrupted PEM should fail to parse

Scenario: RSA corrupted PEM with Truncate
  Given a deterministic factory seeded with "rsa-truncate-test"
  When I generate an RSA key for label "rsa-truncate"
  And I corrupt the PKCS8 PEM with Truncate to 50 bytes
  Then the corrupted PEM should have length 50
  And the corrupted PEM should fail to parse

Scenario: RSA corrupted PEM with ExtraBlankLine
  Given a deterministic factory seeded with "rsa-blankline-test"
  When I generate an RSA key for label "rsa-blankline"
  And I corrupt the PKCS8 PEM with ExtraBlankLine
  Then the corrupted PEM should fail to parse
```

### 1.2 HMAC Feature Expansion (`hmac.feature`)

#### New Scenarios for HS384 and HS512

```gherkin
# --- HMAC variants ---

Scenario: deterministic HS384 secrets are stable
  Given a deterministic factory seeded with "hs384-seed"
  When I generate an HMAC HS384 secret for label "hs384-issuer"
  And I generate an HMAC HS384 secret for label "hs384-issuer" again
  Then the HMAC secrets should be identical

Scenario: deterministic HS512 secrets are stable
  Given a deterministic factory seeded with "hs512-seed"
  When I generate an HMAC HS512 secret for label "hs512-issuer"
  And I generate an HMAC HS512 secret for label "hs512-issuer" again
  Then the HMAC secrets should be identical

Scenario: HMAC HS256 and HS384 produce different secrets for same label
  Given a deterministic factory seeded with "hmac-variant-test"
  When I generate an HMAC HS256 secret for label "shared-label"
  And I generate another HMAC HS384 secret for label "shared-label"
  Then the HMAC secrets should be different

Scenario: HMAC HS384 and HS512 produce different secrets for same label
  Given a deterministic factory seeded with "hmac-variant-test-2"
  When I generate an HMAC HS384 secret for label "shared-label"
  And I generate another HMAC HS512 secret for label "shared-label"
  Then the HMAC secrets should be different

# --- HMAC formats ---

Scenario: HMAC secret bytes are accessible
  Given a deterministic factory seeded with "hmac-bytes-test"
  When I generate an HMAC HS256 secret for label "hmac-bytes"
  Then the HMAC secret bytes should have length 32

Scenario: HMAC HS384 secret bytes have correct length
  Given a deterministic factory seeded with "hmac-hs384-bytes-test"
  When I generate an HMAC HS384 secret for label "hmac-hs384"
  Then the HMAC secret bytes should have length 48

Scenario: HMAC HS512 secret bytes have correct length
  Given a deterministic factory seeded with "hmac-hs512-bytes-test"
  When I generate an HMAC HS512 secret for label "hmac-hs512"
  Then the HMAC secret bytes should have length 64

# --- HMAC negative fixtures ---

Scenario: HMAC corrupted PEM with BadHeader
  Given a deterministic factory seeded with "hmac-corrupt-test"
  When I generate an HMAC HS256 secret for label "hmac-corrupt"
  And I corrupt the HMAC PEM with BadHeader
  Then the corrupted HMAC PEM should contain "-----BEGIN CORRUPTED KEY-----"

Scenario: HMAC truncated DER fails to parse
  Given a deterministic factory seeded with "hmac-truncate-test"
  When I generate an HMAC HS256 secret for label "hmac-truncate"
  And I truncate the HMAC DER to 10 bytes
  Then the truncated HMAC DER should have length 10
  And the truncated HMAC DER should fail to parse

# --- HMAC JWKS ---

Scenario: HMAC HS384 JWK has required fields
  Given a deterministic factory seeded with "hmac-hs384-jwk"
  When I generate an HMAC HS384 secret for label "hs384-signer"
  Then the HMAC JWK should have kty "oct"
  And the HMAC JWK should have alg "HS384"
  And the HMAC JWK should have use "sig"
  And the HMAC JWK should have a kid
  And the HMAC JWK should have k parameter

Scenario: HMAC HS512 JWK has required fields
  Given a deterministic factory seeded with "hmac-hs512-jwk"
  When I generate an HMAC HS512 secret for label "hs512-signer"
  Then the HMAC JWK should have kty "oct"
  And the HMAC JWK should have alg "HS512"
  And the HMAC JWK should have use "sig"
  And the HMAC JWK should have a kid
  And the HMAC JWK should have k parameter
```

### 1.3 X.509 Feature Expansion (`x509.feature`)

#### New Scenarios for CRL and Revoked Certs

```gherkin
# --- CRL and Revoked Certs ---

Scenario: X.509 certificate chain with revoked leaf
  Given a deterministic factory seeded with "crl-test"
  When I generate a certificate chain for domain "test.example.com" with label "revoked-chain"
  And I get the revoked leaf variant of the certificate chain
  Then the revoked leaf certificate should be parseable
  And the revoked leaf certificate should have a CRL distribution point

Scenario: revoked leaf certificate is different from valid
  Given a deterministic factory seeded with "revoked-diff-test"
  When I generate a certificate chain for domain "test.example.com" with label "revoked-check"
  And I get the revoked leaf variant of the certificate chain
  Then the revoked leaf certificate should differ from the valid leaf certificate

# --- Hostname Mismatch ---

Scenario: X.509 certificate chain with hostname mismatch
  Given a deterministic factory seeded with "hostname-mismatch-test"
  When I generate a certificate chain for domain "test.example.com" with label "mismatch-chain"
  And I get the hostname mismatch variant with "wrong.example.com"
  Then the leaf certificate should have common name "wrong.example.com"
  And the leaf certificate should not contain SAN "test.example.com"

Scenario: hostname mismatch chain is different from valid
  Given a deterministic factory seeded with "hostname-diff-test"
  When I generate a certificate chain for domain "test.example.com" with label "hostname-check"
  And I get the hostname mismatch variant with "wrong.example.com"
  Then the hostname mismatch leaf certificate should differ from the valid leaf certificate

# --- Chain Negative Variants ---

Scenario: X.509 certificate chain with expired leaf
  Given a deterministic factory seeded with "expired-leaf-test"
  When I generate a certificate chain for domain "test.example.com" with label "expired-leaf-chain"
  And I get the expired leaf variant of the certificate chain
  Then the expired leaf certificate should have not_after in the past
  And the intermediate certificate should be valid

Scenario: X.509 certificate chain with expired intermediate
  Given a deterministic factory seeded with "expired-int-test"
  When I generate a certificate chain for domain "test.example.com" with label "expired-int-chain"
  And I get the expired intermediate variant of the certificate chain
  Then the expired intermediate certificate should have not_after in the past
  And the leaf certificate should be valid

# --- SAN Validation ---

Scenario: X.509 certificate with multiple SANs
  Given a deterministic factory seeded with "san-test"
  When I generate an X.509 certificate for domain "test.example.com" with label "multi-san"
  And I add SAN "localhost" to the X.509 certificate
  And I add SAN "127.0.0.1" to the X.509 certificate
  And I add SAN "*.example.com" to the X.509 certificate
  Then the X.509 certificate should contain SAN "test.example.com"
  And the X.509 certificate should contain SAN "localhost"
  And the X.509 certificate should contain SAN "127.0.0.1"
  And the X.509 certificate should contain SAN "*.example.com"

Scenario: X.509 certificate chain SANs are in leaf only
  Given a deterministic factory seeded with "chain-san-test"
  When I generate a certificate chain for domain "test.example.com" with label "san-chain"
  And I add SAN "localhost" to the certificate chain
  Then the leaf certificate should contain SAN "test.example.com"
  And the leaf certificate should contain SAN "localhost"
  And the intermediate certificate should not contain SAN "localhost"
  And the root certificate should not contain SAN "localhost"
```

### 1.4 JWKS Feature Expansion (`jwks.feature`)

#### New Scenarios for Multi-Key and Rotation

```gherkin
# --- Multi-Key Same Type ---

Scenario: JWKS with multiple RSA keys
  Given a deterministic factory seeded with "multi-rsa-test"
  When I generate an RSA key for label "rsa-1" with spec RS256
  And I generate an RSA key for label "rsa-2" with spec RS256
  And I build a JWKS with the RSA keys with kids "key-1" and "key-2"
  Then the JWKS should contain 2 keys
  And each key in the JWKS should have kty "RSA"
  And each key in the JWKS should have a unique kid

Scenario: JWKS with multiple ECDSA keys
  Given a deterministic factory seeded with "multi-ecdsa-test"
  When I generate an ECDSA ES256 key for label "ecdsa-1"
  And I generate an ECDSA ES256 key for label "ecdsa-2"
  And I build a JWKS with the ECDSA keys with kids "es256-1" and "es256-2"
  Then the JWKS should contain 2 keys
  And each key in the JWKS should have kty "EC"
  And each key in the JWKS should have a unique kid

# --- JWKS Rotation ---

Scenario: JWKS rotation adds new key
  Given a deterministic factory seeded with "rotation-test"
  When I generate an RSA key for label "key-v1" with spec RS256
  And I build a JWKS containing the RSA key with kid "v1"
  Then the JWKS should contain 1 key
  When I generate an RSA key for label "key-v2" with spec RS256
  And I build a JWKS containing both keys with kids "v1" and "v2"
  Then the JWKS should contain 2 keys
  And the JWKS should contain a key with kid "v1"
  And the JWKS should contain a key with kid "v2"

Scenario: JWKS rotation removes old key
  Given a deterministic factory seeded with "rotation-remove-test"
  When I generate an RSA key for label "key-v1" with spec RS256
  And I generate an RSA key for label "key-v2" with spec RS256
  And I build a JWKS with both keys with kids "v1" and "v2"
  Then the JWKS should contain 2 keys
  When I build a JWKS with only the second key with kid "v2"
  Then the JWKS should contain 1 key
  And the JWKS should contain a key with kid "v2"
  And the JWKS should not contain a key with kid "v1"

# --- JWKS Filtering ---

Scenario: JWKS filtering by algorithm
  Given a deterministic factory seeded with "filter-test"
  When I generate an RSA key for label "rsa-key" with spec RS256
  And I generate an ECDSA ES256 key for label "ecdsa-key"
  And I generate an HMAC HS256 secret for label "hmac-key"
  And I build a JWKS containing all keys
  Then the JWKS should contain 3 keys
  And the JWKS should contain a key with alg "RS256"
  And the JWKS should contain a key with alg "ES256"
  And the JWKS should contain a key with alg "HS256"

# --- JWKS from X.509 ---

Scenario: JWKS from X.509 certificate
  Given a deterministic factory seeded with "x509-jwks-test"
  When I generate an X.509 certificate for domain "test.example.com" with label "x509-jwks"
  Then the X.509 certificate should have a JWK representation
  And the X.509 certificate JWK should have kty "RSA"
  And the X.509 certificate JWK should have a kid
```

## Phase 2: New BDD Features

### 2.1 JWT Integration Feature (`jwt.feature`)

```gherkin
Feature: JWT signing and verification
  As a test author
  I want to sign and verify JWTs with uselesskey fixtures
  So that I can test JWT-based authentication flows

  # --- JWT Signing ---

  Scenario: sign JWT with RSA RS256
    Given a deterministic factory seeded with "jwt-rsa-test"
    When I generate an RSA key for label "jwt-issuer" with spec RS256
    And I sign a JWT with the RSA key
    Then the JWT should be valid
    And the JWT header should have alg "RS256"

  Scenario: sign JWT with ECDSA ES256
    Given a deterministic factory seeded with "jwt-ecdsa-test"
    When I generate an ECDSA ES256 key for label "jwt-issuer"
    And I sign a JWT with the ECDSA key
    Then the JWT should be valid
    And the JWT header should have alg "ES256"

  Scenario: sign JWT with Ed25519
    Given a deterministic factory seeded with "jwt-ed25519-test"
    When I generate an Ed25519 key for label "jwt-issuer"
    And I sign a JWT with the Ed25519 key
    Then the JWT should be valid
    And the JWT header should have alg "EdDSA"

  Scenario: sign JWT with HMAC HS256
    Given a deterministic factory seeded with "jwt-hmac-test"
    When I generate an HMAC HS256 secret for label "jwt-issuer"
    And I sign a JWT with the HMAC secret
    Then the JWT should be valid
    And the JWT header should have alg "HS256"

  # --- JWT Verification ---

  Scenario: verify JWT with RSA public key
    Given a deterministic factory seeded with "jwt-verify-rsa-test"
    When I generate an RSA key for label "jwt-verifier" with spec RS256
    And I sign a JWT with the RSA key
    And I verify the JWT with the RSA public key
    Then the JWT should verify successfully

  Scenario: verify JWT with JWKS
    Given a deterministic factory seeded with "jwt-jwks-test"
    When I generate an RSA key for label "jwt-jwks" with spec RS256
    And I build a JWKS containing the RSA key with kid "jwt-key"
    And I sign a JWT with the RSA key
    And I verify the JWT with the JWKS
    Then the JWT should verify successfully

  # --- JWT Algorithm Mismatch ---

  Scenario: verify JWT with wrong algorithm fails
    Given a deterministic factory seeded with "jwt-alg-mismatch-test"
    When I generate an RSA key for label "jwt-mismatch" with spec RS256
    And I sign a JWT with the RSA key
    And I attempt to verify the JWT with ES256 algorithm
    Then the JWT verification should fail

  # --- JWT Negative Scenarios ---

  Scenario: verify JWT with wrong key fails
    Given a deterministic factory seeded with "jwt-wrong-key-test"
    When I generate an RSA key for label "jwt-wrong" with spec RS256
    And I generate another RSA key for label "jwt-wrong-2" with spec RS256
    And I sign a JWT with the first RSA key
    And I attempt to verify the JWT with the second RSA key
    Then the JWT verification should fail
```

### 2.2 TLS Integration Feature (`tls.feature`)

```gherkin
Feature: TLS configuration
  As a test author
  I want to generate TLS server and client configurations
  So that I can test TLS handshake scenarios

  # --- TLS Server Config ---

  Scenario: create TLS server config with X.509 chain
    Given a deterministic factory seeded with "tls-server-test"
    When I generate a certificate chain for domain "test.example.com" with label "tls-server"
    And I create a TLS server config with the certificate chain
    Then the TLS server config should be valid
    And the TLS server config should have a certificate chain

  Scenario: create TLS server config with ECDSA chain
    Given a deterministic factory seeded with "tls-server-ecdsa-test"
    When I generate a certificate chain for domain "test.example.com" with label "tls-server-ecdsa"
    And I create a TLS server config with the ECDSA certificate chain
    Then the TLS server config should be valid

  # --- TLS Client Config ---

  Scenario: create TLS client config with root CA
    Given a deterministic factory seeded with "tls-client-test"
    When I generate a certificate chain for domain "test.example.com" with label "tls-client"
    And I create a TLS client config with the root CA
    Then the TLS client config should be valid
    And the TLS client config should have a root CA

  # --- mTLS Scenarios ---

  Scenario: create mTLS client config with client cert
    Given a deterministic factory seeded with "mtls-test"
    When I generate a certificate chain for domain "client.example.com" with label "mtls-client"
    And I create an mTLS client config with the client certificate chain
    Then the mTLS client config should be valid
    And the mTLS client config should have a client certificate

  Scenario: mTLS server requires client certificate
    Given a deterministic factory seeded with "mtls-server-test"
    When I generate a certificate chain for domain "server.example.com" with label "mtls-server"
    And I create an mTLS server config with client auth required
    Then the mTLS server config should require client certificates

  # --- TLS Negative Scenarios ---

  Scenario: TLS client rejects expired certificate
    Given a deterministic factory seeded with "tls-expired-test"
    When I generate a certificate chain for domain "test.example.com" with label "tls-expired"
    And I get the expired leaf variant of the certificate chain
    And I create a TLS client config with the root CA
    And I attempt to verify the expired certificate
    Then the certificate verification should fail

  Scenario: TLS client rejects unknown CA
    Given a deterministic factory seeded with "tls-unknown-ca-test"
    When I generate a certificate chain for domain "test.example.com" with label "tls-unknown"
    And I get the unknown CA variant of the certificate chain
    And I create a TLS client config with the original root CA
    And I attempt to verify the unknown CA certificate
    Then the certificate verification should fail

  Scenario: TLS client rejects hostname mismatch
    Given a deterministic factory seeded with "tls-hostname-test"
    When I generate a certificate chain for domain "test.example.com" with label "tls-hostname"
    And I get the hostname mismatch variant with "wrong.example.com"
    And I create a TLS client config with the root CA
    And I attempt to verify the hostname mismatch certificate
    Then the certificate verification should fail
```

### 2.3 Edge Cases Feature (`edge_cases.feature`)

```gherkin
Feature: Edge cases and error handling
  As a test author
  I want to test edge cases and error conditions
  So that I can ensure robustness of the library

  # --- Label Edge Cases ---

  Scenario: empty label generates valid key
    Given a deterministic factory seeded with "empty-label-test"
    When I generate an RSA key for label "" with spec RS256
    Then the PKCS8 PEM should be parseable

  Scenario: label with special characters generates valid key
    Given a deterministic factory seeded with "special-chars-test"
    When I generate an RSA key for label "test-label_123!@#$%" with spec RS256
    Then the PKCS8 PEM should be parseable

  Scenario: very long label generates valid key
    Given a deterministic factory seeded with "long-label-test"
    When I generate an RSA key for label "this-is-a-very-long-label-that-exceeds-normal-lengths" with spec RS256
    Then the PKCS8 PEM should be parseable

  # --- Factory Edge Cases ---

  Scenario: factory cache isolates different labels
    Given a deterministic factory seeded with "cache-isolation-test"
    When I generate an RSA key for label "label-a" with spec RS256
    And I generate an RSA key for label "label-b" with spec RS256
    And I clear the factory cache
    And I generate the same keys again
    Then each regenerated key should be identical to the original

  # --- Determinism Edge Cases ---

  Scenario: deterministic order independence across key types
    Given a deterministic factory seeded with "order-indep-test"
    When I generate an RSA key for label "rsa" with spec RS256
    And I generate an ECDSA ES256 key for label "ecdsa"
    And I generate an Ed25519 key for label "ed25519"
    And I clear the factory cache
    And I generate the same keys in reverse order
    Then each regenerated key should be identical to the original

  # --- Negative Fixture Edge Cases ---

  Scenario: truncating DER to 0 bytes returns empty
    Given a deterministic factory seeded with "truncate-zero-test"
    When I generate an RSA key for label "truncate-zero" with spec RS256
    And I truncate the PKCS8 DER to 0 bytes
    Then the truncated DER should have length 0

  Scenario: truncating DER beyond length returns original
    Given a deterministic factory seeded with "truncate-beyond-test"
    When I generate an RSA key for label "truncate-beyond" with spec RS256
    And I truncate the PKCS8 DER to 99999 bytes
    Then the truncated DER should equal the original

  # --- Key ID Edge Cases ---

  Scenario: kid is unique across key types
    Given a deterministic factory seeded with "kid-unique-test"
    When I generate an RSA key for label "kid-rsa" with spec RS256
    And I generate an ECDSA ES256 key for label "kid-ecdsa"
    And I generate an Ed25519 key for label "kid-ed25519"
    And I generate an HMAC HS256 secret for label "kid-hmac"
    Then each key should have a unique kid
```

## Implementation Notes

### Step Implementation Requirements

For each new scenario, the following step implementations may need to be added to [`crates/uselesskey-bdd/tests/bdd.rs`](../crates/uselesskey-bdd/tests/bdd.rs):

1. **RSA RS384/RS512 steps**: New spec variants
2. **HMAC HS384/HS512 steps**: New spec variants
3. **JWT signing/verification steps**: Integration with jsonwebtoken
4. **TLS config steps**: Integration with rustls
5. **Edge case steps**: Label handling, cache behavior

### World State Extensions

The [`UselessWorld`](../crates/uselesskey-bdd/tests/bdd.rs:9) struct may need additional fields:

```rust
// JWT-related fields
jwt_token: Option<String>,
jwt_claims: Option<String>,

// TLS-related fields
tls_server_config: Option<TlsServerConfig>,
tls_client_config: Option<TlsClientConfig>,
```

### Feature Flags

Some scenarios may require feature flags:
- `jwt.feature`: Requires `jsonwebtoken` feature
- `tls.feature`: Requires `rustls` features
- Edge cases: Should work with default features
