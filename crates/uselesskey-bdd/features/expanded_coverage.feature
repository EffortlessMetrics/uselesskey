Feature: Expanded BDD coverage
  As a test author
  I want comprehensive coverage of determinism, cache, negative, token, and multi-algorithm behavior
  So that edge cases across all fixture types are exercised

  # ==========================================================================
  # Determinism: factory recreation for non-default specs
  # ==========================================================================

  Scenario: recreating factory yields identical RS384 key
    Given a deterministic factory seeded with "det-expand-rs384-recreate"
    When I generate an RSA key for label "rs384-stable" with spec RS384
    And I switch to a deterministic factory seeded with "det-expand-rs384-recreate"
    And I generate an RSA key for label "rs384-stable" with spec RS384 again
    Then the PKCS8 PEM should be identical

  Scenario: recreating factory yields identical RS512 key
    Given a deterministic factory seeded with "det-expand-rs512-recreate"
    When I generate an RSA key for label "rs512-stable" with spec RS512
    And I switch to a deterministic factory seeded with "det-expand-rs512-recreate"
    And I generate an RSA key for label "rs512-stable" with spec RS512 again
    Then the PKCS8 PEM should be identical

  Scenario: recreating factory yields identical ECDSA ES384 key
    Given a deterministic factory seeded with "det-expand-es384-recreate"
    When I generate an ECDSA ES384 key for label "es384-stable"
    And I switch to a deterministic factory seeded with "det-expand-es384-recreate"
    And I generate an ECDSA ES384 key for label "es384-stable" again
    Then the ECDSA PKCS8 PEM should be identical

  Scenario: different seeds produce different RS384 keys
    Given a deterministic factory seeded with "det-expand-rs384-seed-a"
    When I generate an RSA key for label "service" with spec RS384
    And I switch to a deterministic factory seeded with "det-expand-rs384-seed-b"
    And I generate another RSA key for label "service" with spec RS384
    Then the keys should have different moduli

  Scenario: different seeds produce different ECDSA ES384 keys
    Given a deterministic factory seeded with "det-expand-es384-seed-a"
    When I generate an ECDSA ES384 key for label "service"
    And I switch to a deterministic factory seeded with "det-expand-es384-seed-b"
    And I generate another ECDSA ES384 key for label "service"
    Then the ECDSA keys should have different public keys

  Scenario: different seeds produce different Ed25519 keys
    Given a deterministic factory seeded with "det-expand-ed-seed-a"
    When I generate an Ed25519 key for label "service"
    And I switch to a deterministic factory seeded with "det-expand-ed-seed-b"
    And I generate another Ed25519 key for label "service"
    Then the Ed25519 keys should have different public keys

  # ==========================================================================
  # Cache: hit/miss for HMAC HS384/HS512, ECDSA ES384, random mode
  # ==========================================================================

  Scenario: HMAC HS384 cache hit returns identical secret
    Given a deterministic factory seeded with "cache-expand-hs384-hit"
    When I generate an HMAC HS384 secret for label "cached-hs384"
    And I generate an HMAC HS384 secret for label "cached-hs384" again
    Then the HMAC secrets should be identical

  Scenario: HMAC HS512 cache hit returns identical secret
    Given a deterministic factory seeded with "cache-expand-hs512-hit"
    When I generate an HMAC HS512 secret for label "cached-hs512"
    And I generate an HMAC HS512 secret for label "cached-hs512" again
    Then the HMAC secrets should be identical

  Scenario: ECDSA ES384 cache hit returns identical key material
    Given a deterministic factory seeded with "cache-expand-es384-hit"
    When I generate an ECDSA ES384 key for label "cached-es384"
    And I generate an ECDSA ES384 key for label "cached-es384" again
    Then the ECDSA PKCS8 PEM should be identical

  Scenario: same label different ECDSA specs produce different keys
    Given a deterministic factory seeded with "cache-expand-ecdsa-spec-miss"
    When I generate an ECDSA ES256 key for label "shared-ecdsa"
    And I generate another ECDSA ES384 key for label "shared-ecdsa"
    Then the ECDSA keys should have different public keys

  Scenario: cache clear followed by re-derive gives identical HMAC HS384 secret
    Given a deterministic factory seeded with "cache-expand-hs384-clear"
    When I generate an HMAC HS384 secret for label "clear-hs384"
    And I clear the factory cache
    And I generate an HMAC HS384 secret for label "clear-hs384" again
    Then the HMAC secrets should be identical

  Scenario: cache clear followed by re-derive gives identical HMAC HS512 secret
    Given a deterministic factory seeded with "cache-expand-hs512-clear"
    When I generate an HMAC HS512 secret for label "clear-hs512"
    And I clear the factory cache
    And I generate an HMAC HS512 secret for label "clear-hs512" again
    Then the HMAC secrets should be identical

  Scenario: random ECDSA cache hit returns identical key
    Given a random factory
    When I generate an ECDSA ES256 key for label "random-ecdsa-cached"
    And I generate an ECDSA ES256 key for label "random-ecdsa-cached" again
    Then the ECDSA PKCS8 PEM should be identical

  Scenario: random Ed25519 cache hit returns identical key
    Given a random factory
    When I generate an Ed25519 key for label "random-ed-cached"
    And I generate an Ed25519 key for label "random-ed-cached" again
    Then the Ed25519 PKCS8 PEM should be identical

  Scenario: random HMAC cache hit returns identical secret
    Given a random factory
    When I generate an HMAC HS256 secret for label "random-hmac-cached"
    And I generate an HMAC HS256 secret for label "random-hmac-cached" again
    Then the HMAC secrets should be identical

  Scenario: random ECDSA cache clear produces different key
    Given a random factory
    When I generate an ECDSA ES256 key for label "random-ecdsa-clear"
    And I clear the factory cache
    And I generate an ECDSA ES256 key for label "random-ecdsa-clear" again
    Then the ECDSA keys should have different public keys

  Scenario: random Ed25519 cache clear produces different key
    Given a random factory
    When I generate an Ed25519 key for label "random-ed-clear"
    And I clear the factory cache
    And I generate another Ed25519 key for label "random-ed-clear"
    Then the Ed25519 keys should have different public keys

  Scenario: random HMAC cache clear produces different secret
    Given a random factory
    When I generate an HMAC HS256 secret for label "random-hmac-clear"
    And I clear the factory cache
    And I generate another HMAC HS256 secret for label "random-hmac-clear"
    Then the HMAC secrets should be different

  # ==========================================================================
  # Negative: Ed25519 BadHeader, ECDSA/Ed25519 DER truncation with checks
  # ==========================================================================

  Scenario: Ed25519 BadHeader corruption replaces the BEGIN line
    Given a deterministic factory seeded with "neg-expand-ed-badheader"
    When I generate an Ed25519 key for label "header-test"
    And I corrupt the Ed25519 PKCS8 PEM with BadHeader
    Then the corrupted Ed25519 PEM should contain "BEGIN CORRUPTED KEY"
    And the corrupted Ed25519 PEM should fail to parse

  Scenario: ECDSA ES256 BadHeader corruption replaces the BEGIN line
    Given a deterministic factory seeded with "neg-expand-ecdsa-badheader"
    When I generate an ECDSA ES256 key for label "header-test"
    And I corrupt the ECDSA PKCS8 PEM with BadHeader
    Then the corrupted ECDSA PEM should contain "BEGIN CORRUPTED KEY"
    And the corrupted ECDSA PEM should fail to parse

  Scenario: ECDSA DER truncation to 50 bytes fails parsing
    Given a deterministic factory seeded with "neg-expand-ecdsa-truncate"
    When I generate an ECDSA ES256 key for label "truncate-check"
    And I truncate the ECDSA PKCS8 DER to 50 bytes
    Then the truncated ECDSA DER should have length 50
    And the truncated ECDSA DER should fail to parse

  Scenario: Ed25519 DER truncation to 10 bytes fails parsing
    Given a deterministic factory seeded with "neg-expand-ed-truncate"
    When I generate an Ed25519 key for label "truncate-check"
    And I truncate the Ed25519 PKCS8 DER to 10 bytes
    Then the truncated Ed25519 DER should have length 10
    And the truncated Ed25519 DER should fail to parse

  Scenario: RSA deterministic PEM and DER corruption variants differ
    Given a deterministic factory seeded with "neg-expand-rsa-variant-diff"
    When I generate an RSA key for label "multi-variant"
    And I deterministically corrupt the RSA PKCS8 PEM with variant "gamma"
    And I deterministically corrupt the RSA PKCS8 PEM with variant "delta" again
    Then the deterministic text artifacts should differ

  Scenario: ECDSA deterministic PEM corruption variants differ
    Given a deterministic factory seeded with "neg-expand-ecdsa-variant-diff"
    When I generate an ECDSA ES256 key for label "multi-variant"
    And I deterministically corrupt the ECDSA PKCS8 PEM with variant "gamma"
    And I deterministically corrupt the ECDSA PKCS8 PEM with variant "delta" again
    Then the deterministic text artifacts should differ

  Scenario: Ed25519 deterministic PEM corruption variants differ
    Given a deterministic factory seeded with "neg-expand-ed-variant-diff"
    When I generate an Ed25519 key for label "multi-variant"
    And I deterministically corrupt the Ed25519 PKCS8 PEM with variant "gamma"
    And I deterministically corrupt the Ed25519 PKCS8 PEM with variant "delta" again
    Then the deterministic text artifacts should differ

  # ==========================================================================
  # Token: isolation from HS384/HS512, format in mixed context
  # ==========================================================================

  Scenario: generating tokens does not perturb RSA RS384 determinism
    Given a deterministic factory seeded with "token-expand-rs384-isolation"
    When I generate an RSA key for label "rs384-anchor" with spec RS384
    And I generate an API key token for label "noise-api"
    And I generate a bearer token for label "noise-bearer"
    And I generate an OAuth access token for label "noise-oauth"
    And I clear the factory cache
    And I generate an RSA key for label "rs384-anchor" with spec RS384 again
    Then the PKCS8 PEM should be identical

  Scenario: generating HMAC HS384 does not perturb token determinism
    Given a deterministic factory seeded with "token-expand-hmac-isolation"
    When I generate an API key token for label "stable-api"
    And I generate an HMAC HS384 secret for label "noise-hs384"
    And I generate an HMAC HS512 secret for label "noise-hs512"
    And I clear the factory cache
    And I generate an API key token for label "stable-api" again
    Then the token values should be identical

  Scenario: API key format after mixed key generation
    Given a deterministic factory seeded with "token-expand-mixed-format"
    When I generate an RSA key for label "rsa-noise" with spec RS256
    And I generate an ECDSA ES256 key for label "ecdsa-noise"
    And I generate an Ed25519 key for label "ed-noise"
    And I generate an HMAC HS256 secret for label "hmac-noise"
    And I generate an API key token for label "after-mixed"
    Then the token value should start with "uk_test_"
    And the token value should have length 40

  Scenario: bearer token format after mixed key generation
    Given a deterministic factory seeded with "token-expand-bearer-mixed"
    When I generate an RSA key for label "rsa-noise" with spec RS256
    And I generate an ECDSA ES384 key for label "ecdsa-noise"
    And I generate a bearer token for label "after-mixed"
    Then the token value should be valid base64url
    And the token value should have length 43

  Scenario: OAuth token format after mixed key generation
    Given a deterministic factory seeded with "token-expand-oauth-mixed"
    When I generate an Ed25519 key for label "ed-noise"
    And I generate an HMAC HS512 secret for label "hmac-noise"
    And I generate an OAuth access token for label "after-mixed"
    Then the token value should have three dot-separated segments
    And the token value header should decode to valid JSON
    And the OAuth payload should contain issuer "uselesskey"
    And the OAuth payload should contain subject "after-mixed"

  # ==========================================================================
  # Multi-algorithm: all types valid in same factory, SPKI PEM validity
  # ==========================================================================

  Scenario: all key types produce valid SPKI PEM from same factory
    Given a deterministic factory seeded with "multi-expand-spki-pem"
    When I generate an RSA key for label "spki-rsa" with spec RS256
    And I generate an ECDSA ES256 key for label "spki-ecdsa"
    And I generate an Ed25519 key for label "spki-ed25519"
    Then the SPKI PEM should be parseable
    And the ECDSA SPKI PEM should be parseable
    And the Ed25519 SPKI PEM should be parseable

  Scenario: all key types plus HMAC have unique kids in same factory
    Given a deterministic factory seeded with "multi-expand-unique-kids"
    When I generate an RSA key for label "kid-rsa" with spec RS256
    And I generate an ECDSA ES256 key for label "kid-ecdsa"
    And I generate an Ed25519 key for label "kid-ed25519"
    And I generate an HMAC HS256 secret for label "kid-hmac"
    Then each key should have a unique kid

  Scenario: mixed JWKS contains all four kty values
    Given a deterministic factory seeded with "multi-expand-jwks-kty"
    When I generate an RSA key for label "jwks-rsa" with spec RS256
    And I generate an ECDSA ES256 key for label "jwks-ecdsa"
    And I generate an Ed25519 key for label "jwks-ed25519"
    And I generate an HMAC HS256 secret for label "jwks-hmac"
    And I build a JWKS containing all keys
    Then the JWKS should contain 4 keys
    And the JWKS should contain a key with kty "RSA"
    And the JWKS should contain a key with kty "EC"
    And the JWKS should contain a key with kty "OKP"

  Scenario: interleaved generation of all types preserves RSA determinism
    Given a deterministic factory seeded with "multi-expand-interleave-rsa"
    When I generate an RSA key for label "rsa-anchor" with spec RS256
    And I generate an ECDSA ES256 key for label "noise-ecdsa"
    And I generate an Ed25519 key for label "noise-ed"
    And I generate an HMAC HS384 secret for label "noise-hmac"
    And I generate an API key token for label "noise-token"
    And I clear the factory cache
    And I generate an RSA key for label "rsa-anchor" again
    Then the PKCS8 PEM should be identical

  Scenario: interleaved generation of all types preserves ECDSA ES384 determinism
    Given a deterministic factory seeded with "multi-expand-interleave-es384"
    When I generate an ECDSA ES384 key for label "ecdsa-anchor"
    And I generate an RSA key for label "noise-rsa" with spec RS256
    And I generate an Ed25519 key for label "noise-ed"
    And I generate an HMAC HS512 secret for label "noise-hmac"
    And I generate a bearer token for label "noise-bearer"
    And I clear the factory cache
    And I generate an ECDSA ES384 key for label "ecdsa-anchor" again
    Then the ECDSA PKCS8 PEM should be identical

  Scenario: interleaved generation preserves HMAC HS512 determinism
    Given a deterministic factory seeded with "multi-expand-interleave-hs512"
    When I generate an HMAC HS512 secret for label "hmac-anchor"
    And I generate an RSA key for label "noise-rsa" with spec RS256
    And I generate an ECDSA ES256 key for label "noise-ecdsa"
    And I generate an Ed25519 key for label "noise-ed"
    And I generate an OAuth access token for label "noise-oauth"
    And I clear the factory cache
    And I generate an HMAC HS512 secret for label "hmac-anchor" again
    Then the HMAC secrets should be identical

  Scenario: all key types produce valid DER and PEM after interleaved generation
    Given a deterministic factory seeded with "multi-expand-all-valid"
    When I generate an RSA key for label "valid-rsa" with spec RS256
    And I generate an ECDSA ES256 key for label "valid-ecdsa"
    And I generate an Ed25519 key for label "valid-ed25519"
    And I generate an HMAC HS256 secret for label "valid-hmac"
    Then the PKCS8 DER should be parseable
    And the SPKI DER should be parseable
    And the ECDSA PKCS8 DER should be parseable
    And the ECDSA SPKI DER should be parseable
    And the Ed25519 PKCS8 DER should be parseable
    And the Ed25519 SPKI DER should be parseable
    And the HMAC secret bytes should have length 32
