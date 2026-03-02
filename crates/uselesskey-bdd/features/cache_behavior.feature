Feature: Cache behavior
  As a test author
  I want to verify factory cache hit and miss behavior
  So that I can rely on correct caching across different seeds, labels, and specs

  # --- Cache hit: same label same spec returns cached value ---

  Scenario: RSA cache hit returns identical key material
    Given a deterministic factory seeded with "cache-hit-rsa"
    When I generate an RSA key for label "cached-rsa"
    And I generate an RSA key for label "cached-rsa" again
    Then the PKCS8 PEM should be identical

  Scenario: ECDSA cache hit returns identical key material
    Given a deterministic factory seeded with "cache-hit-ecdsa"
    When I generate an ECDSA ES256 key for label "cached-ecdsa"
    And I generate an ECDSA ES256 key for label "cached-ecdsa" again
    Then the ECDSA PKCS8 PEM should be identical

  # --- Cache miss: different labels get different keys ---

  Scenario: different labels are cache-isolated for RSA
    Given a deterministic factory seeded with "cache-miss-label-rsa"
    When I generate an RSA key for label "label-alpha"
    And I generate another RSA key for label "label-beta"
    Then the keys should have different moduli

  Scenario: different labels are cache-isolated for ECDSA
    Given a deterministic factory seeded with "cache-miss-label-ecdsa"
    When I generate an ECDSA ES256 key for label "label-alpha"
    And I generate another ECDSA ES256 key for label "label-beta"
    Then the ECDSA keys should have different public keys

  # --- Cache miss: different specs for same label ---

  Scenario: same label different HMAC specs produce different secrets
    Given a deterministic factory seeded with "cache-miss-spec-hmac"
    When I generate an HMAC HS256 secret for label "shared-hmac"
    And I generate another HMAC HS384 secret for label "shared-hmac"
    Then the HMAC secrets should be different

  # --- Cache clear then re-derive: determinism preserved ---

  Scenario: cache clear followed by re-derive gives identical RSA key
    Given a deterministic factory seeded with "cache-clear-rsa"
    When I generate an RSA key for label "clear-test"
    And I clear the factory cache
    And I generate an RSA key for label "clear-test" again
    Then the PKCS8 PEM should be identical

  Scenario: cache clear followed by re-derive gives identical HMAC secret
    Given a deterministic factory seeded with "cache-clear-hmac"
    When I generate an HMAC HS256 secret for label "clear-hmac"
    And I clear the factory cache
    And I generate an HMAC HS256 secret for label "clear-hmac" again
    Then the HMAC secrets should be identical

  Scenario: cache clear followed by re-derive gives identical token
    Given a deterministic factory seeded with "cache-clear-token"
    When I generate an API key token for label "clear-token"
    And I clear the factory cache
    And I generate an API key token for label "clear-token" again
    Then the token values should be identical

  # --- New factory instance: cache is empty but determinism holds ---

  Scenario: new factory instance gets cache miss but same deterministic value
    Given a deterministic factory seeded with "cache-new-factory"
    When I generate an RSA key for label "new-factory-test"
    And I switch to a deterministic factory seeded with "cache-new-factory"
    And I generate an RSA key for label "new-factory-test" again
    Then the PKCS8 PEM should be identical

  # --- Random mode cache behavior ---

  Scenario: random factory caches within session
    Given a random factory
    When I generate an RSA key for label "random-cached"
    And I generate an RSA key for label "random-cached" again
    Then the PKCS8 PEM should be identical

  Scenario: random factory cache clear produces different key
    Given a random factory
    When I generate an RSA key for label "random-clear"
    And I clear the factory cache
    And I generate an RSA key for label "random-clear" again
    Then the PKCS8 PEM should differ
