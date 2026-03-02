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

  # --- Special Label Edge Cases for All Key Types ---

  Scenario: label with unicode characters generates valid RSA key
    Given a deterministic factory seeded with "unicode-label-test"
    When I generate an RSA key for label "日本語テスト" with spec RS256
    Then the PKCS8 PEM should be parseable

  Scenario: label with unicode characters generates valid ECDSA key
    Given a deterministic factory seeded with "unicode-ecdsa-test"
    When I generate an ECDSA ES256 key for label "émoji-🔑"
    Then the ECDSA PKCS8 DER should be parseable

  Scenario: label with whitespace generates valid key
    Given a deterministic factory seeded with "whitespace-label-test"
    When I generate an RSA key for label "  spaces  " with spec RS256
    Then the PKCS8 PEM should be parseable

  Scenario: label with newlines generates valid key
    Given a deterministic factory seeded with "newline-label-test"
    When I generate an Ed25519 key for label "line1\nline2"
    Then the Ed25519 PKCS8 DER should be parseable

  # --- Factory Re-creation Determinism ---

  Scenario: recreating factory with same seed yields identical RSA key
    Given a deterministic factory seeded with "recreation-rsa-test"
    When I generate an RSA key for label "stable"
    And I switch to a deterministic factory seeded with "recreation-rsa-test"
    And I generate an RSA key for label "stable" again
    Then the PKCS8 PEM should be identical

  Scenario: recreating factory with same seed yields identical ECDSA key
    Given a deterministic factory seeded with "recreation-ecdsa-test"
    When I generate an ECDSA ES256 key for label "stable"
    And I switch to a deterministic factory seeded with "recreation-ecdsa-test"
    And I generate an ECDSA ES256 key for label "stable" again
    Then the ECDSA PKCS8 PEM should be identical

  Scenario: recreating factory with same seed yields identical Ed25519 key
    Given a deterministic factory seeded with "recreation-ed25519-test"
    When I generate an Ed25519 key for label "stable"
    And I switch to a deterministic factory seeded with "recreation-ed25519-test"
    And I generate an Ed25519 key for label "stable" again
    Then the Ed25519 PKCS8 PEM should be identical

  Scenario: recreating factory with same seed yields identical HMAC secret
    Given a deterministic factory seeded with "recreation-hmac-test"
    When I generate an HMAC HS256 secret for label "stable"
    And I switch to a deterministic factory seeded with "recreation-hmac-test"
    And I generate an HMAC HS256 secret for label "stable" again
    Then the HMAC secrets should be identical

  # --- Unicode labels for more key types ---

  Scenario: label with unicode characters generates valid Ed25519 key
    Given a deterministic factory seeded with "unicode-ed25519-test"
    When I generate an Ed25519 key for label "名前テスト"
    Then the Ed25519 PKCS8 DER should be parseable

  Scenario: label with unicode characters generates valid HMAC secret
    Given a deterministic factory seeded with "unicode-hmac-test"
    When I generate an HMAC HS256 secret for label "clé-secrète-🔐"
    Then the HMAC secret bytes should have length 32

  # --- Very long labels for more key types ---

  Scenario: very long label generates valid ECDSA key
    Given a deterministic factory seeded with "long-label-ecdsa-test"
    When I generate an ECDSA ES256 key for label "this-is-a-very-long-label-that-exceeds-normal-lengths-for-ecdsa"
    Then the ECDSA PKCS8 DER should be parseable

  Scenario: very long label generates valid Ed25519 key
    Given a deterministic factory seeded with "long-label-ed25519-test"
    When I generate an Ed25519 key for label "this-is-a-very-long-label-that-exceeds-normal-lengths-for-ed25519"
    Then the Ed25519 PKCS8 DER should be parseable

  Scenario: very long label generates valid HMAC secret
    Given a deterministic factory seeded with "long-label-hmac-test"
    When I generate an HMAC HS256 secret for label "this-is-a-very-long-label-that-exceeds-normal-lengths-for-hmac"
    Then the HMAC secret bytes should have length 32

  # --- DER truncation edge cases for ECDSA and Ed25519 ---

  Scenario: truncating ECDSA DER to 0 bytes returns empty
    Given a deterministic factory seeded with "truncate-zero-ecdsa"
    When I generate an ECDSA ES256 key for label "truncate-zero"
    And I truncate the ECDSA PKCS8 DER to 0 bytes
    Then the truncated ECDSA DER should have length 0

  Scenario: truncating Ed25519 DER to 0 bytes returns empty
    Given a deterministic factory seeded with "truncate-zero-ed25519"
    When I generate an Ed25519 key for label "truncate-zero"
    And I truncate the Ed25519 PKCS8 DER to 0 bytes
    Then the truncated Ed25519 DER should have length 0

  # --- Special character labels for ECDSA ---

  Scenario: label with special characters generates valid ECDSA key
    Given a deterministic factory seeded with "special-chars-ecdsa"
    When I generate an ECDSA ES256 key for label "test-label_123!@#$%"
    Then the ECDSA PKCS8 DER should be parseable
