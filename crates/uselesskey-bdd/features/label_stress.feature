Feature: Label stress tests
  As a test author
  I want to verify that extreme label values produce valid fixtures
  So that I can trust uselesskey with any user-provided label string

  # --- Empty labels across all key types ---

  Scenario: empty label generates valid ECDSA key
    Given a deterministic factory seeded with "label-stress-empty-ecdsa"
    When I generate an ECDSA ES256 key for label ""
    Then the ECDSA PKCS8 DER should be parseable

  Scenario: empty label generates valid Ed25519 key
    Given a deterministic factory seeded with "label-stress-empty-ed25519"
    When I generate an Ed25519 key for label ""
    Then the Ed25519 PKCS8 DER should be parseable

  Scenario: empty label generates valid HMAC secret
    Given a deterministic factory seeded with "label-stress-empty-hmac"
    When I generate an HMAC HS256 secret for label ""
    Then the HMAC secret bytes should have length 32

  Scenario: empty label generates valid API key token
    Given a deterministic factory seeded with "label-stress-empty-token"
    When I generate an API key token for label ""
    Then the token value should start with "uk_test_"
    And the token value should have length 40

  # --- Whitespace and special character labels ---

  Scenario: tab-only label generates valid RSA key
    Given a deterministic factory seeded with "label-stress-tab"
    When I generate an RSA key for label "	"
    Then the PKCS8 PEM should be parseable

  Scenario: special characters label generates valid Ed25519 key
    Given a deterministic factory seeded with "label-stress-special-ed"
    When I generate an Ed25519 key for label "!@#$%^&*()_+-=[]{}|;':\",./<>?"
    Then the Ed25519 PKCS8 DER should be parseable

  Scenario: emoji label generates valid HMAC secret
    Given a deterministic factory seeded with "label-stress-emoji-hmac"
    When I generate an HMAC HS256 secret for label "🔑🔐🗝️"
    Then the HMAC secret bytes should have length 32

  Scenario: emoji label generates valid bearer token
    Given a deterministic factory seeded with "label-stress-emoji-bearer"
    When I generate a bearer token for label "🎉🎊"
    Then the token value should be valid base64url
    And the token value should have length 43

  # --- Determinism with special labels ---

  Scenario: unicode label is deterministic for ECDSA
    Given a deterministic factory seeded with "label-stress-det-unicode-ecdsa"
    When I generate an ECDSA ES256 key for label "ключ-тест"
    And I generate an ECDSA ES256 key for label "ключ-тест" again
    Then the ECDSA PKCS8 PEM should be identical

  Scenario: unicode label is deterministic for tokens
    Given a deterministic factory seeded with "label-stress-det-unicode-token"
    When I generate an API key token for label "مفتاح-اختبار"
    And I generate an API key token for label "مفتاح-اختبار" again
    Then the token values should be identical

  Scenario: empty label is deterministic for RSA
    Given a deterministic factory seeded with "label-stress-det-empty-rsa"
    When I generate an RSA key for label ""
    And I generate an RSA key for label "" again
    Then the PKCS8 PEM should be identical

  # --- Label collision avoidance ---

  Scenario: similar labels produce different keys
    Given a deterministic factory seeded with "label-stress-collision"
    When I generate an Ed25519 key for label "test"
    And I generate another Ed25519 key for label "test "
    Then the Ed25519 keys should have different public keys

  Scenario: case-different labels produce different keys
    Given a deterministic factory seeded with "label-stress-case"
    When I generate an ECDSA ES256 key for label "MyKey"
    And I generate another ECDSA ES256 key for label "mykey"
    Then the ECDSA keys should have different public keys
