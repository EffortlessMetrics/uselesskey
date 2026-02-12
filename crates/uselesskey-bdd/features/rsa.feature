Feature: RSA fixtures
  As a test author
  I want to generate RSA key fixtures
  So that I can test cryptographic workflows without committing secrets

  # --- Determinism ---

  Scenario: deterministic RSA fixtures are stable
    Given a deterministic factory seeded with "0x0000000000000000000000000000000000000000000000000000000000000042"
    When I generate an RSA key for label "issuer"
    And I generate an RSA key for label "issuer" again
    Then the PKCS8 PEM should be identical

  Scenario: deterministic derivation survives cache clear
    Given a deterministic factory seeded with "test-seed-alpha"
    When I generate an RSA key for label "first"
    And I clear the factory cache
    And I generate an RSA key for label "first" again
    Then the PKCS8 PEM should be identical

  Scenario: different labels produce different keys
    Given a deterministic factory seeded with "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    When I generate an RSA key for label "alice"
    And I generate another RSA key for label "bob"
    Then the keys should have different moduli

  Scenario: different seeds produce different keys
    Given a deterministic factory seeded with "seed-one"
    When I generate an RSA key for label "service"
    And I switch to a deterministic factory seeded with "seed-two"
    And I generate another RSA key for label "service"
    Then the keys should have different moduli

  # --- Random mode ---

  Scenario: random factory produces different keys each time
    Given a random factory
    When I generate an RSA key for label "ephemeral"
    And I clear the factory cache
    And I generate an RSA key for label "ephemeral" again
    Then the keys should have different moduli

  Scenario: random factory caches within same session
    Given a random factory
    When I generate an RSA key for label "cached"
    And I generate an RSA key for label "cached" again
    Then the PKCS8 PEM should be identical

  # --- Key formats ---

  Scenario: PKCS8 DER private key is valid
    Given a deterministic factory seeded with "format-test"
    When I generate an RSA key for label "der-test"
    Then the PKCS8 DER should be parseable

  Scenario: SPKI PEM public key is valid
    Given a deterministic factory seeded with "format-test"
    When I generate an RSA key for label "spki-test"
    Then the SPKI PEM should be parseable

  Scenario: SPKI DER public key is valid
    Given a deterministic factory seeded with "format-test"
    When I generate an RSA key for label "spki-der-test"
    Then the SPKI DER should be parseable

  # --- Negative fixtures: mismatched keys ---

  Scenario: mismatched public key is different
    Given a random factory
    When I generate an RSA key for label "issuer"
    Then a mismatched SPKI DER should parse and differ

  Scenario: mismatched key is deterministic
    Given a deterministic factory seeded with "mismatch-test"
    When I generate an RSA key for label "victim"
    And I get the mismatched public key
    And I get the mismatched public key again
    Then the mismatched keys should be identical

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
