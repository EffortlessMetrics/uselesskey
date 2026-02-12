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
