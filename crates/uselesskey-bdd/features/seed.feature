Feature: Seed parsing
  As a test author
  I want flexible seed parsing
  So that I can use various seed formats in CI and local development

  Scenario: hex seed with 0x prefix
    Given a deterministic factory seeded with "0x0000000000000000000000000000000000000000000000000000000000000001"
    When I generate an RSA key for label "hex-test"
    Then the PKCS8 DER should be parseable

  Scenario: hex seed without 0x prefix
    Given a deterministic factory seeded with "0000000000000000000000000000000000000000000000000000000000000002"
    When I generate an RSA key for label "hex-test"
    Then the PKCS8 DER should be parseable

  Scenario: string seed is hashed to 32 bytes
    Given a deterministic factory seeded with "my-simple-seed"
    When I generate an RSA key for label "string-test"
    Then the PKCS8 DER should be parseable

  Scenario: same string seed produces same keys
    Given a deterministic factory seeded with "reproducible"
    When I generate an RSA key for label "test"
    And I switch to a deterministic factory seeded with "reproducible"
    And I generate an RSA key for label "test" again
    Then the PKCS8 PEM should be identical

  Scenario: short string seeds work
    Given a deterministic factory seeded with "ci"
    When I generate an RSA key for label "short-seed"
    Then the PKCS8 DER should be parseable

  Scenario: long string seeds work
    Given a deterministic factory seeded with "this-is-a-very-long-seed-value-that-exceeds-32-characters-significantly"
    When I generate an RSA key for label "long-seed"
    Then the PKCS8 DER should be parseable

  # --- Seed Determinism Across Factory Instances ---

  Scenario: same seed across factory instances produces same ECDSA key
    Given a deterministic factory seeded with "ecdsa-seed-instance"
    When I generate an ECDSA ES256 key for label "instance-test"
    And I switch to a deterministic factory seeded with "ecdsa-seed-instance"
    And I generate an ECDSA ES256 key for label "instance-test" again
    Then the ECDSA PKCS8 PEM should be identical

  Scenario: same seed across factory instances produces same Ed25519 key
    Given a deterministic factory seeded with "ed25519-seed-instance"
    When I generate an Ed25519 key for label "instance-test"
    And I switch to a deterministic factory seeded with "ed25519-seed-instance"
    And I generate an Ed25519 key for label "instance-test" again
    Then the Ed25519 PKCS8 PEM should be identical

  Scenario: same seed across factory instances produces same HMAC secret
    Given a deterministic factory seeded with "hmac-seed-instance"
    When I generate an HMAC HS256 secret for label "instance-test"
    And I switch to a deterministic factory seeded with "hmac-seed-instance"
    And I generate an HMAC HS256 secret for label "instance-test" again
    Then the HMAC secrets should be identical

  Scenario: different seeds produce different ECDSA keys
    Given a deterministic factory seeded with "ecdsa-seed-one"
    When I generate an ECDSA ES256 key for label "service"
    And I switch to a deterministic factory seeded with "ecdsa-seed-two"
    And I generate another ECDSA ES256 key for label "service"
    Then the ECDSA keys should have different public keys

  Scenario: different seeds produce different Ed25519 keys
    Given a deterministic factory seeded with "ed25519-seed-one"
    When I generate an Ed25519 key for label "service"
    And I switch to a deterministic factory seeded with "ed25519-seed-two"
    And I generate another Ed25519 key for label "service"
    Then the Ed25519 keys should have different public keys

  # --- KID Determinism Across Factory Instances ---

  Scenario: same seed produces same RSA KID across factory instances
    Given a deterministic factory seeded with "kid-stability-rsa"
    When I generate an RSA key for label "kid-check"
    And I capture the kid
    And I switch to a deterministic factory seeded with "kid-stability-rsa"
    And I generate an RSA key for label "kid-check" again
    And I capture the kid again
    Then the kids should be identical

  Scenario: same seed produces same ECDSA KID across factory instances
    Given a deterministic factory seeded with "kid-stability-ecdsa"
    When I generate an ECDSA ES256 key for label "kid-check"
    And I capture the ECDSA kid
    And I switch to a deterministic factory seeded with "kid-stability-ecdsa"
    And I generate an ECDSA ES256 key for label "kid-check" again
    And I capture the ECDSA kid again
    Then the ECDSA kids should be identical
