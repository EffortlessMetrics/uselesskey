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
