@ring
Feature: ring adapter integration
  As a test author
  I want to use uselesskey fixtures with the ring crypto library
  So that I can test ring-based signing and verification

  Scenario: RSA key converts to ring key pair and signs
    Given a deterministic factory seeded with "ring-rsa-test"
    When I generate an RSA key for label "ring-rsa"
    And I sign and verify test data using the ring RSA adapter
    Then the adapter round-trip should succeed

  Scenario: ECDSA P-256 key converts to ring key pair and signs
    Given a deterministic factory seeded with "ring-p256-test"
    When I generate an ECDSA ES256 key for label "ring-p256"
    And I sign and verify test data using the ring ECDSA adapter
    Then the adapter round-trip should succeed

  Scenario: ECDSA P-384 key converts to ring key pair and signs
    Given a deterministic factory seeded with "ring-p384-test"
    When I generate an ECDSA ES384 key for label "ring-p384"
    And I sign and verify test data using the ring ECDSA adapter
    Then the adapter round-trip should succeed

  Scenario: Ed25519 key converts to ring key pair and signs
    Given a deterministic factory seeded with "ring-ed25519-test"
    When I generate an Ed25519 key for label "ring-ed25519"
    And I sign and verify test data using the ring Ed25519 adapter
    Then the adapter round-trip should succeed
