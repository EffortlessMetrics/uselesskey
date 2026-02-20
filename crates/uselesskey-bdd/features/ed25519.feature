Feature: Ed25519 fixtures
  As a test author
  I want to generate Ed25519 key fixtures
  So that I can test EdDSA cryptographic workflows without committing secrets

  # --- Determinism ---

  Scenario: deterministic Ed25519 fixtures are stable
    Given a deterministic factory seeded with "0x0000000000000000000000000000000000000000000000000000000000000042"
    When I generate an Ed25519 key for label "signer"
    And I generate an Ed25519 key for label "signer" again
    Then the Ed25519 PKCS8 PEM should be identical

  Scenario: deterministic Ed25519 derivation survives cache clear
    Given a deterministic factory seeded with "ed25519-seed-alpha"
    When I generate an Ed25519 key for label "first"
    And I clear the factory cache
    And I generate an Ed25519 key for label "first" again
    Then the Ed25519 PKCS8 PEM should be identical

  Scenario: different labels produce different Ed25519 keys
    Given a deterministic factory seeded with "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    When I generate an Ed25519 key for label "alice"
    And I generate another Ed25519 key for label "bob"
    Then the Ed25519 keys should have different public keys

  Scenario: different seeds produce different Ed25519 keys
    Given a deterministic factory seeded with "seed-one"
    When I generate an Ed25519 key for label "service"
    And I switch to a deterministic factory seeded with "seed-two"
    And I generate another Ed25519 key for label "service"
    Then the Ed25519 keys should have different public keys

  # --- Random mode ---

  Scenario: random factory produces different Ed25519 keys each time
    Given a random factory
    When I generate an Ed25519 key for label "ephemeral"
    And I clear the factory cache
    And I generate an Ed25519 key for label "ephemeral" again
    Then the Ed25519 keys should have different public keys

  Scenario: random factory caches Ed25519 within same session
    Given a random factory
    When I generate an Ed25519 key for label "cached"
    And I generate an Ed25519 key for label "cached" again
    Then the Ed25519 PKCS8 PEM should be identical

  # --- Key formats ---

  Scenario: Ed25519 PKCS8 DER private key is valid
    Given a deterministic factory seeded with "format-test"
    When I generate an Ed25519 key for label "der-test"
    Then the Ed25519 PKCS8 DER should be parseable

  Scenario: Ed25519 SPKI PEM public key is valid
    Given a deterministic factory seeded with "format-test"
    When I generate an Ed25519 key for label "spki-test"
    Then the Ed25519 SPKI PEM should be parseable

  Scenario: Ed25519 SPKI DER public key is valid
    Given a deterministic factory seeded with "format-test"
    When I generate an Ed25519 key for label "spki-der-test"
    Then the Ed25519 SPKI DER should be parseable

  # --- Negative fixtures: mismatched keys ---

  Scenario: mismatched Ed25519 public key is different
    Given a random factory
    When I generate an Ed25519 key for label "signer"
    Then an Ed25519 mismatched SPKI DER should parse and differ

  Scenario: mismatched Ed25519 key is deterministic
    Given a deterministic factory seeded with "mismatch-test"
    When I generate an Ed25519 key for label "victim"
    And I get the mismatched Ed25519 public key
    And I get the mismatched Ed25519 public key again
    Then the mismatched Ed25519 keys should be identical

  # --- Negative fixtures: corruption ---

  Scenario: Ed25519 corrupted PEM with BadHeader
    Given a deterministic factory seeded with "corrupt-test"
    When I generate an Ed25519 key for label "corrupted"
    And I corrupt the Ed25519 PKCS8 PEM with BadHeader
    Then the corrupted Ed25519 PEM should contain "-----BEGIN CORRUPTED KEY-----"

  Scenario: Ed25519 truncated DER fails to parse
    Given a deterministic factory seeded with "truncate-test"
    When I generate an Ed25519 key for label "truncated"
    And I truncate the Ed25519 PKCS8 DER to 10 bytes
    Then the truncated Ed25519 DER should have length 10
    And the truncated Ed25519 DER should fail to parse

  Scenario: deterministic Ed25519 PEM corruption with variant is stable
    Given a deterministic factory seeded with "ed25519-det-corrupt-pem"
    When I generate an Ed25519 key for label "ed25519-det-pem"
    And I deterministically corrupt the Ed25519 PKCS8 PEM with variant "v1"
    And I deterministically corrupt the Ed25519 PKCS8 PEM with variant "v1" again
    Then the deterministic text artifacts should be identical
    And the deterministic Ed25519 PEM artifact should fail to parse

  Scenario: deterministic Ed25519 DER corruption with variant is stable
    Given a deterministic factory seeded with "ed25519-det-corrupt-der"
    When I generate an Ed25519 key for label "ed25519-det-der"
    And I deterministically corrupt the Ed25519 PKCS8 DER with variant "v1"
    And I deterministically corrupt the Ed25519 PKCS8 DER with variant "v1" again
    Then the deterministic binary artifacts should be identical
    And the deterministic Ed25519 DER artifact should fail to parse

  # --- JWK support ---

  Scenario: Ed25519 public JWK has correct format
    Given a deterministic factory seeded with "jwk-test"
    When I generate an Ed25519 key for label "jwt-signer"
    Then the Ed25519 public JWK should have kty "OKP"
    And the Ed25519 public JWK should have crv "Ed25519"
    And the Ed25519 public JWK should have alg "EdDSA"
    And the Ed25519 public JWK should have use "sig"
    And the Ed25519 public JWK should have a kid
    And the Ed25519 public JWK should have x parameter

  Scenario: Ed25519 private JWK has correct format
    Given a deterministic factory seeded with "jwk-test"
    When I generate an Ed25519 key for label "jwt-signer"
    Then the Ed25519 private JWK should have d parameter

  Scenario: Ed25519 JWKS has valid structure
    Given a deterministic factory seeded with "jwks-test"
    When I generate an Ed25519 key for label "auth-service"
    Then the Ed25519 JWKS should have a keys array
    And the Ed25519 JWKS keys array should contain one key

  Scenario: Ed25519 kid is deterministic
    Given a deterministic factory seeded with "kid-test"
    When I generate an Ed25519 key for label "issuer"
    And I capture the Ed25519 kid
    And I clear the factory cache
    And I generate an Ed25519 key for label "issuer" again
    And I capture the Ed25519 kid again
    Then the Ed25519 kids should be identical
