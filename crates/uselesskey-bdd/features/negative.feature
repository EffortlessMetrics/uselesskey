Feature: Negative fixtures
  As a test author
  I want to generate corrupted key fixtures
  So that I can test error handling paths

  Background:
    Given a deterministic factory seeded with "negative-fixtures-test"
    And I generate an RSA key for label "test-key"

  # --- Corrupted PEM ---

  Scenario: BadHeader corruption replaces the BEGIN line
    When I corrupt the PKCS8 PEM with BadHeader
    Then the corrupted PEM should contain "BEGIN CORRUPTED KEY"
    And the corrupted PEM should fail to parse

  Scenario: BadFooter corruption replaces the END line
    When I corrupt the PKCS8 PEM with BadFooter
    Then the corrupted PEM should contain "END CORRUPTED KEY"
    And the corrupted PEM should fail to parse

  Scenario: BadBase64 corruption injects invalid characters
    When I corrupt the PKCS8 PEM with BadBase64
    Then the corrupted PEM should contain "THIS_IS_NOT_BASE64"
    And the corrupted PEM should fail to parse

  Scenario: Truncate corruption cuts the PEM short
    When I corrupt the PKCS8 PEM with Truncate to 50 bytes
    Then the corrupted PEM should have length 50
    And the corrupted PEM should fail to parse

  Scenario: ExtraBlankLine corruption adds whitespace
    When I corrupt the PKCS8 PEM with ExtraBlankLine
    Then the corrupted PEM should fail to parse

  # --- Truncated DER ---

  Scenario: truncated DER is shorter than original
    When I truncate the PKCS8 DER to 100 bytes
    Then the truncated DER should have length 100
    And the truncated DER should fail to parse

  Scenario: truncating beyond length returns original
    When I truncate the PKCS8 DER to 99999 bytes
    Then the truncated DER should equal the original

  # --- Corruption variant distinctness ---

  Scenario: deterministic PEM corruption with variant is stable
    When I deterministically corrupt the RSA PKCS8 PEM with variant "neg-v1"
    And I deterministically corrupt the RSA PKCS8 PEM with variant "neg-v1" again
    Then the deterministic text artifacts should be identical
    And the deterministic RSA PEM artifact should fail to parse

  Scenario: deterministic DER corruption with variant is stable
    When I deterministically corrupt the RSA PKCS8 DER with variant "neg-v1"
    And I deterministically corrupt the RSA PKCS8 DER with variant "neg-v1" again
    Then the deterministic binary artifacts should be identical
    And the deterministic RSA DER artifact should fail to parse

  # --- Mismatched keys ---

  Scenario: mismatched public key does not match the original private key
    Then a mismatched SPKI DER should parse and differ

  Scenario: mismatched key variant is deterministic
    When I get the mismatched public key
    And I get the mismatched public key again
    Then the mismatched keys should be identical

  # --- Different corruption variants produce different outputs ---

  Scenario: different PEM corruption variants produce different outputs
    When I deterministically corrupt the RSA PKCS8 PEM with variant "variant-alpha"
    And I deterministically corrupt the RSA PKCS8 PEM with variant "variant-beta" again
    Then the deterministic text artifacts should differ

  Scenario: different DER corruption variants produce different outputs
    When I deterministically corrupt the RSA PKCS8 DER with variant "variant-alpha"
    And I deterministically corrupt the RSA PKCS8 DER with variant "variant-beta" again
    Then the deterministic binary artifacts should differ

  # --- Multiple corruption types on same key ---

  Scenario: BadHeader and BadFooter produce different corruptions
    When I corrupt the PKCS8 PEM with BadHeader
    Then the corrupted PEM should contain "BEGIN CORRUPTED KEY"
    And the corrupted PEM should fail to parse

  Scenario: Truncate to 1 byte produces minimal output
    When I corrupt the PKCS8 PEM with Truncate to 1 bytes
    Then the corrupted PEM should have length 1
    And the corrupted PEM should fail to parse

  # --- Cross-key-type corruption: all corrupt variants fail parsing ---

  Scenario: ECDSA deterministic corrupt variant fails standard parsing
    Given a deterministic factory seeded with "ecdsa-corrupt-neg"
    When I generate an ECDSA ES256 key for label "corrupt-check"
    And I deterministically corrupt the ECDSA PKCS8 PEM with variant "corrupt-v1"
    And I deterministically corrupt the ECDSA PKCS8 PEM with variant "corrupt-v1" again
    Then the deterministic text artifacts should be identical
    And the deterministic ECDSA PEM artifact should fail to parse

  Scenario: Ed25519 deterministic corrupt variant fails standard parsing
    Given a deterministic factory seeded with "ed25519-corrupt-neg"
    When I generate an Ed25519 key for label "corrupt-check"
    And I deterministically corrupt the Ed25519 PKCS8 PEM with variant "corrupt-v1"
    And I deterministically corrupt the Ed25519 PKCS8 PEM with variant "corrupt-v1" again
    Then the deterministic text artifacts should be identical
    And the deterministic Ed25519 PEM artifact should fail to parse
