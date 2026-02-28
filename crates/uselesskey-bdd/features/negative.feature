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

  Scenario: truncated DER to 1 byte fails to parse
    When I truncate the PKCS8 DER to 1 bytes
    Then the truncated DER should have length 1
    And the truncated DER should fail to parse

  Scenario: truncated DER to 0 bytes is empty
    When I truncate the PKCS8 DER to 0 bytes
    Then the truncated DER should have length 0

  # --- Deterministic corruption variants ---

  Scenario: different deterministic PEM variants produce different outputs
    When I deterministically corrupt the RSA PKCS8 PEM with variant "alpha"
    And I deterministically corrupt the RSA PKCS8 PEM with variant "beta" into slot 2
    Then the deterministic text artifacts should differ

  Scenario: different deterministic DER variants produce different outputs
    When I deterministically corrupt the RSA PKCS8 DER with variant "alpha"
    And I deterministically corrupt the RSA PKCS8 DER with variant "beta" into slot 2
    Then the deterministic binary artifacts should differ
