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

  # --- ECDSA corruption type coverage ---

  Scenario: ECDSA BadFooter corruption replaces the END line
    Given a deterministic factory seeded with "ecdsa-badfooter-neg"
    When I generate an ECDSA ES256 key for label "footer-test"
    And I corrupt the ECDSA PKCS8 PEM with BadFooter
    Then the corrupted ECDSA PEM should contain "END CORRUPTED KEY"
    And the corrupted ECDSA PEM should fail to parse

  Scenario: ECDSA BadBase64 corruption injects invalid characters
    Given a deterministic factory seeded with "ecdsa-badbase64-neg"
    When I generate an ECDSA ES256 key for label "base64-test"
    And I corrupt the ECDSA PKCS8 PEM with BadBase64
    Then the corrupted ECDSA PEM should contain "THIS_IS_NOT_BASE64"
    And the corrupted ECDSA PEM should fail to parse

  Scenario: ECDSA Truncate corruption cuts the PEM short
    Given a deterministic factory seeded with "ecdsa-truncate-pem-neg"
    When I generate an ECDSA ES256 key for label "truncate-pem"
    And I corrupt the ECDSA PKCS8 PEM with Truncate to 30 bytes
    Then the corrupted ECDSA PEM should have length 30
    And the corrupted ECDSA PEM should fail to parse

  Scenario: ECDSA ExtraBlankLine corruption fails parsing
    Given a deterministic factory seeded with "ecdsa-blankline-neg"
    When I generate an ECDSA ES256 key for label "blankline-test"
    And I corrupt the ECDSA PKCS8 PEM with ExtraBlankLine
    Then the corrupted ECDSA PEM should fail to parse

  # --- Ed25519 corruption type coverage ---

  Scenario: Ed25519 BadFooter corruption replaces the END line
    Given a deterministic factory seeded with "ed25519-badfooter-neg"
    When I generate an Ed25519 key for label "footer-test"
    And I corrupt the Ed25519 PKCS8 PEM with BadFooter
    Then the corrupted Ed25519 PEM should contain "END CORRUPTED KEY"
    And the corrupted Ed25519 PEM should fail to parse

  Scenario: Ed25519 BadBase64 corruption injects invalid characters
    Given a deterministic factory seeded with "ed25519-badbase64-neg"
    When I generate an Ed25519 key for label "base64-test"
    And I corrupt the Ed25519 PKCS8 PEM with BadBase64
    Then the corrupted Ed25519 PEM should contain "THIS_IS_NOT_BASE64"
    And the corrupted Ed25519 PEM should fail to parse

  Scenario: Ed25519 Truncate corruption cuts the PEM short
    Given a deterministic factory seeded with "ed25519-truncate-pem-neg"
    When I generate an Ed25519 key for label "truncate-pem"
    And I corrupt the Ed25519 PKCS8 PEM with Truncate to 20 bytes
    Then the corrupted Ed25519 PEM should have length 20
    And the corrupted Ed25519 PEM should fail to parse

  Scenario: Ed25519 ExtraBlankLine corruption fails parsing
    Given a deterministic factory seeded with "ed25519-blankline-neg"
    When I generate an Ed25519 key for label "blankline-test"
    And I corrupt the Ed25519 PKCS8 PEM with ExtraBlankLine
    Then the corrupted Ed25519 PEM should fail to parse

  # --- DER corruption variants across key types ---

  Scenario: ECDSA different DER corruption variants produce different outputs
    Given a deterministic factory seeded with "ecdsa-der-variants-neg"
    When I generate an ECDSA ES256 key for label "der-variant-test"
    And I deterministically corrupt the ECDSA PKCS8 DER with variant "alpha"
    And I deterministically corrupt the ECDSA PKCS8 DER with variant "beta" again
    Then the deterministic binary artifacts should differ

  Scenario: Ed25519 different DER corruption variants produce different outputs
    Given a deterministic factory seeded with "ed25519-der-variants-neg"
    When I generate an Ed25519 key for label "der-variant-test"
    And I deterministically corrupt the Ed25519 PKCS8 DER with variant "alpha"
    And I deterministically corrupt the Ed25519 PKCS8 DER with variant "beta" again
    Then the deterministic binary artifacts should differ

  # --- Mismatched key determinism across types ---

  Scenario: ECDSA mismatched key variant is deterministic
    Given a deterministic factory seeded with "ecdsa-mismatch-det-neg"
    When I generate an ECDSA ES256 key for label "mismatch-victim"
    And I get the mismatched ECDSA public key
    And I get the mismatched ECDSA public key again
    Then the mismatched ECDSA keys should be identical

  Scenario: Ed25519 mismatched key variant is deterministic
    Given a deterministic factory seeded with "ed25519-mismatch-det-neg"
    When I generate an Ed25519 key for label "mismatch-victim"
    And I get the mismatched Ed25519 public key
    And I get the mismatched Ed25519 public key again
    Then the mismatched Ed25519 keys should be identical
