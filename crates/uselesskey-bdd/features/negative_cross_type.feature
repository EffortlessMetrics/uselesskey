Feature: Cross-type negative fixture edge cases
  As a test author
  I want to verify negative fixtures work consistently across all key types
  So that I can trust corruption and mismatch features for every algorithm

  # --- ECDSA ES384 corruption coverage ---

  Scenario: ECDSA ES384 BadHeader corruption
    Given a deterministic factory seeded with "neg-ecdsa384-badheader"
    When I generate an ECDSA ES384 key for label "es384-corrupt"
    And I corrupt the ECDSA PKCS8 PEM with BadHeader
    Then the corrupted ECDSA PEM should contain "BEGIN CORRUPTED KEY"
    And the corrupted ECDSA PEM should fail to parse

  Scenario: ECDSA ES384 BadBase64 corruption
    Given a deterministic factory seeded with "neg-ecdsa384-badbase64"
    When I generate an ECDSA ES384 key for label "es384-base64"
    And I corrupt the ECDSA PKCS8 PEM with BadBase64
    Then the corrupted ECDSA PEM should contain "THIS_IS_NOT_BASE64"
    And the corrupted ECDSA PEM should fail to parse

  Scenario: ECDSA ES384 DER truncation
    Given a deterministic factory seeded with "neg-ecdsa384-truncate"
    When I generate an ECDSA ES384 key for label "es384-truncate"
    And I truncate the ECDSA PKCS8 DER to 50 bytes
    Then the truncated ECDSA DER should have length 50
    And the truncated ECDSA DER should fail to parse

  # --- Deterministic corruption stability across key types ---

  Scenario: ECDSA deterministic DER corruption is stable
    Given a deterministic factory seeded with "neg-ecdsa-det-der-stable"
    When I generate an ECDSA ES256 key for label "det-stable"
    And I deterministically corrupt the ECDSA PKCS8 DER with variant "v1"
    And I deterministically corrupt the ECDSA PKCS8 DER with variant "v1" again
    Then the deterministic binary artifacts should be identical
    And the deterministic ECDSA DER artifact should fail to parse

  Scenario: Ed25519 deterministic DER corruption is stable
    Given a deterministic factory seeded with "neg-ed25519-det-der-stable"
    When I generate an Ed25519 key for label "det-stable"
    And I deterministically corrupt the Ed25519 PKCS8 DER with variant "v1"
    And I deterministically corrupt the Ed25519 PKCS8 DER with variant "v1" again
    Then the deterministic binary artifacts should be identical
    And the deterministic Ed25519 DER artifact should fail to parse

  # --- Mismatched keys across all types ---

  Scenario: RSA mismatched SPKI DER is parseable but different
    Given a deterministic factory seeded with "neg-rsa-mismatch-parse"
    When I generate an RSA key for label "mismatch-rsa"
    Then a mismatched SPKI DER should parse and differ

  Scenario: ECDSA mismatched SPKI DER is parseable but different
    Given a deterministic factory seeded with "neg-ecdsa-mismatch-parse"
    When I generate an ECDSA ES256 key for label "mismatch-ecdsa"
    Then an ECDSA mismatched SPKI DER should parse and differ

  Scenario: Ed25519 mismatched SPKI DER is parseable but different
    Given a deterministic factory seeded with "neg-ed25519-mismatch-parse"
    When I generate an Ed25519 key for label "mismatch-ed25519"
    Then an Ed25519 mismatched SPKI DER should parse and differ

  # --- DER truncation edge cases ---

  Scenario: RSA DER truncation to 1 byte
    Given a deterministic factory seeded with "neg-rsa-truncate-1"
    When I generate an RSA key for label "truncate-rsa"
    And I truncate the PKCS8 DER to 1 bytes
    Then the truncated DER should have length 1
    And the truncated DER should fail to parse

  Scenario: ECDSA DER truncation to 1 byte
    Given a deterministic factory seeded with "neg-ecdsa-truncate-1"
    When I generate an ECDSA ES256 key for label "truncate-ecdsa"
    And I truncate the ECDSA PKCS8 DER to 1 bytes
    Then the truncated ECDSA DER should have length 1
    And the truncated ECDSA DER should fail to parse

  Scenario: Ed25519 DER truncation to 1 byte
    Given a deterministic factory seeded with "neg-ed25519-truncate-1"
    When I generate an Ed25519 key for label "truncate-ed25519"
    And I truncate the Ed25519 PKCS8 DER to 1 bytes
    Then the truncated Ed25519 DER should have length 1
    And the truncated Ed25519 DER should fail to parse

  # --- Corruption does not affect the original key ---

  Scenario: RSA corruption leaves original PKCS8 PEM intact
    Given a deterministic factory seeded with "neg-rsa-original-intact"
    When I generate an RSA key for label "intact-rsa"
    And I corrupt the PKCS8 PEM with BadHeader
    Then the corrupted PEM should fail to parse
    And the PKCS8 DER should be parseable

  Scenario: ECDSA corruption leaves original PKCS8 DER intact
    Given a deterministic factory seeded with "neg-ecdsa-original-intact"
    When I generate an ECDSA ES256 key for label "intact-ecdsa"
    And I corrupt the ECDSA PKCS8 PEM with BadBase64
    Then the corrupted ECDSA PEM should fail to parse
    And the ECDSA PKCS8 DER should be parseable

  Scenario: Ed25519 corruption leaves original PKCS8 DER intact
    Given a deterministic factory seeded with "neg-ed25519-original-intact"
    When I generate an Ed25519 key for label "intact-ed25519"
    And I corrupt the Ed25519 PKCS8 PEM with BadFooter
    Then the corrupted Ed25519 PEM should fail to parse
    And the Ed25519 PKCS8 DER should be parseable
