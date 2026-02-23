Feature: Core keypair material primitives
  As a test author
  I want a shared PKCS8/SPKI microcrate
  So that key fixture crates reuse one stable API for output and corruption helpers

  Background:
    Given I have a sample PKCS8/SPKI fixture for core-keypair

  Scenario: deterministic corruption is stable
    When I deterministically core-keypair corrupt PKCS8 PEM with variant "core-keypair-v1"
    And I deterministically core-keypair corrupt PKCS8 PEM with variant "core-keypair-v1" again
    Then the deterministic text artifacts should be identical
    And the core-keypair deterministic PEM should differ from the original

  Scenario: DER truncation respects requested length
    When I truncate the core-keypair PKCS8 DER to 3 bytes
    Then the truncated DER should have length 3

  Scenario: key IDs and tempfile outputs are stable and usable
    When I derive a core-keypair kid
    And I derive a core-keypair kid
    And I write core-keypair PEM artifacts to tempfiles
    Then the first and second core-keypair kids should be identical
    And the core-keypair private and public tempfiles should contain PEM headers
