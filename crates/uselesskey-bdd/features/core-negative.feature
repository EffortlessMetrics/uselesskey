Feature: Core negative fixture primitives
  As a test author
  I want deterministic and deterministicish PEM/DER corruption utilities
  So that I can verify interoperability with existing error-path checks

  Scenario: PEM can be deterministically corrupted and will fail parsing
    Given I have a sample PEM fixture for core-negative
    When I core-negatively corrupt the sample PEM with variant "core-id-v1"
    Then the deterministic RSA PEM artifact should fail to parse

  Scenario: deterministic PEM corruption is stable
    Given I have a sample PEM fixture for core-negative
    When I core-negatively corrupt the sample PEM with variant "core-id-v1"
    And I core-negatively corrupt the sample PEM with variant "core-id-v1" again
    Then the deterministic text artifacts should be identical

  Scenario: different PEM corruption variants produce different outputs
    Given I have a sample PEM fixture for core-negative
    When I core-negatively corrupt the sample PEM with variant "variant-a"
    And I core-negatively corrupt the sample PEM with variant "variant-b" again
    Then the deterministic text artifacts should differ

  Scenario: DER corruption and truncation are malformed
    Given I have a sample DER fixture for core-negative
    When I core-negatively truncate a DER sample to 3 bytes
    Then the truncated DER should have length 3
    And the truncated DER should fail to parse

  Scenario: DER truncation to 1 byte yields minimal output
    Given I have a sample DER fixture for core-negative
    When I core-negatively truncate a DER sample to 1 bytes
    Then the truncated DER should have length 1

  Scenario: DER truncation to 0 bytes yields empty output
    Given I have a sample DER fixture for core-negative
    When I core-negatively truncate a DER sample to 0 bytes
    Then the truncated DER should have length 0

  Scenario: DER truncation beyond length returns original
    Given I have a sample DER fixture for core-negative
    When I core-negatively truncate a DER sample to 99999 bytes
    Then the truncated DER should have length 8
