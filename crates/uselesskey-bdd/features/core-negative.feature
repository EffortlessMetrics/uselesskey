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

  Scenario: DER corruption and truncation are malformed
    Given I have a sample DER fixture for core-negative
    When I core-negatively truncate a DER sample to 3 bytes
    Then the truncated DER should have length 3
    And the truncated DER should fail to parse
