Feature: Core kid derivation primitives
  As a test author
  I want a dedicated microcrate for deterministic key identifiers
  So that fixture crates share one stable kid algorithm

  Scenario: derived core-kid is deterministic for identical bytes
    When I derive a core-kid from bytes "fixture-public-key"
    And I derive a core-kid from bytes "fixture-public-key"
    Then the first and second derived core-kids should be identical

  Scenario: derived core-kid changes when bytes change
    When I derive a core-kid from bytes "fixture-public-key-a"
    And I derive a core-kid from bytes "fixture-public-key-b"
    Then the first and second derived core-kids should be different

  Scenario: derived core-kid supports explicit prefix sizing
    When I derive a core-kid with prefix 8 from bytes "fixture-public-key"
    Then the derived core-kid should decode to 8 bytes
