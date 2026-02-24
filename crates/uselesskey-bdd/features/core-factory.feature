Feature: Core factory determinism and cache behavior
  As a test author
  I want factory cache behavior to be independently validated
  So deterministic and cache behavior remains stable across refactors

  Scenario: deterministic cache values are stable
    Given a deterministic factory seeded with "core-factory-seed-1"
    When I request a core-factory u64 value for domain "core-factory", label "label-a", spec "factory-spec", variant "default"
    And I request a core-factory u64 value for domain "core-factory", label "label-a", spec "factory-spec", variant "default"
    Then the first and second core-factory values should match

  Scenario: clearing the cache preserves deterministic values
    Given a deterministic factory seeded with "core-factory-seed-2"
    When I request a core-factory u64 value for domain "core-factory", label "label-b", spec "factory-spec", variant "default"
    And I clear the factory cache
    And I request a core-factory u64 value for domain "core-factory", label "label-b", spec "factory-spec", variant "default"
    Then the first and second core-factory values should match

  Scenario: random mode keeps stable cache values within a process
    Given a random factory
    When I request a core-factory u64 value for domain "core-factory", label "label-c", spec "factory-spec", variant "default"
    And I request a core-factory u64 value for domain "core-factory", label "label-c", spec "factory-spec", variant "default"
    Then the first and second core-factory values should match

  Scenario: mismatched value types are rejected
    Given a random factory
    When I request a core-factory u32 value for domain "core-factory", label "label-type", spec "factory-spec", variant "default"
    And I request a mismatched core-factory value for domain "core-factory", label "label-type", spec "factory-spec", variant "default"
    Then a core-factory type mismatch should panic
