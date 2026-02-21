Feature: Core ID derivation primitives
  As a test author
  I want deterministic seed and identity helpers in the core microcrate
  So that fixture derivation is stable and auditable across versions

  Background:
    Given a core-id master seed "uselesskey-core-id-example"

  Scenario: deterministic derivation is stable for identical inputs
    When I derive a core-id seed with domain "uselesskey:rsa:keypair", label "entity", spec "fixture-spec", variant "v1"
    When I derive a core-id seed with domain "uselesskey:rsa:keypair", label "entity", spec "fixture-spec", variant "v1"
    Then the first and second derived core-id seeds should be identical

  Scenario: domain and variant changes alter output
    When I derive a core-id seed with domain "uselesskey:rsa:keypair", label "entity", spec "fixture-spec", variant "v1"
    And I derive a core-id seed with domain "uselesskey:rsa:keypair", label "entity", spec "fixture-spec", variant "v2"
    Then the first and second derived core-id seeds should be different

  Scenario: seed debug output is redacted
    Then the core-id master seed should be redacted in debug output
