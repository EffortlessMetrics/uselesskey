Feature: Core token shape primitives
  As a test author
  I want deterministic token shape generation primitives in isolation
  So that token format behavior stays stable across releases

  Scenario: API key shape generation is deterministic
    When I generate a core token-shape API key with seed "core-token-shape-001"
    And I generate a core token-shape API key with seed "core-token-shape-001"
    Then the first and second core token-shape values should be identical

  Scenario: API key shape has expected prefix and length
    When I generate a core token-shape API key with seed "core-token-shape-prefix"
    Then the first core token-shape value should start with "uk_test_"
    And the first core token-shape value should have length 40

  Scenario: token-shape kinds use expected authorization schemes
    Then the core-token-shape authorization scheme for API key should be "ApiKey"
    And the core-token-shape authorization scheme for bearer token should be "Bearer"
    And the core-token-shape authorization scheme for OAuth access token should be "Bearer"

  Scenario: bearer and OAuth token-shape formats are different
    When I generate a core token-shape bearer token with seed "core-token-shape-kinds"
    And I generate a core token-shape OAuth access token with seed "core-token-shape-kinds" and subject "tenant-a"
    Then the first and second core token-shape values should be different

  Scenario: bearer token-shape is base64url encoded bytes
    When I generate a core token-shape bearer token with seed "core-token-shape-bearer"
    Then the first core token-shape value should be valid base64url

  Scenario: OAuth token-shape has JWT-style segments
    When I generate a core token-shape OAuth access token with seed "core-token-shape-oauth" and subject "oauth-subject"
    Then the first core token-shape value should have three dot-separated segments
