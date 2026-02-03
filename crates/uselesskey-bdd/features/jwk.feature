Feature: JWK generation
  As a test author
  I want to generate JWK fixtures
  So that I can test JWT verification flows

  Background:
    Given a deterministic factory seeded with "jwk-test-seed"

  Scenario: public JWK has required fields
    When I generate an RSA key for label "auth-service"
    Then the public JWK should have kty "RSA"
    And the public JWK should have alg "RS256"
    And the public JWK should have use "sig"
    And the public JWK should have a kid
    And the public JWK should have n and e parameters

  Scenario: JWKS wraps the JWK in keys array
    When I generate an RSA key for label "auth-service"
    Then the JWKS should have a keys array
    And the JWKS keys array should contain one key

  Scenario: kid is deterministic
    When I generate an RSA key for label "stable-kid"
    And I capture the kid
    And I clear the factory cache
    And I generate an RSA key for label "stable-kid"
    And I capture the kid again
    Then the kids should be identical

  Scenario: kid differs for different keys
    When I generate an RSA key for label "key-one"
    And I capture the kid
    And I generate an RSA key for label "key-two"
    And I capture the kid again
    Then the kids should differ
