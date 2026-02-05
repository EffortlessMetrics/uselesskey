Feature: HMAC fixtures
  As a test author
  I want to generate HMAC secret fixtures
  So that I can test HS256/HS384/HS512 flows without committing secrets

  Scenario: deterministic HMAC secrets are stable
    Given a deterministic factory seeded with "hmac-seed"
    When I generate an HMAC HS256 secret for label "issuer"
    And I generate an HMAC HS256 secret for label "issuer" again
    Then the HMAC secrets should be identical

  Scenario: HMAC JWK has required fields
    Given a deterministic factory seeded with "hmac-jwk"
    When I generate an HMAC HS256 secret for label "jwt-signer"
    Then the HMAC JWK should have kty "oct"
    And the HMAC JWK should have alg "HS256"
    And the HMAC JWK should have use "sig"
    And the HMAC JWK should have a kid
    And the HMAC JWK should have k parameter

  Scenario: HMAC JWKS has valid structure
    Given a deterministic factory seeded with "hmac-jwks"
    When I generate an HMAC HS256 secret for label "issuer"
    Then the HMAC JWKS should have a keys array
    And the HMAC JWKS keys array should contain one key
