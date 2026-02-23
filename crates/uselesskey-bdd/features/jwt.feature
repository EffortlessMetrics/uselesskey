Feature: JWT signing and verification
  As a test author
  I want to sign and verify JWT fixtures
  So that I can test JWT-based authentication flows with uselesskey keys

  # --- Signing ---

  Scenario: sign JWT with RSA
    Given a deterministic factory seeded with "jwt-rsa-test"
    When I generate an RSA key for label "jwt-rsa"
    And I sign a JWT with the RSA key
    Then the JWT should be valid
    And the JWT header should have alg "RS256"
    And the JWT subject should be "jwt-subject"

  Scenario: sign JWT with ECDSA
    Given a deterministic factory seeded with "jwt-ecdsa-test"
    When I generate an ECDSA ES256 key for label "jwt-ecdsa"
    And I sign a JWT with the ECDSA key
    Then the JWT should be valid
    And the JWT header should have alg "ES256"
    And the JWT subject should be "jwt-subject"

  Scenario: sign JWT with Ed25519
    Given a deterministic factory seeded with "jwt-ed25519-test"
    When I generate an Ed25519 key for label "jwt-ed25519"
    And I sign a JWT with the Ed25519 key
    Then the JWT should be valid
    And the JWT header should have alg "EdDSA"
    And the JWT subject should be "jwt-subject"

  Scenario: sign JWT with HMAC
    Given a deterministic factory seeded with "jwt-hmac-test"
    When I generate an HMAC HS256 secret for label "jwt-hmac"
    And I sign a JWT with the HMAC key
    Then the JWT should be valid
    And the JWT header should have alg "HS256"
    And the JWT subject should be "jwt-subject"

  # --- Verification ---

  Scenario: verify JWT with RSA public key
    Given a deterministic factory seeded with "jwt-verify-rsa"
    When I generate an RSA key for label "jwt-verify-rsa"
    And I sign a JWT with the RSA key
    And I verify the JWT with the RSA public key
    Then the JWT should be valid

  Scenario: verify JWT with JWKS
    Given a deterministic factory seeded with "jwt-jwks"
    When I generate an RSA key for label "jwt-jwks"
    And I build a JWKS containing the RSA key with kid "jwt-key"
    And I sign a JWT with the RSA key
    And I verify the JWT with the JWKS
    Then the JWT should be valid

  Scenario: verify JWT fails with wrong algorithm
    Given a deterministic factory seeded with "jwt-wrong-alg"
    When I generate an RSA key for label "jwt-wrong-alg"
    And I sign a JWT with the RSA key
    And I attempt to verify the JWT with ES256 algorithm
    Then the JWT verification should fail

  Scenario: verify JWT fails with wrong key
    Given a deterministic factory seeded with "jwt-wrong-key"
    When I generate an RSA key for label "jwt-wrong"
    And I sign a JWT with the RSA key
    And I generate another RSA key for label "jwt-wrong-2"
    And I attempt to verify the JWT with the second RSA key
    Then the JWT verification should fail
