Feature: JWKS (JSON Web Key Set) builder
  As a test author
  I want to build JWKS collections from multiple keys
  So that I can test JWT verification with multiple signing keys

  # --- JWKS building ---

  Scenario: build JWKS from RSA key
    Given a deterministic factory seeded with "jwks-rsa-test"
    When I generate an RSA key for label "rsa-signer" with spec RS256
    And I build a JWKS containing the RSA key with kid "key-1"
    Then the JWKS should contain 1 key
    And the JWKS should contain a key with kid "key-1"
    And the JWKS should contain a key with kty "RSA"

  Scenario: build JWKS from ECDSA key
    Given a deterministic factory seeded with "jwks-ecdsa-test"
    When I generate an ECDSA ES256 key for label "ecdsa-signer"
    And I build a JWKS containing the ECDSA key with kid "es256-key"
    Then the JWKS should contain 1 key
    And the JWKS should contain a key with kid "es256-key"
    And the JWKS should contain a key with kty "EC"

  Scenario: build JWKS from Ed25519 key
    Given a deterministic factory seeded with "jwks-ed25519-test"
    When I generate an Ed25519 key for label "ed25519-signer"
    And I build a JWKS containing the Ed25519 key with kid "eddsa-key"
    Then the JWKS should contain 1 key
    And the JWKS should contain a key with kid "eddsa-key"
    And the JWKS should contain a key with kty "OKP"

  Scenario: build JWKS from HMAC secret
    Given a deterministic factory seeded with "jwks-hmac-test"
    When I generate an HMAC HS256 secret for label "hmac-signer"
    And I build a JWKS containing the HMAC secret with kid "hs256-key"
    Then the JWKS should contain 1 key
    And the JWKS should contain a key with kid "hs256-key"
    And the JWKS should contain a key with kty "oct"

  # --- Multi-key JWKS ---

  Scenario: build JWKS with multiple key types
    Given a deterministic factory seeded with "jwks-multi-test"
    When I generate an RSA key for label "rsa-multi" with spec RS256
    And I generate an ECDSA ES256 key for label "ecdsa-multi"
    And I generate an Ed25519 key for label "ed25519-multi"
    And I generate an HMAC HS256 secret for label "hmac-multi"
    And I build a JWKS containing all keys
    Then the JWKS should contain 4 keys
    And the JWKS should contain a key with kty "RSA"
    And the JWKS should contain a key with kty "EC"
    And the JWKS should contain a key with kty "OKP"
    And the JWKS should contain a key with kty "oct"

  Scenario: JWKS keys have unique kids
    Given a deterministic factory seeded with "jwks-unique-test"
    When I generate an RSA key for label "rsa-1" with spec RS256
    And I generate an RSA key for label "rsa-2" with spec RS256
    And I build a JWKS with the RSA keys with kids "key-a" and "key-b"
    Then the JWKS should contain 2 keys
    And each key in the JWKS should have a unique kid

  # --- Deterministic ordering ---

  Scenario: JWKS has deterministic ordering in deterministic mode
    Given a deterministic factory seeded with "jwks-order-test"
    When I generate an RSA key for label "rsa-order" with spec RS256
    And I generate an ECDSA ES256 key for label "ecdsa-order"
    And I generate an Ed25519 key for label "ed25519-order"
    And I build a JWKS containing all keys with kids "z-key", "a-key", "m-key"
    And I build another JWKS containing all keys with kids "z-key", "a-key", "m-key"
    Then both JWKS outputs should be identical

  # --- JWKS JSON format ---

  Scenario: JWKS JSON structure is valid
    Given a deterministic factory seeded with "jwks-json-test"
    When I generate an RSA key for label "rsa-json" with spec RS256
    And I build a JWKS containing the RSA key with kid "json-key"
    Then the JWKS JSON should have a "keys" array
    And the JWKS JSON should be parseable

  Scenario: RSA JWKS key contains required fields
    Given a deterministic factory seeded with "jwks-rsa-fields-test"
    When I generate an RSA key for label "rsa-fields" with spec RS256
    And I build a JWKS containing the RSA key with kid "rsa-fields-key"
    Then the JWKS RSA key should contain field "n"
    And the JWKS RSA key should contain field "e"
    And the JWKS RSA key should contain field "kty"
    And the JWKS RSA key should contain field "kid"
    And the JWKS RSA key should contain field "alg"

  Scenario: ECDSA JWKS key contains required fields
    Given a deterministic factory seeded with "jwks-ecdsa-fields-test"
    When I generate an ECDSA ES256 key for label "ecdsa-fields"
    And I build a JWKS containing the ECDSA key with kid "ecdsa-fields-key"
    Then the JWKS EC key should contain field "x"
    And the JWKS EC key should contain field "y"
    And the JWKS EC key should contain field "crv"
    And the JWKS EC key should contain field "kty"
    And the JWKS EC key should contain field "kid"

  # --- Public vs Private JWK ---

  Scenario: JWKS contains only public keys
    Given a deterministic factory seeded with "jwks-public-test"
    When I generate an RSA key for label "rsa-pub" with spec RS256
    And I build a JWKS containing the RSA public key with kid "pub-key"
    Then the JWKS RSA key should not contain field "d"
    And the JWKS RSA key should not contain field "p"
    And the JWKS RSA key should not contain field "q"

  # --- Empty JWKS ---

  Scenario: empty JWKS is valid
    Given a deterministic factory seeded with "jwks-empty-test"
    When I build an empty JWKS
    Then the JWKS should contain 0 keys
    And the JWKS JSON should have an empty "keys" array
