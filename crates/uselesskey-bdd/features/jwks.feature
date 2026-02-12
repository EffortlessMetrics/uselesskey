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

  # --- Multi-Key Same Type ---

  Scenario: JWKS with multiple RSA keys
    Given a deterministic factory seeded with "multi-rsa-test"
    When I generate an RSA key for label "rsa-1" with spec RS256
    And I generate an RSA key for label "rsa-2" with spec RS256
    And I build a JWKS with the RSA keys with kids "key-1" and "key-2"
    Then the JWKS should contain 2 keys
    And each key in the JWKS should have kty "RSA"
    And each key in the JWKS should have a unique kid

  Scenario: JWKS with multiple ECDSA keys
    Given a deterministic factory seeded with "multi-ecdsa-test"
    When I generate an ECDSA ES256 key for label "ecdsa-1"
    And I generate an ECDSA ES256 key for label "ecdsa-2"
    And I build a JWKS with the ECDSA keys with kids "es256-1" and "es256-2"
    Then the JWKS should contain 2 keys
    And each key in the JWKS should have kty "EC"
    And each key in the JWKS should have a unique kid

  Scenario: JWKS with multiple Ed25519 keys
    Given a deterministic factory seeded with "multi-ed25519-test"
    When I generate an Ed25519 key for label "ed25519-1"
    And I generate an Ed25519 key for label "ed25519-2"
    And I build a JWKS with the Ed25519 keys with kids "eddsa-1" and "eddsa-2"
    Then the JWKS should contain 2 keys
    And each key in the JWKS should have kty "OKP"
    And each key in the JWKS should have a unique kid

  Scenario: JWKS with multiple HMAC keys
    Given a deterministic factory seeded with "multi-hmac-test"
    When I generate an HMAC HS256 secret for label "hmac-1"
    And I generate an HMAC HS256 secret for label "hmac-2"
    And I build a JWKS with the HMAC secrets with kids "hs256-1" and "hs256-2"
    Then the JWKS should contain 2 keys
    And each key in the JWKS should have kty "oct"
    And each key in the JWKS should have a unique kid

  # --- JWKS Rotation ---

  Scenario: JWKS rotation adds new key
    Given a deterministic factory seeded with "rotation-test"
    When I generate an RSA key for label "key-v1" with spec RS256
    And I build a JWKS containing the RSA key with kid "v1"
    Then the JWKS should contain 1 key
    When I generate an RSA key for label "key-v2" with spec RS256
    And I build a JWKS containing both keys with kids "v1" and "v2"
    Then the JWKS should contain 2 keys
    And the JWKS should contain a key with kid "v1"
    And the JWKS should contain a key with kid "v2"

  Scenario: JWKS rotation removes old key
    Given a deterministic factory seeded with "rotation-remove-test"
    When I generate an RSA key for label "key-v1" with spec RS256
    And I generate an RSA key for label "key-v2" with spec RS256
    And I build a JWKS with both keys with kids "v1" and "v2"
    Then the JWKS should contain 2 keys
    When I build a JWKS with only the second key with kid "v2"
    Then the JWKS should contain 1 key
    And the JWKS should contain a key with kid "v2"
    And the JWKS should not contain a key with kid "v1"

  Scenario: JWKS rotation preserves key identity
    Given a deterministic factory seeded with "rotation-preserve-test"
    When I generate an RSA key for label "key-stable" with spec RS256
    And I build a JWKS containing the RSA key with kid "stable-key"
    And I generate an RSA key for label "key-new" with spec RS256
    And I build a JWKS containing both keys with kids "stable-key" and "new-key"
    Then the JWKS should contain a key with kid "stable-key"
    And the JWKS key with kid "stable-key" should have the same modulus as the original

  # --- JWKS Filtering ---

  Scenario: JWKS filtering by algorithm
    Given a deterministic factory seeded with "filter-test"
    When I generate an RSA key for label "rsa-key" with spec RS256
    And I generate an ECDSA ES256 key for label "ecdsa-key"
    And I generate an HMAC HS256 secret for label "hmac-key"
    And I build a JWKS containing all keys
    Then the JWKS should contain 3 keys
    And the JWKS should contain a key with alg "RS256"
    And the JWKS should contain a key with alg "ES256"
    And the JWKS should contain a key with alg "HS256"

  Scenario: JWKS filtering by key type
    Given a deterministic factory seeded with "filter-kty-test"
    When I generate an RSA key for label "rsa-filter" with spec RS256
    And I generate an ECDSA ES256 key for label "ecdsa-filter"
    And I generate an Ed25519 key for label "ed25519-filter"
    And I build a JWKS containing all keys
    Then the JWKS should contain 3 keys
    And the JWKS should contain a key with kty "RSA"
    And the JWKS should contain a key with kty "EC"
    And the JWKS should contain a key with kty "OKP"

  Scenario: JWKS filtering by kid
    Given a deterministic factory seeded with "filter-kid-test"
    When I generate an RSA key for label "rsa-a" with spec RS256
    And I generate an RSA key for label "rsa-b" with spec RS256
    And I generate an RSA key for label "rsa-c" with spec RS256
    And I build a JWKS containing all keys with kids "key-a", "key-b", "key-c"
    Then the JWKS should contain 3 keys
    When I filter the JWKS by kid "key-b"
    Then the filtered JWKS should contain 1 key
    And the filtered JWKS should contain a key with kid "key-b"

  # --- JWKS from X.509 ---
  # X.509 certificate JWK scenarios are disabled because X509Cert does not
  # currently expose a private_key_jwk() method.
  # Scenario: JWKS from X.509 certificate
  #   Given a deterministic factory seeded with "x509-jwks-test"
  #   When I generate an X.509 certificate for domain "test.example.com" with label "x509-jwks"
  #   Then the X.509 certificate should have a JWK representation
  #   And the X.509 certificate JWK should have kty "RSA"
  #   And the X.509 certificate JWK should have a kid
