Feature: PGP fixtures
  As a test author
  I want to generate OpenPGP key fixtures
  So that I can test PGP cryptographic workflows without committing secrets

  # --- Determinism (Ed25519) ---

  Scenario: deterministic Ed25519 PGP fixtures are stable
    Given a deterministic factory seeded with "0x0000000000000000000000000000000000000000000000000000000000000042"
    When I generate an Ed25519 PGP key for label "signer"
    And I generate an Ed25519 PGP key for label "signer" again
    Then the PGP private key armor should be identical

  # Note: PGP keygen embeds a creation timestamp from the pgp crate,
  # so cache-clear determinism is not supported (unlike RSA/ECDSA).

  Scenario: different labels produce different PGP keys
    Given a deterministic factory seeded with "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    When I generate an Ed25519 PGP key for label "alice"
    And I generate another Ed25519 PGP key for label "bob"
    Then the PGP fingerprints should be different

  Scenario: different seeds produce different PGP keys
    Given a deterministic factory seeded with "seed-one"
    When I generate an Ed25519 PGP key for label "service"
    And I switch to a deterministic factory seeded with "seed-two"
    And I generate another Ed25519 PGP key for label "service"
    Then the PGP fingerprints should be different

  # --- Random mode ---

  Scenario: random factory produces different PGP keys each time
    Given a random factory
    When I generate an Ed25519 PGP key for label "ephemeral"
    And I clear the factory cache
    And I generate an Ed25519 PGP key for label "ephemeral" again
    Then the PGP fingerprints should be different

  Scenario: random factory caches PGP within same session
    Given a random factory
    When I generate an Ed25519 PGP key for label "cached"
    And I generate an Ed25519 PGP key for label "cached" again
    Then the PGP private key armor should be identical

  # --- RSA 2048 variant ---

  Scenario: deterministic RSA 2048 PGP fixtures are stable
    Given a deterministic factory seeded with "pgp-rsa2048-seed"
    When I generate an RSA 2048 PGP key for label "rsa-signer"
    And I generate an RSA 2048 PGP key for label "rsa-signer" again
    Then the PGP private key armor should be identical

  Scenario: RSA 2048 PGP key has correct armor format
    Given a deterministic factory seeded with "pgp-rsa2048-format"
    When I generate an RSA 2048 PGP key for label "rsa-test"
    Then the PGP private key armor should contain "BEGIN PGP PRIVATE KEY BLOCK"
    And the PGP public key armor should contain "BEGIN PGP PUBLIC KEY BLOCK"

  # --- RSA 3072 variant ---

  Scenario: deterministic RSA 3072 PGP fixtures are stable
    Given a deterministic factory seeded with "pgp-rsa3072-seed"
    When I generate an RSA 3072 PGP key for label "rsa3072-signer"
    And I generate an RSA 3072 PGP key for label "rsa3072-signer" again
    Then the PGP private key armor should be identical

  Scenario: RSA 3072 and RSA 2048 produce different keys for same label
    Given a deterministic factory seeded with "pgp-rsa-variant-test"
    When I generate an RSA 2048 PGP key for label "shared-label"
    And I generate another RSA 3072 PGP key for label "shared-label"
    Then the PGP fingerprints should be different

  # --- Ed25519 variant ---

  Scenario: Ed25519 PGP key has correct armor format
    Given a deterministic factory seeded with "pgp-ed25519-format"
    When I generate an Ed25519 PGP key for label "ed25519-test"
    Then the PGP private key armor should contain "BEGIN PGP PRIVATE KEY BLOCK"
    And the PGP public key armor should contain "BEGIN PGP PUBLIC KEY BLOCK"

  Scenario: Ed25519 and RSA 2048 produce different keys for same label
    Given a deterministic factory seeded with "pgp-algo-variant-test"
    When I generate an Ed25519 PGP key for label "shared-label"
    And I generate another RSA 2048 PGP key for label "shared-label"
    Then the PGP fingerprints should be different

  # --- Key formats ---

  Scenario: PGP private key binary is valid
    Given a deterministic factory seeded with "pgp-binary-test"
    When I generate an Ed25519 PGP key for label "binary-test"
    Then the PGP private key binary should be parseable

  Scenario: PGP public key binary is valid
    Given a deterministic factory seeded with "pgp-pub-binary-test"
    When I generate an Ed25519 PGP key for label "pub-binary-test"
    Then the PGP public key binary should be parseable

  Scenario: PGP armored private key parses and matches fingerprint
    Given a deterministic factory seeded with "pgp-parse-test"
    When I generate an Ed25519 PGP key for label "parse-test"
    Then the PGP private key armor should be parseable
    And the parsed PGP key fingerprint should match

  Scenario: PGP armored public key parses and matches fingerprint
    Given a deterministic factory seeded with "pgp-pub-parse-test"
    When I generate an Ed25519 PGP key for label "pub-parse-test"
    Then the PGP public key armor should be parseable
    And the parsed PGP public key fingerprint should match

  # --- User ID ---

  Scenario: PGP user ID is generated from label
    Given a deterministic factory seeded with "pgp-userid-test"
    When I generate an Ed25519 PGP key for label "Test User"
    Then the PGP user ID should contain "Test User"
    And the PGP user ID should contain "@uselesskey.test"

  Scenario: PGP user ID sanitizes special characters
    Given a deterministic factory seeded with "pgp-sanitize-test"
    When I generate an Ed25519 PGP key for label "Test!@#User"
    Then the PGP user ID should contain "Test!@#User"

  # --- Fingerprint ---

  Scenario: PGP fingerprint is exposed
    Given a deterministic factory seeded with "pgp-fp-test"
    When I generate an Ed25519 PGP key for label "fp-test"
    Then the PGP fingerprint should be non-empty

  # --- Negative fixtures: mismatched keys ---

  Scenario: mismatched PGP public key is different
    Given a random factory
    When I generate an Ed25519 PGP key for label "signer"
    Then a PGP mismatched public key binary should parse and differ

  Scenario: mismatched PGP key is deterministic
    Given a deterministic factory seeded with "pgp-mismatch-test"
    When I generate an Ed25519 PGP key for label "victim"
    And I get the mismatched PGP public key binary
    And I get the mismatched PGP public key binary again
    Then the mismatched PGP keys should be identical

  Scenario: mismatched PGP armored public key differs
    Given a deterministic factory seeded with "pgp-mismatch-armor-test"
    When I generate an Ed25519 PGP key for label "armor-victim"
    Then a PGP mismatched public key armor should differ from original

  # --- Negative fixtures: corruption ---

  Scenario: PGP corrupted armor with BadBase64
    Given a deterministic factory seeded with "pgp-corrupt-test"
    When I generate an Ed25519 PGP key for label "corrupted"
    And I corrupt the PGP private key armor with BadBase64
    Then the corrupted PGP armor should contain "THIS_IS_NOT_BASE64!!!"

  Scenario: PGP truncated binary fails to parse
    Given a deterministic factory seeded with "pgp-truncate-test"
    When I generate an Ed25519 PGP key for label "truncated"
    And I truncate the PGP private key binary to 32 bytes
    Then the truncated PGP binary should have length 32
    And the truncated PGP binary should fail to parse

  Scenario: PGP deterministically corrupted armor is stable
    Given a deterministic factory seeded with "pgp-det-corrupt-test"
    When I generate an Ed25519 PGP key for label "det-corrupt"
    And I deterministically corrupt the PGP private key armor with variant "v1"
    And I deterministically corrupt the PGP private key armor with variant "v1" again
    Then the corrupted PGP armors should be identical

  Scenario: PGP deterministically corrupted binary is stable
    Given a deterministic factory seeded with "pgp-det-bin-corrupt-test"
    When I generate an Ed25519 PGP key for label "det-bin-corrupt"
    And I deterministically corrupt the PGP private key binary with variant "v1"
    And I deterministically corrupt the PGP private key binary with variant "v1" again
    Then the corrupted PGP binaries should be identical

  # --- Tempfile support ---

  Scenario: PGP private key armor tempfile is valid
    Given a deterministic factory seeded with "pgp-tempfile-test"
    When I generate an Ed25519 PGP key for label "tempfile"
    And I write the PGP private key armor to a tempfile
    Then the PGP tempfile should exist
    And the PGP tempfile should contain "BEGIN PGP PRIVATE KEY BLOCK"

  Scenario: PGP public key armor tempfile is valid
    Given a deterministic factory seeded with "pgp-pub-tempfile-test"
    When I generate an Ed25519 PGP key for label "pub-tempfile"
    And I write the PGP public key armor to a tempfile
    Then the PGP public tempfile should exist
    And the PGP public tempfile should contain "BEGIN PGP PUBLIC KEY BLOCK"

  # --- Debug safety ---

  Scenario: PGP debug output does not leak key material
    Given a deterministic factory seeded with "pgp-debug-test"
    When I generate an Ed25519 PGP key for label "debug-test"
    Then the PGP debug output should not contain the private key armor
    And the PGP debug output should contain the fingerprint
