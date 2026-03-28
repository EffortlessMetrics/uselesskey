# uselesskey-pqc

Experimental PQC fixtures for test code.

This crate is intentionally **opaque-first**:
- deterministic large vectors for parser/buffer/TLS-prep tests
- malformed/truncated size negatives
- no production-readiness claims

`PqcFixtureMode::Real` is reserved for future ML-KEM / ML-DSA backends when ecosystem maturity is sufficient.
