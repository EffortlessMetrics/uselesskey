# Roadmap

A reasonable v0.2 might add:

- ECDSA / Ed25519 fixtures (`p256`, `p384`, `ed25519-dalek`)
- X.509 leaf/cert chain fixtures (`rcgen` or `x509-cert`)
- adapters for common stacks (jsonwebtoken, rustls, aws-lc-rs)
- deterministic “corruptions” derived via variant + RNG rather than hard-coded transforms
- a `no_std` core (if worth it)
