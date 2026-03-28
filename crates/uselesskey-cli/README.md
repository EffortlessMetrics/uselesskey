# uselesskey-cli

Manifest and export helpers for handing uselesskey-generated fixtures to local tooling and secret-store ingestion paths.

This crate is intentionally focused on one-shot export flows:

1. Generate fixtures once.
2. Write bundle outputs and metadata manifest.
3. Exit.

It does **not** implement rotation engines, lease management, retrieval APIs, or long-running secret-store behavior.
