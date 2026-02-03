# Security policy

This repository ships **test fixture generators**.

- Do not use in production.
- Do not use as a key management tool.
- Do not assume deterministic fixtures are secret.

## Reporting

If you believe there is a security issue in the code itself (e.g. memory safety issue, unexpected disclosure in logs),
open a private report or a GitHub security advisory.

If your scanner flags runtime-generated outputs, that is expected; configure scanning exclusions for build/test artifacts
rather than committing fixture blobs.
