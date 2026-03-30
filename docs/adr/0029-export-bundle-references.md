# ADR-0029: Export Bundles as References, Not Secret Custody

## Status

Accepted

## Context

`uselesskey` already generates deterministic fixtures and supports shape-first
exports (PEM/DER/JWK/tempfiles), but handoff into real-world delivery tooling
still requires per-project glue code.

Teams commonly need to feed generated fixtures into one of:

- file-based bundle workflows
- envdir / `.env` flows
- Kubernetes Secret manifests
- SOPS pipelines
- Vault KV payload writers

The project must keep its test-fixture positioning: generate artifacts and stop.
It must not become a secret custody service or provider SDK wrapper.

## Decision

Introduce a reference-oriented export layer starting in `uselesskey-cli`, with a
path to split into `crates/uselesskey-export` if scope grows.

Core model:

- `KeyRef`
  - `File(path)`
  - `Env(var_name)`
  - `Vault(path)`
  - `AwsSecret(name)`
  - `GcpSecret(name)`
  - `K8sSecret(name, key)`
- `ExportBundleSpec`
  - bundle name
  - outputs
  - target format
  - optional env var names / secret names
- `ExportBundleResult`
  - written files
  - manifest path
  - references

Initial export targets:

- flat file bundle
- envdir
- `.env` fragment
- Kubernetes Secret YAML
- SOPS-ready YAML skeleton
- Vault KV JSON payload
- generic manifest with references

CLI surface (first wave):

- `uselesskey bundle`
- `uselesskey export k8s`
- `uselesskey export vault-kv-json`

Schema policy:

- Reuse existing fixture manifest/receipt structures where possible.
- Do not create a second independent schema for fixture identity and outputs.

Provider policy:

- Keep provider-specific APIs and clients out of the default code path.
- Prefer file/manifests consumed by existing secret-management toolchains.

## Consequences

### Positive

- Deterministic fixture generation can be handed to common toolchains without
  custom glue.
- The project keeps a strict “generate, write, reference, stop” boundary.
- Interop expands without coupling core crates to cloud/provider SDK churn.

### Negative

- Export format maintenance increases golden-test surface area.
- Some users may still request direct provider API integration that remains out
  of scope.
- CLI scope may grow enough to justify extraction into a dedicated export crate.

## Alternatives Considered

- **Direct Vault/KMS/Kubernetes API clients in core path**
  - **Rejected:** violates non-custody positioning and increases operational
    and security burden.
- **No export layer, rely entirely on user scripts**
  - **Rejected:** repeats glue code across users and weakens deterministic
    fixture handoff ergonomics.
- **Separate export schema from existing manifest/receipt model**
  - **Rejected:** introduces avoidable drift and duplicated identity semantics.
