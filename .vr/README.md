# .vr/ — Repository State Root

Canonical repo-local state directory for the `vertrule-verifier` repository.

Governed by Repo State Standard v1.

## Canonical Layout

```
.vr/
  README.md
  governance/
    policies/
    authorities/
    manifest.toml
    known-nondeterminism.toml
  receipts/
    governance/
  state/
  public/
  tmp/
```

## Invariants

1. Exactly one canonical state root: `.vr/`
2. Governance definitions and receipts are strictly separated.
3. No mutable operational files at `.vr/` root level.
4. All path resolution uses `.vr/` prefix, never bare `governance/`.
