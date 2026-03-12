# Work Order: Public Schema and Verifier Alignment

Date: 2026-03-10

## Executive summary

Present bottom line: the public constitutional story is not yet closed, but the canonical centers are now clear.

- `vertrule-schemas` is the public constitutional schema surface.
- `vertrule-verifier` is the independent public verification engine.
- `vertrule-runtime` is a receipt producer and must not enter the verifier trust base.
- `receipts-profile` is not part of the canonical public contract; it may remain temporarily as legacy migration collateral only.
- The public envelope/header is constitutional schema and belongs in `vertrule-schemas`.
- No profile or domain receipt family is elevated into the constitutional core yet.

Current repo reality contradicts older verifier planning in several places and this work order takes present code as authoritative:

- The public schema package is now `vertrule-schemas`, not `vr-definitions`.
- `vertrule-schemas` currently owns public nouns and must absorb the constitutional envelope/header.
- `vertrule-verifier` currently still owns a standalone verifier-side `ReceiptEnvelope`, which is migration debt.
- `vr-jcs` remains sourced from the runtime tree by path, which is acceptable for local development but not for public release.

## Workstream glossary

| ID | Meaning | Closure condition |
|---|---|---|
| `WS-ARCH` | Canonical public architecture | One written architecture statement with no competing public-contract language in active verifier/schema docs |
| `WS-CONTRACT` | Public receipt contract closure | The constitutional envelope/header lives in `vertrule-schemas` and all active public docs and code agree |
| `WS-SCHEMA` | Constitutional schema surface closure | `vertrule-schemas` scope is explicit and enforced by code/docs |
| `WS-VERIFY` | Independent verifier closure | `vertrule-verifier` verifies real bundles without runtime imports in release dependencies |
| `WS-DEPS` | Dependency-boundary closure | No publish-bound verifier dependency points into private runtime trees |
| `WS-COLLATERAL` | Vector/profile collateral closure | `receipts-profile` is non-canonical, any still-needed collateral is migrated or regenerated, and the repo is archived once nothing live depends on it |
| `WS-CLI` | Thin-wrapper closure | Any CLI surface delegates verification semantics to `vertrule-verifier` |
| `WS-PACKAGE` | Publication packaging closure | Public crates pass `cargo package` and `cargo publish --dry-run` from their own public surfaces |
| `WS-TRUST` | Third-party trust closure | A third party can verify a real receipt bundle with public artifacts only |

## Canonical public architecture

| Layer | Canonical owner | Scope | Non-scope |
|---|---|---|---|
| Constitutional schema surface | `vertrule-schemas` | Public envelope/header structs, digest/version bindings, receipt discriminators, identity-binding fields, structural identity constraints | Canonicalization execution, chain verification, result types, parsing helpers, convenience constructors, runtime behavior |
| Verification engine | `vertrule-verifier` | Envelope parsing, schema-profile enforcement, digest checks, chain checks, signature checks, deterministic result emission | Receipt minting, signing, workload execution |
| Producer boundary | `vertrule-runtime` | Receipt production, signing, governed execution, internal payload generation | Verifier trust anchor, public verification dependency |
| Profile/domain extensions | `receipts-profile` and domain repos | Fixtures, vectors, migration material, profile-specific examples | Constitutional core ownership and long-term repo-of-record status unless explicit elevation criteria are met |

Required architectural assertion: there is exactly one canonical public verification story. Today that story is `vertrule-schemas` plus `vertrule-verifier`, with `vr-jcs` as an exposed canonicalization dependency that still requires publication closure.

Elevation rule for profile/domain families:

- independent verifiers must need to parse the family directly
- the family must be cross-implementation rather than tied to one producer/runtime line
- the family must be stable enough to freeze publicly
- the family must change the public trust story rather than encode producer-local detail

Present decision: none of the current profile/domain receipt families meet that bar.

## Present-state contradictions to older verifier planning

| Prior assumption | Present code reality | Required treatment |
|---|---|---|
| `vr-definitions` is the canonical public schema crate | The schema package name is `vertrule-schemas`, but the repository is still named `vertrule-definitions` | Prefer package reality now; require repository rename before publication |
| `receipts-profile` can remain the public schema/vector source of truth | `receipts-profile` still carries legacy reference material and private-repo status | Reject that role; freeze it as migration collateral only, migrate anything live, then archive it |
| `vr-receipt` is already the public constitutional envelope home | The active verifier still owns `ReceiptEnvelope`, but the constitutional decision is now that the public envelope/header belongs in `vertrule-schemas` | Treat verifier-owned envelope code as migration debt |
| Runtime extraction can remain fuzzy during publication | `vertrule-verifier` still path-depends on `vr-jcs` under `vertrule-runtime` | Treat as a dependency blocker for public release |

## Repo ownership

| Repo | Owns | Must not own | Current state |
|---|---|---|---|
| `vertrule-schemas` | Constitutional nouns, public envelope/header structs, digest/version bindings, receipt discriminators, identity constraints | Verification behavior, runtime execution, signing, competing profile contracts | Partial: nouns are present; constitutional envelope/header migration is still required |
| `vertrule-verifier` | Public receipt verification behavior, schema-profile enforcement, deterministic result output, verifier CLI | Runtime execution, receipt production, alternate contract definitions | Partial: verifier is functional; publication and dependency closure are open |
| `vertrule-runtime` | Receipt production, signing, internal envelope emitters, canonicalization implementation source today | Required verifier trust dependency | Contradiction present: `vr-jcs` still comes from the runtime tree |
| `receipts-profile` | Temporary legacy collateral during migration only | Constitutional source of truth, independent verifier logic, competing top-level contract, permanent repo-of-record status | Transitional: demote now, migrate anything live, archive when empty of live dependencies |
| `vertrule-cli` | Thin UX wrapper if retained | Independent verification semantics | Open: older planning still treats CLI and verifier as separate stories |

## Competing public contract

The following patterns are rejected:

- `receipts-profile` `receipt-v0.2` acting as a peer public contract beside the envelope/header contract.
- `vertrule-runtime`-owned crates acting as mandatory verifier trust anchors.
- CLI-specific verification logic diverging from `vertrule-verifier`.
- Profile-specific top-level receipt families presenting themselves as public constitutional alternatives.

Required closure:

1. Keep one canonical public envelope/header contract in `vertrule-schemas`.
2. Keep `vertrule-verifier` responsible for verification behavior only.
3. Demote all other surfaces to collateral, migration, or producer-only roles.

`receipts-profile` policy:

- it is not canonical
- it may temporarily remain as legacy collateral during migration
- any still-needed vectors, fixtures, or reference artifacts must move into their real homes or be regenerated from them
- once nothing live depends on it, it should be archived and removed from the active repository set

## Dependency boundary

`vertrule-verifier` may depend on:

- `vertrule-schemas`
- `vr-jcs`
- narrow cryptography and serialization crates
- public test/vector assets for verification fixtures

`vertrule-verifier` must not depend on:

- `vertrule-runtime`
- `vertrule-core`
- `vertrule-app`
- `vertrule-adapters`
- `vertrule-cli`
- runtime-only helper crates in release dependencies
- profile repos as code dependencies

Current state:

- Release dependencies are narrow.
- `vr-jcs` still enters by runtime path dependency.
- dev-dependencies still include `vr-kernel-testutils` from the runtime tree.
- Boundary tests exist and should remain exact-name checks rather than substring checks.

## Packaging and publication

Before public release, all of the following must be true:

- `vertrule-schemas` and `vertrule-verifier` have self-contained licenses and publish metadata.
- No release dependency in `vertrule-verifier` points into a private runtime repo path.
- The public contract is documented once and does not conflict with active READMEs or work orders.
- Trust artifacts exist as public fixtures: schema/profile description, valid/invalid vectors, command examples, and release notes.
- `cargo package` and `cargo publish --dry-run` pass from the public repos themselves.
- The `vertrule-schemas` repository name converges with the public package name before publication.

## Milestones

### Phase 0: Canonical story lock

Closure test:

- This work order exists.
- Active public docs in `vertrule-schemas` and `vertrule-verifier` no longer describe a second constitutional source of truth.
- `receipts-profile` is explicitly described as non-canonical migration collateral with an archival end state.

### Phase 1: Contract closure

Closure test:

- The constitutional envelope/header types exist in `vertrule-schemas`.
- `vertrule-verifier` no longer owns the canonical public envelope/header structs.
- All active verifier-facing docs use the same field set and identity triple.

### Phase 2: Dependency closure

Closure test:

- `vertrule-verifier` release dependencies do not traverse `../vertrule-runtime/...`.
- `vr-jcs` is public in its own right or relocated into a public verifier workspace.
- Any retained `vr-receipt` dependency is public and verifier-facing, not runtime-trust-bearing.

### Phase 3: Publication closure

Closure test:

- `cargo package` and `cargo publish --dry-run` pass for `vertrule-schemas` and `vertrule-verifier`.
- README, work order, and trust-pack docs agree.
- A third-party verifier can validate a real receipt bundle with public artifacts only.

## Closure matrix

| Repo | Workstream / Risk | Required artifact | Required command(s) | Blocking? | Owner | Status |
|---|---|---|---|---|---|---|
| `vertrule-verifier` | `WS-ARCH` | `WORKORDER-public-schema-and-verifier-alignment-2026-03-10.md` | `rg -n "receipts-profile|vr-definitions|public verifier|source-of-truth" README.md WORKORDER-public-schema-and-verifier-alignment-2026-03-10.md` | Yes | `vertrule-verifier` | Done |
| `vertrule-schemas` | `WS-SCHEMA` | `operator_private/public-surface-role.md` | `rg -n "Freeze nouns|does not belong|constitutional schema surface" operator_private/public-surface-role.md` | No | `vertrule-schemas` | Done |
| `vertrule-schemas` | `WS-PACKAGE` | Repository rename plan or completed repository rename to `vertrule-schemas` | `test -d ../vertrule-schemas` | Yes | `vertrule-schemas` | Open |
| `vertrule-schemas` | `WS-CONTRACT` | Constitutional envelope/header types in `src/` plus migration note closing verifier-owned contract drift | `rg -n "Envelope|Header|ReceiptType|SchemaVersion" src` | Yes | `vertrule-schemas` | Open |
| `vertrule-schemas` and `vertrule-verifier` | `WS-ARCH` | Explicit note that no profile/domain family is constitutional core yet | `rg -n "profile/domain|none yet|constitutional core" WORKORDER-public-schema-and-verifier-alignment-2026-03-10.md ../*/operator_private/public-surface-role.md` | No | `architecture` | Done |
| `vertrule-verifier` | `WS-VERIFY` | Stable verifier contract doc set plus vectors already under `test-vectors/` | `cargo check && cargo test && cargo clippy --all-targets --all-features -- -D warnings` | No | `vertrule-verifier` | Partial |
| `vertrule-verifier` | `WS-DEPS` | Publish-clean dependency graph | `cargo tree -e normal` | Yes | `vertrule-verifier` | Open |
| `vertrule-runtime` | `WS-DEPS` | Public disposition for `vr-jcs` and any verifier-facing substrate crate | `cargo tree -p vr-receipt` and `cargo tree -p vr-rbh` | Yes | `vertrule-runtime` | Open |
| `receipts-profile` | `WS-COLLATERAL` | Demotion note, migration inventory, and archive trigger once live dependencies reach zero | `rg -n "receipt-v0.2|RS256|source-of-truth|public contract" README.md reference && rg -n "receipts-profile" ../vertrule-verifier ../vertrule-schemas ../vertrule-runtime ../vertrule-cli` | Yes | `receipts-profile` | Open |
| `vertrule-cli` | `WS-CLI` | Thin-wrapper decision or removal plan | `rg -n "verify|receipt|chain" ../vertrule-cli` | No | `vertrule-cli` | Open |
| `vertrule-schemas` and `vertrule-verifier` | `WS-PACKAGE` | Public release checklist and publish metadata | `cargo package --allow-dirty` and `cargo publish --dry-run --allow-dirty` | Yes | `release` | Open |
| `vertrule-verifier` | `WS-TRUST` | Third-party verifier release definition and trust pack | `cargo run --bin vr-verify -- receipt <bundle>` | Yes | `vertrule-verifier` | Open |

## Open constitutional decisions

- After the constitutional envelope/header moves into `vertrule-schemas`, is any thin verifier-facing substrate crate still necessary, or should the public surface reduce to `vertrule-schemas` plus verifier behavior in `vertrule-verifier` with no separate contract crate?

## Publish blockers

### Contract blockers

- The envelope/header constitutional ownership decision is settled, but the code migration into `vertrule-schemas` is not complete.
- Active docs still reflect more than one historical verifier story.
- `receipts-profile` has not yet been fully demoted, drained of live collateral, and placed on an archive path.
- No profile/domain family is blocked on elevation because none are elevated yet.
- The public substrate boundary is not yet minimized: it is still open whether any thin verifier-facing contract crate remains necessary after the envelope/header migration.

### Dependency blockers

- `vertrule-verifier` still depends on `vr-jcs` via a runtime path.
- Verifier dev tooling still depends on runtime-owned test utilities.
- The runtime tree still contains duplicate verifier-adjacent surfaces, which complicates trust-boundary explanation.

### Packaging blockers

- `publish = false` remains on public crates.
- License paths and path dependencies still assume local multi-repo checkout.
- The schema repository is still named `vertrule-definitions`; publication requires repository rename convergence to `vertrule-schemas`.

### Trust blockers

- There is not yet one public release bundle that states the canonical contract, vectors, commands, and trust boundary in one place.
- A third-party user cannot yet install the full public verifier stack without reaching into private-runtime paths.

## Final release definition

A third-party verifier can:

1. Obtain `vertrule-schemas`, `vertrule-verifier`, and all required public dependencies without access to `vertrule-runtime`.
2. Read one canonical public contract for the receipt envelope/header and identity triple.
3. Run the verifier on a real receipt bundle and reproduce the same verification result and result digest on an independent machine.
4. Use public vectors and schema/profile artifacts to validate both positive and negative cases.
5. Do all of the above without consulting runtime internals, private policy engines, or private operator infrastructure.
