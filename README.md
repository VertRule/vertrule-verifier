# `vr-verifier`

Standalone public verifier for `VertRule` receipt envelopes.

Current execution plan: `WORKORDER-public-schema-and-verifier-alignment-2026-03-10.md`

This repository is the intended public verification surface for `VertRule`
receipts. It verifies receipt structure, digest integrity, chain linkage, and
signatures without importing the private runtime crates that produce receipts.

## Scope

`vr-verifier` is for **verification only**.

It does not:

- mint receipts
- sign receipts
- execute governed workloads
- require trust in `vertrule-runtime`

## Current Features

The crate already provides three verifier entry points:

- single-receipt verification
- chain verification
- signed-receipt verification

The verifier currently checks:

- envelope version compatibility
- schema/profile conformance for the public envelope
- JCS canonicalization assumptions
- `event_hash` recomputation with `BLAKE3`
- chain parent linkage through `parent_id`
- monotonic `logical_time`
- uniform `context_digest` across a chain
- stable `policy_digest` across a chain
- Ed25519 signature verification
- deterministic result emission as canonical JSON

## Public Contract

This verifier is built around the `UnifiedReceiptEnvelope`-style public receipt
shape:

- `envelope_version`
- `receipt_type`
- `context_digest`
- `schema_digest`
- `policy_digest`
- `logical_time`
- `event_hash`
- `parent_id`
- `boundary_origin`
- `payload`

That outer envelope is intended to be the stable public verification contract.
Domain-specific governed receipts live inside `payload`.

## Dependency Policy

The verifier is intentionally narrow.

Current production dependencies are:

- `vertrule-schemas`
- `vr-jcs`
- `base64`
- `blake3`
- `ed25519-dalek`
- `hex`
- `serde`
- `serde_json`
- `thiserror`

The architectural rule is simple:

`vr-verifier` may depend on public substrate crates, but it must not depend on
the private runtime execution stack.

## Repository Relationships

The intended split around this repo is:

- `vertrule-verifier`: verifier library and verifier CLI
- `vertrule-definitions`: canonical public types
- `receipts-profile`: schemas, fixtures, and keys documentation
- `policy-registry`: policy epochs and allowed vocabularies
- `vertrule-examples`: public example bundles
- `vertrule-runtime`: private producer and signer, not a verifier dependency

## Current Gaps Before Publication

This repo is close to publishable, but not fully there yet.

- the crate still uses local path dependencies
- the canonicalization crate still lives under `vertrule-runtime`
- the crate is still marked `publish = false`
- the license path still points into `vertrule-runtime`
- the broader repo set still exposes more than one public verifier story

## Intended End State

The clean publish target is:

- `vr-verifier` as the one public verification engine
- `vertrule-schemas`, `vr-jcs`, and `vr-receipt` as public substrate crates
- `receipts-profile` as the schema/vector repo
- `vertrule-cli` as an optional thin UX wrapper over this library

## CLI

The repository currently ships the `vr-verify` binary.

```text
vr-verify receipt <file.json>
vr-verify chain   <chain.json>
vr-verify signed  <file.json> <sig.json>
```

The CLI emits canonical JSON verification results to stdout and a result digest
to stderr.

## Trust Model

The purpose of this repository is to let an external reviewer verify a receipt
bundle without needing access to the private execution runtime. That is the core
publication goal for the external `VertRule` verifier.
