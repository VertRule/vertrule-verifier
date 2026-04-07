# Bundle Verification Roadmap

## Goal

Make bundle verification a first-class capability of `vertrule-verifier` so a
reviewer can validate the full artifact from one verifier surface, without
depending on `vr-browser-runtime`.

Today, bundle verification is split across two surfaces:

- `vertrule-verifier` validates the canonical receipt envelope
- `vr-browser-runtime` recomputes sidecar digests for `layer_trace` and
  `selection_policy`

That works, but it leaves an avoidable precision gap. The same public verifier
should be able to validate the entire bundle.

---

## Recommended Direction

### 1. Add bundle verification to vertrule-verifier

Introduce:

- `verify_bundle_json(...)` in `vertrule-verifier/src/wasm.rs`
- `vr-verify bundle ...` in `vertrule-verifier/src/bin/vr_verify.rs`

This path should:

1. verify `envelope_canonical` using the existing receipt verifier
2. recompute `BLAKE3(JCS(layer_trace))`
3. recompute `BLAKE3(JCS(selection_policy))`
4. compare those digests against the values bound in the receipt payload
5. return a single structured verification result

The result should make all three checks explicit:

- envelope verification
- layer-trace digest verification
- selection-policy digest verification

### 2. Define the bundle as a public schema

If the verifier documentation says an external reviewer can verify a receipt
bundle using only `vertrule-verifier`, that needs to be literally true.

The bundle shape should be moved into a public schema, ideally in:

- `vertrule-schemas`, or
- a very small verifier-side public module

That makes the audited artifact format stable, documented, and shared between
producer and verifier.

### 3. Keep two validation gates

Do not replace the current producer-path gate. Keep both.

**Producer-path gate**
Keep `vertrule-website/scripts/verify-fixtures.mjs`.

Purpose:

- proves the shipped website + runtime path is coherent
- catches drift in exported browser artifacts

**Verifier-only gate**
Add a second gate that verifies the same bundle using only `vertrule-verifier`.

Purpose:

- proves the verifier can validate the bundle independently
- removes the criticism that "the producer stack revalidated itself"

This dual-gate model is stronger than either gate alone.

### 4. Align the live download format with the audited bundle format

The website should export the same `vr-execution-bundle/v1` shape that the
fixtures and verifier gate expect.

Recommended change:

- store `envelope_canonical` as a canonical string, not a parsed object

This avoids a common footgun:

- pretty-printed nested envelope objects are not verifier-ready as raw input
- canonical string form preserves exact bytes and makes downstream verification
  simpler

`vertrule-website/src/components/execute/ExecutionSurface.tsx` is the place to
tighten this.

### 5. Make the public verify page accept bundles directly

The public verify flow should not require the user to manually extract the
receipt first.

Instead, the verify page should accept:

- raw canonical receipt envelope, or
- full execution bundle

For bundles, it should display:

- envelope verification result
- layer-trace digest check
- selection-policy digest check

That removes the remaining user-facing precision gap and makes the audit
workflow match the artifact workflow.

---

## Target Standard

The clean standard is:

> **one public verifier artifact can validate the whole bundle**

That means:

- one schema
- one verifier path
- one structured verification result
- one reviewer workflow

Until that exists, the next-best state is:

- the current producer-path bundle check, plus
- an independent verifier-side rehash gate

---

## Why this matters

This closes two problems at once:

1. **Audit precision** — A reviewer no longer has to trust a split verification
   story.
2. **Workflow clarity** — The exported bundle, the public verify page, the
   fixture gate, and the verifier crate all speak the same artifact format.

That is the point where bundle verification becomes a real public surface, not
just an internal convention.
