#!/bin/bash
# check-repo-state.sh — Enforce Repo State Standard v1
#
# Validates that the repository conforms to the canonical .vr/ layout.
# Run by ci-prepush (local CI) on every push.
#
# See: docs/dev/repo-state-standard-v1.md

set -euo pipefail

FAIL=0
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

fail() {
    echo "  FAIL: $1" >&2
    FAIL=1
}

pass() {
    echo "  ok: $1"
}

echo "Repo State Standard v1 — layout check"
echo ""

# ── 1. Canonical root exists ──
if [ -d .vr ]; then
    pass ".vr/ exists"
else
    fail ".vr/ missing"
fi

# ── 2. Legacy state root absent ──
if [ -d .vertrule ]; then
    fail ".vertrule/ still exists — run migration (docs/dev/repo-state-migration.md)"
else
    pass ".vertrule/ absent"
fi

# ── 3. Legacy governance root absent ──
if [ -d governance ] && [ -f governance/encoding_law.toml -o -d governance/policies ]; then
    fail "top-level governance/ contains definitions — move to .vr/governance/"
else
    pass "no legacy governance/ root"
fi

# ── 4. No mutable state at .vr/ root ──
for f in .vr/seal.json .vr/change.json; do
    if [ -f "$f" ]; then
        fail "$f at .vr/ root — move to .vr/state/"
    fi
done
pass "no mutable state at .vr/ root"

# ── 5. No receipt files in governance definitions ──
if find .vr/governance -name 'receipt.json' 2>/dev/null | grep -q .; then
    fail "receipt.json found under .vr/governance/ — receipts belong in .vr/receipts/governance/"
else
    pass "no receipts in .vr/governance/"
fi

# ── 6. No mixed receipt provenance ──
if [ -d .vr/receipts ]; then
    mixed=0
    for entry in .vr/receipts/*; do
        [ -e "$entry" ] || continue
        name=$(basename "$entry")
        case "$name" in
            governance|capabilities|runtime|local) ;;
            *) if [ -f "$entry" ]; then
                   fail "file .vr/receipts/$name has no provenance folder"
                   mixed=1
               elif [ -d "$entry" ]; then
                   fail "directory .vr/receipts/$name is not a recognized provenance class"
                   mixed=1
               fi ;;
        esac
    done
    if [ "$mixed" -eq 0 ]; then
        pass "receipt provenance is clean"
    fi
fi

# ── 7. .vr/README.md exists ──
if [ -f .vr/README.md ]; then
    pass ".vr/README.md exists"
else
    fail ".vr/README.md missing"
fi

# ── 8. No .vertrule path literals in production code ──
if rg --type rust --type sh '\.vertrule[^_]' \
     --glob '!docs/dev/repo-state-*' \
     --glob '!.vr/README.md' \
     --glob '!tooling/scripts/check-repo-state.sh' \
     -q 2>/dev/null; then
    fail "production code contains .vertrule path literals:"
    rg --type rust --type sh '\.vertrule[^_]' \
       --glob '!docs/dev/repo-state-*' \
       --glob '!.vr/README.md' \
       --glob '!tooling/scripts/check-repo-state.sh' \
       -n 2>/dev/null | head -10 >&2
else
    pass "no .vertrule literals in production code"
fi

# ── 9. No .vr/bricks path literals in production code ──
if rg --type rust --type sh '\.vr/bricks' \
     --glob '!tooling/scripts/check-repo-state.sh' \
     -q 2>/dev/null; then
    fail "production code contains .vr/bricks literals (use .vr/capabilities/):"
    rg --type rust --type sh '\.vr/bricks' \
       --glob '!tooling/scripts/check-repo-state.sh' \
       -n 2>/dev/null | head -10 >&2
else
    pass "no .vr/bricks literals in production code"
fi

echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "All repo-state checks passed"
else
    echo "Repo-state checks FAILED" >&2
    exit 1
fi
