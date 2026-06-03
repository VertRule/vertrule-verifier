#!/usr/bin/env bash
# Repo-local pre-push contract consumed by the shared governance pre-push
# hook (governance/hooks/pre-push, contract-resolution tier 1).
#
# Delegates to `just verify` so the push gate and the manual local gate are
# identical. The checks live in the justfile; this script is a thin dispatch
# and carries no guard logic of its own.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
exec just verify
