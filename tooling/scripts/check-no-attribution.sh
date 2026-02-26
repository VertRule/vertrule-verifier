#!/usr/bin/env bash
# Shared attribution pattern checker for VertRule
# Used by: .github/workflows/no-attribution.yml, .git/hooks/commit-msg
#
# Usage:
#   check-no-attribution.sh --pr-body <file>    Check PR body text
#   check-no-attribution.sh --commit-msg <file>  Check a commit message
#   check-no-attribution.sh --commits <range>     Check commit messages in range

set -euo pipefail

# Blocked patterns (case-insensitive grep -iE)
PATTERNS=(
  'Co-Authored-By'
  'Generated with.*Claude'
  'noreply@anthropic\.com'
  'claude\.com/claude-code'
)

# Build combined pattern for grep
COMBINED=""
for p in "${PATTERNS[@]}"; do
  if [ -z "$COMBINED" ]; then
    COMBINED="$p"
  else
    COMBINED="${COMBINED}|${p}"
  fi
done

# Color codes
RED='\033[0;31m'
NC='\033[0m'

check_text() {
  local label="$1"
  local text="$2"

  if printf '%s\n' "$text" | grep -iEq "$COMBINED"; then
    printf '%b\n' "${RED}Attribution found in ${label}:${NC}"
    printf '%s\n' "$text" | grep -iEn "$COMBINED" | while IFS= read -r line; do
      printf '%b\n' "  ${RED}${line}${NC}"
    done
    return 1
  fi
  return 0
}

MODE="${1:-}"
TARGET="${2:-}"

case "$MODE" in
  --pr-body)
    if [ -z "$TARGET" ] || [ ! -f "$TARGET" ]; then
      echo "Usage: $0 --pr-body <file>"
      exit 2
    fi
    BODY=$(cat "$TARGET")
    check_text "PR body" "$BODY"
    ;;

  --commit-msg)
    if [ -z "$TARGET" ] || [ ! -f "$TARGET" ]; then
      echo "Usage: $0 --commit-msg <file>"
      exit 2
    fi
    MSG=$(cat "$TARGET")
    check_text "commit message" "$MSG"
    ;;

  --commits)
    if [ -z "$TARGET" ]; then
      echo "Usage: $0 --commits <range>"
      exit 2
    fi
    VIOLATIONS=0
    while IFS= read -r sha; do
      MSG=$(git log --format='%B' -n 1 "$sha")
      if ! check_text "commit ${sha:0:8}" "$MSG"; then
        VIOLATIONS=$((VIOLATIONS + 1))
      fi
    done < <(git log --format='%H' "$TARGET")

    if [ "$VIOLATIONS" -gt 0 ]; then
      exit 1
    fi
    ;;

  *)
    echo "Usage: $0 {--pr-body <file>|--commit-msg <file>|--commits <range>}"
    exit 2
    ;;
esac
