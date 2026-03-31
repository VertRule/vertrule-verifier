#!/usr/bin/env bash
# Generate a shields.io-style SVG badge for local CI status.
# Usage: gen-badge.sh passing|failing [output-path]
set -euo pipefail

status="${1:-unknown}"
output="${2:-artifacts/local-ci-badge.svg}"

case "$status" in
    passing)
        color="#4c1"
        label="passing"
        ;;
    failing)
        color="#e05d44"
        label="failing"
        ;;
    *)
        color="#9f9f9f"
        label="unknown"
        ;;
esac

cat > "$output" <<SVGEOF
<svg xmlns="http://www.w3.org/2000/svg" width="108" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <mask id="a"><rect width="108" height="20" rx="3" fill="#fff"/></mask>
  <g mask="url(#a)">
    <path fill="#555" d="M0 0h62v20H0z"/>
    <path fill="${color}" d="M62 0h46v20H62z"/>
    <path fill="url(#b)" d="M0 0h108v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="31" y="15" fill="#010101" fill-opacity=".3">local CI</text>
    <text x="31" y="14">local CI</text>
    <text x="84" y="15" fill="#010101" fill-opacity=".3">${label}</text>
    <text x="84" y="14">${label}</text>
  </g>
</svg>
SVGEOF
