#!/bin/bash
# verify_digests.sh — verify SHA256SUMS over every file in the pack
# (except SHA256SUMS itself). Run from anywhere; must exit 0.
set -u
PACK="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PACK"
sha256sum -c SHA256SUMS
