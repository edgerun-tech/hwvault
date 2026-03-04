#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATES="$ROOT/docs/templates"
BASE="${HWVAULT_REPOS_BASE:-/home/ken/src/releases}"

repos=(hwvault hwvault-extension hwvault-android hwvault-ios)
for repo in "${repos[@]}"; do
  target="$BASE/$repo"
  [[ -d "$target" ]] || { echo "skip missing: $target"; continue; }
  cp "$TEMPLATES/SECURITY.md" "$target/SECURITY.md"
  cp "$TEMPLATES/CONTRIBUTING.md" "$target/CONTRIBUTING.md"
  cp "$TEMPLATES/CREDITS.md" "$target/CREDITS.md"
  echo "synced standards -> $repo"

done
