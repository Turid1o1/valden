#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "Building unsigned macOS artifacts (DMG + ZIP)..."
REQUIRE_NOTARIZATION=false CSC_IDENTITY_AUTO_DISCOVERY=false npm run package:mac:unsigned

echo "Artifacts:"
ls -1 dist/*.dmg dist/*.zip 2>/dev/null || true

cat <<'EOF'

Unsigned build note:
- macOS Gatekeeper may block first launch.
- Open app via right click -> Open, or remove quarantine after install:
  xattr -dr com.apple.quarantine "/Applications/VALDEN.app"
EOF
