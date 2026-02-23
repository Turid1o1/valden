#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -z "${APPLE_ID:-}" && -z "${APPLE_API_KEY:-}" ]]; then
  echo "Set notarization credentials first."
  echo "Either:"
  echo "  APPLE_ID + APPLE_APP_SPECIFIC_PASSWORD + APPLE_TEAM_ID"
  echo "or:"
  echo "  APPLE_API_KEY + APPLE_API_KEY_ID + APPLE_API_ISSUER"
  exit 1
fi

echo "Building signed macOS release (DMG)..."
REQUIRE_NOTARIZATION=true npm run package:mac:signed

DMG_PATH="$(ls -1t dist/*.dmg | head -n 1)"
if [[ -z "${DMG_PATH}" ]]; then
  echo "No DMG found in dist/"
  exit 1
fi

echo "Validating app bundles..."
for APP_PATH in dist/mac/VALDEN.app dist/mac-arm64/VALDEN.app; do
  if [[ ! -d "${APP_PATH}" ]]; then
    echo "Missing app bundle: ${APP_PATH}"
    exit 1
  fi

  codesign --verify --deep --strict --verbose=2 "${APP_PATH}"
  xcrun stapler staple -v "${APP_PATH}"
  xcrun stapler validate -v "${APP_PATH}"
  spctl -a -vv --type exec "${APP_PATH}"
done

echo "Validating DMG notarization..."
xcrun stapler staple -v "$DMG_PATH"
xcrun stapler validate -v "$DMG_PATH"
spctl -a -vv --type open "$DMG_PATH"

echo "Release artifact ready: $DMG_PATH"
