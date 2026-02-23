#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_IMAGE="${1:-/Users/mvd/Documents/Изображения/ChatGPT Image 21 февр. 2026 г., 12_51_59.png}"

if [[ ! -f "$SOURCE_IMAGE" ]]; then
  echo "Source image not found: $SOURCE_IMAGE" >&2
  exit 1
fi

WEB_DIR="$ROOT_DIR/web/site"
WEB_ASSETS_DIR="$WEB_DIR/assets"
BRANDING_DIR="$ROOT_DIR/assets/branding"
MAC_DIR="$BRANDING_DIR/mac"
ICONSET_DIR="$MAC_DIR/valden.iconset"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$WEB_ASSETS_DIR" "$BRANDING_DIR" "$MAC_DIR" "$ICONSET_DIR"

cp "$SOURCE_IMAGE" "$BRANDING_DIR/logo-source.png"
cp "$SOURCE_IMAGE" "$WEB_ASSETS_DIR/logo-main.png"

WIDTH="$(sips -g pixelWidth "$SOURCE_IMAGE" | awk '/pixelWidth/ {print $2}')"
HEIGHT="$(sips -g pixelHeight "$SOURCE_IMAGE" | awk '/pixelHeight/ {print $2}')"
if [[ -z "$WIDTH" || -z "$HEIGHT" ]]; then
  echo "Unable to read image dimensions" >&2
  exit 1
fi

if (( WIDTH < HEIGHT )); then
  CROP_SIZE="$WIDTH"
else
  CROP_SIZE="$HEIGHT"
fi

SQUARE_SRC="$TMP_DIR/logo-square.png"
sips -c "$CROP_SIZE" "$CROP_SIZE" "$SOURCE_IMAGE" --out "$SQUARE_SRC" >/dev/null

LOGO_1024="$WEB_ASSETS_DIR/logo-square-1024.png"
sips -z 1024 1024 "$SQUARE_SRC" --out "$LOGO_1024" >/dev/null

sips -z 180 180 "$LOGO_1024" --out "$WEB_DIR/apple-touch-icon.png" >/dev/null
sips -z 192 192 "$LOGO_1024" --out "$WEB_DIR/icon-192.png" >/dev/null
sips -z 512 512 "$LOGO_1024" --out "$WEB_DIR/icon-512.png" >/dev/null
sips -z 32 32 "$LOGO_1024" --out "$WEB_DIR/favicon-32.png" >/dev/null
sips -z 16 16 "$LOGO_1024" --out "$WEB_DIR/favicon-16.png" >/dev/null
sips -s format ico "$WEB_DIR/favicon-32.png" --out "$WEB_DIR/favicon.ico" >/dev/null

cat > "$WEB_DIR/manifest.webmanifest" <<'JSON'
{
  "name": "VALDEN Remote Access",
  "short_name": "VALDEN",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#05070c",
  "theme_color": "#0e7490",
  "icons": [
    {
      "src": "/icon-192.png",
      "sizes": "192x192",
      "type": "image/png"
    },
    {
      "src": "/icon-512.png",
      "sizes": "512x512",
      "type": "image/png"
    }
  ]
}
JSON

cp "$LOGO_1024" "$MAC_DIR/icon_1024.png"

# macOS iconset sizes
sips -z 16 16 "$LOGO_1024" --out "$ICONSET_DIR/icon_16x16.png" >/dev/null
sips -z 32 32 "$LOGO_1024" --out "$ICONSET_DIR/icon_16x16@2x.png" >/dev/null
sips -z 32 32 "$LOGO_1024" --out "$ICONSET_DIR/icon_32x32.png" >/dev/null
sips -z 64 64 "$LOGO_1024" --out "$ICONSET_DIR/icon_32x32@2x.png" >/dev/null
sips -z 128 128 "$LOGO_1024" --out "$ICONSET_DIR/icon_128x128.png" >/dev/null
sips -z 256 256 "$LOGO_1024" --out "$ICONSET_DIR/icon_128x128@2x.png" >/dev/null
sips -z 256 256 "$LOGO_1024" --out "$ICONSET_DIR/icon_256x256.png" >/dev/null
sips -z 512 512 "$LOGO_1024" --out "$ICONSET_DIR/icon_256x256@2x.png" >/dev/null
sips -z 512 512 "$LOGO_1024" --out "$ICONSET_DIR/icon_512x512.png" >/dev/null
sips -z 1024 1024 "$LOGO_1024" --out "$ICONSET_DIR/icon_512x512@2x.png" >/dev/null

iconutil -c icns "$ICONSET_DIR" -o "$MAC_DIR/valden.icns"
cp "$MAC_DIR/valden.icns" "$ROOT_DIR/web/site/assets/valden.icns"

echo "Brand assets generated from: $SOURCE_IMAGE"
echo "Website logo: $WEB_ASSETS_DIR/logo-main.png"
echo "Website favicon: $WEB_DIR/favicon.ico"
echo "macOS icon: $MAC_DIR/valden.icns"
