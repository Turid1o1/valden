#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="$ROOT_DIR/infra/certs"
COTURN_TEMPLATE="$ROOT_DIR/infra/coturn/turnserver.conf.template"
COTURN_OUTPUT="$ROOT_DIR/infra/coturn/turnserver.conf"

mkdir -p "$CERT_DIR"

if [[ ! -f "$CERT_DIR/fullchain.pem" || ! -f "$CERT_DIR/privkey.pem" ]]; then
  openssl req -x509 -nodes -newkey rsa:4096 \
    -keyout "$CERT_DIR/privkey.pem" \
    -out "$CERT_DIR/fullchain.pem" \
    -days 365 \
    -subj "/CN=VALDEN" >/dev/null 2>&1
fi

: "${TURN_SECRET:?TURN_SECRET is required}"
: "${TURN_REALM:?TURN_REALM is required}"
: "${PUBLIC_IP:?PUBLIC_IP is required}"

cp "$COTURN_TEMPLATE" "$COTURN_OUTPUT"
sed -i.bak \
  -e "s/__TURN_SECRET__/${TURN_SECRET//\//\\\/}/g" \
  -e "s/__TURN_REALM__/${TURN_REALM//\//\\\/}/g" \
  -e "s/__PUBLIC_IP__/${PUBLIC_IP//\//\\\/}/g" \
  "$COTURN_OUTPUT"
rm -f "$COTURN_OUTPUT.bak"

echo "Runtime artifacts prepared."
