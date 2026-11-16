#!/usr/bin/env bash
# Dump the app's SwiftData store from the simulator so the persisted contact
# can be inspected outside the UI.
set -uo pipefail

UDID="${1:?usage: dump_store.sh <simulator-udid>}"
ADDR="GqTokf3PYKjTzkTJrahA8AY47eBVe9fyrun9CfLg6JEp"

echo "=== app container ==="
CONTAINER=$(xcrun simctl get_app_container "$UDID" com.privamesh data 2>/dev/null)
if [ -z "${CONTAINER:-}" ]; then
  echo "app container not found (app may not be installed on $UDID)"
  exit 0
fi
echo "$CONTAINER"

echo
echo "=== store files ==="
find "$CONTAINER" -type f \( -name '*.store' -o -name '*.sqlite' -o -name '*.sqlite3' \) 2>/dev/null | while read -r f; do
  echo "$f"
done

DB=$(find "$CONTAINER" -type f -name '*.store' 2>/dev/null | head -1)
if [ -z "${DB:-}" ]; then
  echo "no .store file present"
  exit 0
fi

echo
echo "=== tables ==="
sqlite3 "$DB" ".tables" 2>&1

echo
echo "=== ZCONTACT (row per stored contact) ==="
sqlite3 -header -line "$DB" "select * from ZCONTACT;" 2>&1 | head -200

echo
echo "=== does the store contain the impersonated address? ==="
sqlite3 "$DB" ".dump" 2>/dev/null | grep -c "$ADDR" || true
echo "=== does it contain the attacker bundle fingerprint (payload key material)? ==="
sqlite3 "$DB" ".dump" 2>/dev/null | grep -o "walletSignature" | wc -l

echo
echo "=== full dump (first 400 lines) ==="
sqlite3 "$DB" ".dump" 2>&1 | head -400
