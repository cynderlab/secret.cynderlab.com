#!/usr/bin/env bash
# End-to-end smoke test against a local uvicorn. Usage: bash e2e_check.sh
set -u
BASE=http://127.0.0.1:8001
DB=$(mktemp -u /tmp/secrets-e2e-XXXX.db)

SECRET_DB_PATH="$DB" uv run uvicorn app.main:app --host 127.0.0.1 --port 8001 >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
sleep 2

echo "--- create ---"
RESP=$(curl -s $BASE/api/secrets -H 'content-type: application/json' \
  -d '{"secret": "e2e: tk-99", "expires_at": "2026-08-20"}')
echo "$RESP"
SLUG=$(echo "$RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['slug'])")
KEY=$(echo "$RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['link'].split('#')[1])")

echo "--- reveal ---"
curl -s $BASE/api/secrets/$SLUG/reveal -H 'content-type: application/json' -d "{\"key\": \"$KEY\"}"
echo
echo "--- second reveal (expect 404) ---"
curl -s -o /dev/null -w "%{http_code}\n" $BASE/api/secrets/$SLUG/reveal \
  -H 'content-type: application/json' -d "{\"key\": \"$KEY\"}"

echo "--- pages ---"
for p in / /privacy /legal /llms.txt /robots.txt /nope /s/badslug /s/AAAAAAAAAAAAAAAAAAAAAA; do
  printf "%s -> %s\n" "$p" "$(curl -s -o /dev/null -w '%{http_code}' $BASE$p)"
done

echo "--- security headers on / ---"
curl -sI $BASE/ | grep -i -E "content-security|referrer|x-frame|x-content"
echo "--- cache-control on /s/ ---"
curl -sI $BASE/s/AAAAAAAAAAAAAAAAAAAAAA | grep -i cache-control
rm -f "$DB" "$DB-wal" "$DB-shm"
