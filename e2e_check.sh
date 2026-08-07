#!/usr/bin/env bash
# End-to-end smoke test against a throwaway local instance (port 8002 so it never
# clashes with a deployed service on 8001). Usage: bash e2e_check.sh
set -u
BASE=http://127.0.0.1:8002
DB=$(mktemp -u /tmp/secrets-e2e-XXXX.db)

SECRET_DB_PATH="$DB" uv run uvicorn app.main:app --host 127.0.0.1 --port 8002 >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
sleep 2

echo "--- secret flows (incl. passphrase gate) ---"
uv run python gate_e2e.py "$BASE" || exit 1

echo "--- pages ---"
for p in / /how-it-works /privacy /legal /robots.txt /nope /s/badslug /s/AAAAAAAAAAAAAAAAAAAAAA; do
  printf "%s -> %s\n" "$p" "$(curl -s -o /dev/null -w '%{http_code}' $BASE$p)"
done

echo "--- security headers on / ---"
curl -sI $BASE/ | grep -i -E "content-security|referrer|x-frame|x-content"
echo "--- cache-control on /s/ (404 but still no-store) ---"
curl -sI $BASE/s/AAAAAAAAAAAAAAAAAAAAAA | grep -i cache-control
rm -f "$DB" "$DB-wal" "$DB-shm"
