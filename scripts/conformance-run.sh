#!/usr/bin/env bash
# Start the TypeScript SUT in conformance mode and run the pinned shared
# conformance runner against it, writing a JSON report. The runner's own
# verdict is intentionally all-or-nothing and ignored at this layer: this
# repository claims the `core` profile with an explicit `deviations` list, and
# CI gates the report with scripts/check-conformance-report.mjs (an undeclared
# stable failure is a regression; a deviation that stops failing must go).
#
# usage: scripts/conformance-run.sh [REPORT] [CONTRACT_DIR] [SEED]
#   default report: build/conformance-report.json
#   default contract dir: .contract
#   default seed: $CONTRACT_DIR/examples/seed.yaml
#
# The seed pins issuer==http://localhost:8080, which OAUTH2_ISSUER must match.
# A throwaway ES256 key is generated; it is test-only and discarded at exit.
set -euo pipefail

cd "$(dirname "$0")/.."
report_arg="${1:-build/conformance-report.json}"
mkdir -p "$(dirname "$report_arg")"
report="$(cd "$(dirname "$report_arg")" && pwd)/$(basename "$report_arg")"
contract_dir="$(cd "${2:-.contract}" && pwd)"
seed="${3:-$contract_dir/examples/seed.yaml}"
[ -f "$seed" ] || { echo "seed not found: $seed" >&2; exit 1; }

pin="$(sed -n 's/^contract:[[:space:]]*//p' conformance.yaml)"
printf '%s' "$pin" | grep -Eq '^[0-9a-f]{40}$' || { echo "conformance.yaml needs a full 40-hex commit pin" >&2; exit 1; }
actual="$(git -C "$contract_dir" rev-parse HEAD)"
[ "$actual" = "$pin" ] || { echo "contract at $actual, pinned $pin; run scripts/setup-conformance.sh" >&2; exit 1; }

work="$(mktemp -d)"
srv_pid=""
cleanup() { [ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null || true; find "$work" -mindepth 1 -delete 2>/dev/null || true; rmdir "$work" 2>/dev/null || true; }
trap cleanup EXIT

openssl ecparam -name prime256v1 -genkey -noout -out "$work/key.pem"
openssl pkcs8 -topk8 -nocrypt -in "$work/key.pem" -out "$work/key.p8"
key_pem="$(cat "$work/key.p8")"

# Allocate a free loopback port (parsePort forbids 0, so pick a real ephemeral one).
free_port="$(node scripts/free-port.mjs)"

: > "$work/port"
OAUTH2_ENV=test \
OAUTH2_ISSUER=http://localhost:8080 \
OAUTH2_SESSION_SECRET=0123456789abcdef0123456789abcdef \
OAUTH2_SIGNING_KEY_PEM="$key_pem" \
OAUTH2_SIGNING_KEY_ID=k1 \
OAUTH2_HOST=127.0.0.1 \
OAUTH2_PORT="$free_port" \
OAUTH2_DATABASE_PATH=:memory: \
OAUTH2_CONFORMANCE_MODE=1 \
OAUTH2_CONFORMANCE_SEED="$seed" \
pnpm start >"$work/server.log" 2>&1 &
srv_pid=$!

# Wait for readiness. The server prints "listening on http://127.0.0.1:PORT".
port=""
for _ in $(seq 1 100); do
  if grep -q 'listening on ' "$work/server.log"; then
    port="$(sed -n 's/.*listening on http:\/\/127\.0\.0\.1://p' "$work/server.log" | tail -1 | tr -d '/')"
    [ -n "$port" ] && break
  fi
  if ! kill -0 "$srv_pid" 2>/dev/null; then
    echo "SUT exited before listening:" >&2; cat "$work/server.log" >&2; exit 1
  fi
  sleep 0.1
done
[ -n "$port" ] || { echo "SUT never reported listening" >&2; cat "$work/server.log" >&2; exit 1; }
base_url="http://127.0.0.1:$port"

# Runner's exit code is deliberately ignored; the gate reads the report.
set +e
pnpm --dir "$contract_dir/runner" exec tsx src/cli.ts run \
  --base-url "$base_url" --scenarios "$contract_dir/scenarios" --profile core \
  --contract "$pin" \
  --implementation "$(sed -n 's/^implementation:[[:space:]]*//p' conformance.yaml)" \
  --report "$report"
set -e

mkdir -p "$(dirname "$report")"
echo "conformance report written to $report"
