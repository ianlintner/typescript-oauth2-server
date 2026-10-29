#!/usr/bin/env bash
set -euo pipefail
# Real database integration: fail rather than silently skip adapter parity.
: "${TEST_POSTGRES_URL:?set a disposable PostgreSQL URL}"
: "${TEST_MONGO_URL:?set a disposable MongoDB replica-set URL}"
pnpm exec tsx --test test/adapter-parity.test.ts
