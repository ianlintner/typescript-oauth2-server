#!/usr/bin/env bash
# Check out the shared oauth2-conformance contract at the commit pinned in
# conformance.yaml, into .contract (gitignored). The runner lives inside that
# checkout, so this repository vendors no contract fixtures or runner code.
#
# usage: scripts/setup-conformance.sh [CONTRACT_DIR]   (default: .contract)
set -euo pipefail

cd "$(dirname "$0")/.."
contract_dir="${1:-.contract}"
repository="https://github.com/ianlintner/oauth2-conformance"

commit="$(sed -n 's/^contract:[[:space:]]*//p' conformance.yaml)"
if [ -z "$commit" ] || ! printf '%s' "$commit" | grep -Eq '^[0-9a-f]{40}$'; then
  echo "conformance.yaml must pin contract to a full 40-hex commit SHA" >&2
  exit 1
fi

# Idempotent: reuse an existing checkout if it is already at the pinned commit.
# .git may be a directory (clone) or a file (linked worktree).
if [ -e "$contract_dir/.git" ]; then
  if [ "$(git -C "$contract_dir" rev-parse HEAD 2>/dev/null)" = "$commit" ]; then
    echo "contract already checked out at $commit"
    exit 0
  fi
  git -C "$contract_dir" fetch --quiet origin "$commit"
else
  git clone --filter=blob:none --no-checkout "$repository" "$contract_dir"
fi

git -C "$contract_dir" checkout --detach "$commit"
test "$(git -C "$contract_dir" rev-parse HEAD)" = "$commit"
echo "contract checked out at $commit"
