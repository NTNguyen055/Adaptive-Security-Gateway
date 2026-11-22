#!/usr/bin/env bash
# P0.4 — Static coverage gate for Lua regression (local versus Jenkins).
# Read-only: no Docker, network, Redis, credentials or source execution.
# Install as tests/check-ci-suite-parity.sh and invoke from repository root.
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
local_runner="$root/tests/run-unit.sh"
ci_runner="$root/tests/run-ci.sh"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
[[ -f "$local_runner" && -f "$ci_runner" ]] || fail 'Missing local or CI runner'

# Extract literal test_name:source_name entries strictly from the runner arrays.
# Do not source the scripts, which could launch containers or modify runtime state.
extract_pairs() {
  local path="$1" marker="$2"
  awk -v marker="$marker" '
    index($0,marker) { inside=1; next }
    inside && /^[[:space:]]*\)/ { exit }
    inside && /^[[:space:]]*\047[^\047]+\047/ {
      s=$0
      sub(/^[[:space:]]*\047/, "", s)
      sub(/\047.*/, "", s)
      sub(/\r$/, "", s)
      print s
    }
  ' "$path"
}

local_pairs="$(extract_pairs "$local_runner" 'local pairs=(')"
ci_pairs="$(extract_pairs "$ci_runner" 'lua_tests=(')"
[[ -n "$local_pairs" ]] || fail 'Local runner has no recognized Lua test array'
[[ -n "$ci_pairs" ]] || fail 'CI runner has no recognized Lua test array'

if [[ "$local_pairs" != "$ci_pairs" ]]; then
  printf 'FAIL: Local/CI suite arrays differ (including execution order).\n' >&2
  diff -u <(printf '%s\n' "$local_pairs") \
          <(printf '%s\n' "$ci_pairs") >&2 || true
  exit 1
fi

declare -A registered=()
count=0
while IFS= read -r pair; do
  [[ "$pair" =~ ^[a-zA-Z0-9_]+:[a-zA-Z0-9_]+$ ]] \
    || fail "Malformed test:module pair: $pair"
  test_name="${pair%%:*}"
  source_name="${pair#*:}"
  [[ -z "${registered[$test_name]:-}" ]] || fail "Duplicate Lua test: $test_name"
  [[ -f "$root/nginx/tests/$test_name.lua" ]] \
    || fail "Missing test source: $test_name.lua"
  [[ -f "$root/nginx/lua/$source_name.lua" ]] \
    || fail "Missing target module: $source_name.lua"
  registered[$test_name]=1
  count=$((count + 1))
done <<< "$local_pairs"

# Fail when a new test_*.lua file silently falls outside BOTH runners.
shopt -s nullglob
lua_files=("$root"/nginx/tests/test_*.lua)
shopt -u nullglob
[[ ${#lua_files[@]} -gt 0 ]] || fail 'No Lua test files in nginx/tests'

for path in "${lua_files[@]}"; do
  name="${path##*/}"
  name="${name%.lua}"
  [[ -n "${registered[$name]:-}" ]] \
    || fail "Unregistered Lua test in both runners: nginx/tests/$name.lua"
done

[[ "$count" -eq "${#lua_files[@]}" ]] \
  || fail 'Suite count differs from test_*.lua file count'

printf 'PASS: Local/CI Lua suite parity (%d suites, all Lua tests accounted for)\n' "$count"
