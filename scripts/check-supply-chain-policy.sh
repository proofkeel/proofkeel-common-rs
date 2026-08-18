#!/bin/sh
set -eu

fail() {
    printf 'supply-chain policy check: %s\n' "$1" >&2
    exit 1
}

require_literal() {
    file=$1
    literal=$2
    description=$3

    grep -Fq "$literal" "$file" || fail "$description"
}

policy=deny.toml
workflow=.github/workflows/supply-chain.yml

[ -f "$policy" ] || fail "deny.toml is missing"
[ -f "$workflow" ] || fail "the supply-chain workflow is missing"

require_literal "$policy" 'yanked = "deny"' \
    "yanked dependencies are not denied"
require_literal "$policy" '"Apache-2.0"' \
    "Apache-2.0 is missing from the license allowlist"
require_literal "$policy" '"MIT"' \
    "MIT is missing from the license allowlist"
require_literal "$policy" 'unknown-registry = "deny"' \
    "unknown registries are not denied"
require_literal "$policy" 'unknown-git = "deny"' \
    "unknown git sources are not denied"
require_literal "$policy" \
    'allow-registry = ["https://github.com/rust-lang/crates.io-index"]' \
    "crates.io is not the sole allowed registry"

require_literal "$workflow" 'pull_request:' \
    "the supply-chain gate does not run for pull requests"
require_literal "$workflow" 'schedule:' \
    "advisories are not rescanned on a schedule"
require_literal "$workflow" 'uses: taiki-e/install-action@v2.85.5' \
    "the supply-chain tool installer is not pinned"
require_literal "$workflow" 'tool: cargo-deny@0.20.2,cargo-audit@0.22.2' \
    "cargo-deny and cargo-audit are not pinned to the reviewed versions"
require_literal "$workflow" 'fallback: none' \
    "the tool installer permits an unreviewed fallback path"
require_literal "$workflow" 'run: cargo deny check' \
    "CI does not enforce the complete cargo-deny policy"
require_literal "$workflow" 'run: cargo audit' \
    "CI does not enforce the RustSec audit"

printf 'supply-chain policy check: ok\n'
