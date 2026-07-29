# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository status

Intentionally empty scaffold (created 2026-07-28). Crates arrive by
**history-preserving extraction** from `proofkeel-agent` using
`git filter-repo` — never by hand-copying files. Preserved commit provenance
is part of the audit story for these supply-chain-critical crates. If asked to
add chassis code here before the extraction has happened, do the extraction
first.

## What this is

Shared chassis crates consumed by both ProofKeel agent binaries:
`proofkeel-agent` (acts: remediation/patching, root) and `proofkeel-sensor`
(observes: telemetry, read-only). Extraction set: `pk-transport`, `pk-update`,
`pk-osinfo`; candidates `pk-store`, `pk-sched`. `pk-proto` stays in
`proofkeel-agent` — each client repo owns its own protocol contract.

## Constraints

- Supply-chain critical: `pk-update` (signed self-update) ships in every agent
  install. The signature-verification invariants in SECURITY.md are normative.
  `proofkeel-agent`'s release auditor scope must follow `pk-update` into this
  repo when it lands.
- Public at first `cargo publish` — full git history becomes public; every
  commit must be publishable. DCO sign-off (`git commit -s`) on all commits.
- Semver discipline: `proofkeel-agent` and `proofkeel-sensor` pin exact
  versions; breaking changes are coordinated releases.
- Toolchain pinned in `rust-toolchain.toml`, matching the two agent repos.

## Commands

- `cargo build` / `cargo test` — no-op until crates land (empty workspace).
