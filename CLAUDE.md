# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository status

No longer an empty scaffold: the 2026-07-29 history-preserving extraction from
`proofkeel-agent` (via `git filter-repo`) landed three real crates — see
`crates/`. Preserved commit provenance is part of the audit story for these
supply-chain-critical crates. Any further crate must arrive the same way,
never by hand-copying files.

## What this is

Shared chassis crates consumed by both ProofKeel agent binaries:
`proofkeel-agent` (acts: remediation/patching, root) and `proofkeel-sensor`
(observes: telemetry, read-only).

Extracted so far:

| Crate        | Role                                                                                                 |
| ------------ | ---------------------------------------------------------------------------------------------------- |
| `pk-sysroot` | root-confined filesystem reads (was `pk_collect::SysRoot` / `pk_snapshot::SysRoot`)                  |
| `pk-osinfo`  | OS/distro/init/virt/container detection, and the probes both agents' host projections are built from |
| `pk-backoff` | jittered retry backoff (was `pk_transport::ExponentialBackoff` / `pk_ship::Backoff`)                 |

Deliberately **not** shared, despite being in the original plan: `pk-transport`
(agent's gRPC/tonic vs sensor's HTTPS/reqwest — different protocol, different
trust model), `pk-store` outbox (SQLite/WAL vs segment files with CRC32
framing), `pk-update` (sensor has no self-update path yet — nothing to
converge), and signed-document verification (agent's zstd/protobuf bundle vs
sensor's JSON envelope — only the key-id trust set is common, and it is
small). See README.md's "Deliberately not shared" section for the full
rationale before proposing to merge any of these. `pk-agent-proto` never moves
here — protocol contracts are owned by the client repo that speaks them
(`proofkeel-agent`, `proofkeel-sensor` each own theirs).

## Constraints

- Supply-chain critical, but not for self-update: every crate here compiles
  into *both* agent binaries, so a defect or a compromised dependency reaches
  every ProofKeel install regardless of which agent is running. The
  invariants in SECURITY.md (confined-read path safety, `#![forbid(unsafe_code)]`
  across the workspace, dependency vetting) are normative. `pk-update` does
  **not** follow into this repo — the agent-release-auditor scope stays with
  `proofkeel-agent` (plan §4.2), and the 2026-08-03 decision that the sensor
  gets no self-update path at all makes that permanent rather than "not yet".
- Public at first `cargo publish` — full git history becomes public; every
  commit must be publishable. DCO sign-off (`git commit -s`) on all commits.
- Semver discipline: `proofkeel-agent` and `proofkeel-sensor` pin exact
  versions; breaking changes are coordinated releases.
- Toolchain pinned in `rust-toolchain.toml`, matching the two agent repos.

## Commands

The workspace has three real crates and a real test suite; these are not
no-ops:

- `cargo build --workspace` — build all crates.
- `cargo test --workspace` — run all tests.
- `cargo fmt --all -- --check` — formatting gate (matches CI).
- `cargo clippy --workspace --all-targets -- -D warnings` — lint gate (matches
  CI).

CI (`.github/workflows/rust.yml`) runs all four across two toolchains: the
pinned `1.94.1` (`rust-toolchain.toml`) and the workspace's declared MSRV
floor `1.85`.
