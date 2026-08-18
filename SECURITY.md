# proofkeel-common-rs — Security Policy

Report vulnerabilities to security@proofkeel.com. Do not open public issues
for security reports.

This repository is supply-chain critical for a narrower reason than "it
carries transport and self-update" — it doesn't. `pk-transport` and
`pk-update` both stayed with their respective agent repos (see CLAUDE.md's
"Deliberately not shared"). What it does carry — `pk-sysroot`, `pk-osinfo`,
`pk-backoff` — compiles into *both* `proofkeel-agent` (root-privileged) and
`proofkeel-sensor` (read-only) binaries, so a defect or a compromised
dependency introduced here reaches every ProofKeel install, regardless of
which agent is running.

## Normative invariants

1. **Confined reads cannot escape their root.** `pk_sysroot::SysRoot` is the
   sanctioned way collectors touch the filesystem. A relative path
   containing `..` is rejected, not normalized — path traversal out of the
   configured root is structurally impossible, not merely checked at the
   call site. Any new confined-read method must preserve reject-don't-normalize
   semantics, with a test for every escaping-path case.
2. **No `unsafe`.** Every crate in this workspace carries
   `#![forbid(unsafe_code)]` at its root, backed by
   `workspace.lints.rust.unsafe_code = "deny"`. Unlike `proofkeel-agent`
   (one audited `unsafe` boundary in `pk-exec`, for `SO_PEERCRED`/`setresuid`),
   this chassis has no FFI need, so there is no exception to grant — a PR
   introducing `unsafe` here should be rejected outright, not reviewed for
   safety.
3. **Dependencies are vetted, not just pinned.** Because this chassis links
   into every agent binary, adding a dependency is a supply-chain decision:
   check maintenance status and license compatibility (Apache-2.0-compatible,
   matching `proofkeel-agent`'s `cargo-deny` policy) before adding one, and
   prefer the existing dependency set over a new crate for a single call site.
   CI runs pinned `cargo-deny` and `cargo-audit` versions on every push and pull
   request, and a scheduled run catches advisories published between changes.
   `deny.toml` rejects unmuted advisories, yanked crates, incompatible licenses,
   wildcard registry dependencies, unknown registries, and all git sources
   unless a reviewed allowlist entry is added. The dependency graph is
   deliberately small (see `Cargo.lock`); keep it that way.
4. **Semver discipline.** Consumers (`proofkeel-agent`, `proofkeel-sensor`)
   pin exact versions or git revisions; breaking changes are coordinated
   releases, not silent version bumps.
5. **History is public.** Public at first `cargo publish` (a crates.io
   source tarball is public regardless of repo visibility). Every commit
   must be publishable — no secrets, internal URLs, or customer identifiers,
   ever.
