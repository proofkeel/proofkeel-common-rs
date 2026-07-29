# proofkeel-common-rs — Security Policy

Report vulnerabilities to security@proofkeel.com. Do not open public issues
for security reports.

This repository is supply-chain critical: it will contain the transport and
signed self-update code compiled into every ProofKeel agent binary.

## Normative invariants

1. **No unverified remote code or artifacts.** Nothing in these crates may
   fetch and act on remote content without signature verification
   (self-update verifies before applying, always).
2. **Semver discipline.** Consumers pin exact versions; breaking changes are
   coordinated releases across `proofkeel-agent` and `proofkeel-sensor`.
3. **History is public.** Public at first `cargo publish`, full history.
   Every commit must be publishable.
