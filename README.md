# proofkeel-common-rs

Shared Rust chassis crates for ProofKeel agents (`proofkeel-agent`,
`proofkeel-sensor`).

**Status: intentionally empty scaffold.** The crates arrive by
history-preserving extraction (`git filter-repo`) from `proofkeel-agent` when
`pk-sensor` development starts — not by hand-copying, so commit provenance is
preserved for auditors.

## Planned extraction set

| Crate | Role |
|---|---|
| `pk-transport` | outbound mTLS connectivity |
| `pk-update` | signed self-update |
| `pk-osinfo` | OS/distro detection |
| (`pk-store`, `pk-sched`) | candidates, extracted only if the sensor needs them |

`pk-proto` never moves here — protocol contracts are owned by the client repo
that speaks them (`proofkeel-agent`, `proofkeel-sensor` each own theirs).

This repository becomes public at the first `cargo publish` (a crates.io
source tarball is public regardless of repo visibility).

## License

Apache-2.0. Contributions require DCO sign-off (`git commit -s`).
