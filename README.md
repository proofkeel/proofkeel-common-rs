# proofkeel-common-rs

Shared Rust chassis crates for ProofKeel agents (`proofkeel-agent`,
`proofkeel-sensor`).

Crates arrive by history-preserving extraction (`git filter-repo`) from
`proofkeel-agent` — not by hand-copying, so commit provenance is preserved for
auditors.

## Extracted

| Crate        | Role                                                                                                 |
| ------------ | ---------------------------------------------------------------------------------------------------- |
| `pk-sysroot` | root-confined filesystem reads (was `pk_collect::SysRoot` / `pk_snapshot::SysRoot`)                  |
| `pk-osinfo`  | OS/distro/init/virt/container detection, and the probes both agents' host projections are built from |
| `pk-backoff` | jittered retry backoff (was `pk_transport::ExponentialBackoff` / `pk_ship::Backoff`)                 |

## Deliberately _not_ shared

The original plan named `pk-transport` and `pk-update`. Comparing the two
agents as built shows that would be a premature merge, not a deduplication:

- **`pk-transport` vs `pk-ship`** — gRPC/tonic with a self-generated Ed25519
  identity and a session-nonce challenge, versus HTTPS/reqwest with an
  externally-provisioned mTLS certificate. Different protocol, different trust
  model. They share the retry schedule, which is now `pk-backoff`, and nothing
  else.
- **`pk-store` outbox vs `pk-spool`** — SQLite/WAL versus segment files with
  CRC32 framing. The sensor avoids `rusqlite` deliberately, for binary size and
  telemetry write volume.
- **`pk-update`** — the sensor has no self-update path. The 2026-08-03
  decision made that permanent, not a staging gap: there is no second
  implementation to converge, and none is planned.
- **Signed-document verification** — the agent verifies a zstd-compressed
  protobuf bundle with a domain-separated prefix and a durable downgrade gate;
  the sensor verifies a JSON envelope with a base64 payload and
  multi-signature key rotation. Only the key-id trust set is common, and it is
  small.

`pk-agent-proto` never moves here — protocol contracts are owned by the client repo
that speaks them (`proofkeel-agent`, `proofkeel-sensor` each own theirs).

## Consuming these crates

Until the first `cargo publish`, both agents depend on pinned git revisions:

```toml
[workspace.dependencies]
pk-sysroot = { git = "https://github.com/proofkeel/proofkeel-common-rs", rev = "<sha>" }
```

Iterate locally with an **uncommitted** `.cargo/config.toml`:

```toml
[patch."https://github.com/proofkeel/proofkeel-common-rs"]
pk-sysroot = { path = "../proofkeel-common-rs/crates/pk-sysroot" }
```

This repository becomes public at the first `cargo publish` (a crates.io
source tarball is public regardless of repo visibility).

## License

Apache-2.0. Contributions require DCO sign-off (`git commit -s`).
