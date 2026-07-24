//! Host posture collection for the ProofKeel agent.
//!
//! A [`Collector`] reads one security domain (packages, ssh, services, ...)
//! through the [`SysRoot`] abstraction and produces a canonical, content-hashed
//! [`DomainState`]. Two seams make collectors testable and safe:
//!
//! - [`SysRoot`] roots **every** filesystem read at a configurable path, so the
//!   same collector runs against the live `/` and against a golden fixture dir.
//! - [`CommandRunner`] abstracts external command execution (`sshd -T`, ...),
//!   so tests inject canned output instead of shelling out (and the privileged
//!   process is the only place a real runner is wired in).
//!
//! Concrete collectors: [`packages::PackagesCollector`] and [`ssh::SshCollector`].

#![forbid(unsafe_code)]

pub mod backupstate;
pub mod bruteforce;
pub mod certs;
pub mod container_packages;
pub mod containers;
pub mod firewall;
pub mod ospatch;
pub mod packages;
pub mod perms;
pub mod ports;
pub mod procmaps;
pub mod services;
pub mod ssh;
pub mod testing;
pub mod watch;

use std::path::{Path, PathBuf};
use std::time::Duration;

/// Errors produced by collectors.
#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    /// A filesystem read under the SysRoot failed.
    #[error("io ({path}): {source}")]
    Io {
        /// The root-relative path that failed.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// An external command failed or returned a non-zero status.
    #[error("command `{program}` failed: {message}")]
    Command {
        /// Program that was invoked.
        program: String,
        /// Human-readable failure detail.
        message: String,
    },
    /// The collected input could not be parsed.
    #[error("parse error in {source_name}: {message}")]
    Parse {
        /// Logical source (e.g. `"dpkg/status"`, `"sshd -T"`).
        source_name: String,
        /// Detail.
        message: String,
    },
    /// Serialization of the typed state failed.
    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Convenience result alias for collectors.
pub type Result<T> = std::result::Result<T, CollectError>;

/// Stable identifier for a collector (matches the control plane's collector
/// registry; used by `PrivOp::RunCollector`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CollectorId(pub String);

impl CollectorId {
    /// Borrow the id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How often a collector should run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cadence {
    /// Run on a fixed period.
    Periodic(Duration),
    /// Run when an inotify-style change is observed (Phase 2; treated as
    /// periodic by the current scheduler).
    OnChange,
    /// Only run on explicit request.
    Manual,
}

/// A collected, canonicalized domain state with its content hash.
///
/// `payload` is the deterministic serialization of the typed domain state;
/// `hash` is its BLAKE3 digest, used for drift detection and the
/// `DomainStateHash` reported in heartbeats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainState {
    /// Which domain this state belongs to.
    pub domain: pk_proto::Domain,
    /// Canonical serialized payload (JSON).
    pub payload: Vec<u8>,
    /// BLAKE3 content hash of `payload`.
    pub hash: [u8; 32],
}

impl DomainState {
    /// Build a `DomainState`, hashing the payload.
    #[must_use]
    pub fn new(domain: pk_proto::Domain, payload: Vec<u8>) -> Self {
        let hash = *blake3::hash(&payload).as_bytes();
        Self {
            domain,
            payload,
            hash,
        }
    }
}

/// A collector for one security domain.
pub trait Collector: Send + Sync {
    /// Stable collector id.
    fn id(&self) -> CollectorId;
    /// Suggested run cadence.
    fn cadence(&self) -> Cadence;
    /// The domain this collector populates.
    fn domain(&self) -> pk_proto::Domain;
    /// Collect the current state, reading only through `sys`.
    fn collect(&self, sys: &SysRoot) -> Result<DomainState>;

    /// Root-relative paths whose change should trigger an immediate re-collect
    /// (the file-watch half of "interval + jitter + file-watch triggers", see
    /// [`watch`]). Default: none (timer-only). Provided (not required) so
    /// existing collectors need not implement it.
    fn watched_paths(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Filesystem root that all collector reads are relative to.
///
/// In production this is `/`; in tests it points at a fixture directory. Reads
/// are confined to the root: a relative path is joined onto the root and any
/// attempt to escape via a leading `/` or `..` component is rejected.
#[derive(Debug, Clone)]
pub struct SysRoot {
    root: PathBuf,
}

impl SysRoot {
    /// Create a root at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The live root (`/`).
    #[must_use]
    pub fn host() -> Self {
        Self::new("/")
    }

    /// The root path.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve a root-relative path, refusing to escape the root.
    ///
    /// # Errors
    /// Returns `None` if `rel` is absolute or contains a `..` component.
    pub fn path(&self, rel: &str) -> Option<PathBuf> {
        let rel = rel.trim_start_matches('/');
        let mut out = self.root.clone();
        for comp in rel.split('/') {
            match comp {
                "" | "." => continue,
                ".." => return None,
                c => out.push(c),
            }
        }
        Some(out)
    }

    /// Read a root-relative file to a string.
    ///
    /// # Errors
    /// Fails if the path escapes the root or cannot be read.
    pub fn read_to_string(&self, rel: &str) -> Result<String> {
        let path = self.path(rel).ok_or_else(|| CollectError::Parse {
            source_name: rel.to_string(),
            message: "path escapes SysRoot".into(),
        })?;
        std::fs::read_to_string(&path).map_err(|e| CollectError::Io {
            path: rel.to_string(),
            source: e,
        })
    }

    /// Read a root-relative file to bytes.
    ///
    /// # Errors
    /// Fails if the path escapes the root or cannot be read.
    pub fn read(&self, rel: &str) -> Result<Vec<u8>> {
        let path = self.path(rel).ok_or_else(|| CollectError::Parse {
            source_name: rel.to_string(),
            message: "path escapes SysRoot".into(),
        })?;
        std::fs::read(&path).map_err(|e| CollectError::Io {
            path: rel.to_string(),
            source: e,
        })
    }

    /// Whether a root-relative path exists.
    #[must_use]
    pub fn exists(&self, rel: &str) -> bool {
        self.path(rel).is_some_and(|p| p.exists())
    }
}

/// Output of an external command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Raw stdout bytes.
    pub stdout: Vec<u8>,
    /// Raw stderr bytes.
    pub stderr: Vec<u8>,
    /// Process exit code.
    pub exit_code: i32,
}

impl CommandOutput {
    /// Whether the command exited zero.
    #[must_use]
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }

    /// stdout as a lossy UTF-8 string.
    #[must_use]
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// stderr as a lossy UTF-8 string.
    #[must_use]
    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// Abstraction over external command execution.
///
/// The production implementation ([`SystemCommandRunner`]) shells out via
/// `std::process::Command`; tests inject [`testing::FixtureRunner`].
pub trait CommandRunner: Send + Sync {
    /// Run `program` with `args`, capturing output.
    ///
    /// # Errors
    /// Fails if the program cannot be spawned.
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput>;
}

/// Real command runner backed by `std::process::Command`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput> {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(|e| CollectError::Command {
                program: program.to_string(),
                message: e.to_string(),
            })?;
        Ok(CommandOutput {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.status.code().unwrap_or(-1),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysroot_confines_reads() {
        let sys = SysRoot::new("/var/lib");
        assert_eq!(
            sys.path("dpkg/status").unwrap(),
            PathBuf::from("/var/lib/dpkg/status")
        );
        // Leading slash is tolerated and normalised.
        assert_eq!(
            sys.path("/dpkg/status").unwrap(),
            PathBuf::from("/var/lib/dpkg/status")
        );
        // Escapes are rejected.
        assert!(sys.path("../etc/passwd").is_none());
        assert!(sys.path("a/../../b").is_none());
    }

    #[test]
    fn domain_state_hashes_payload() {
        let a = DomainState::new(pk_proto::Domain::Packages, b"hello".to_vec());
        let b = DomainState::new(pk_proto::Domain::Packages, b"hello".to_vec());
        let c = DomainState::new(pk_proto::Domain::Packages, b"world".to_vec());
        assert_eq!(a.hash, b.hash);
        assert_ne!(a.hash, c.hash);
    }
}
