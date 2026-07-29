//! Root-confined filesystem access for ProofKeel host collectors.
//!
//! Every read a collector performs goes through [`SysRoot`], which roots it at
//! a configurable path. Two things follow, and both matter:
//!
//! - **Tests run against fixture directories.** A collector that opens `/proc`
//!   directly can only be tested on a host that happens to look right; one that
//!   reads through a root can be tested against a checked-in `/proc` snapshot on
//!   any machine, including CI and a developer's macOS laptop.
//! - **Path traversal is structurally impossible.** A relative path containing
//!   `..` is rejected rather than normalized, so no filename encountered while
//!   walking `/proc` or `/etc/cron.d` can escape the root.
//!
//! # Why some operations have two spellings
//!
//! This crate is the merge of `proofkeel-agent`'s `pk_collect::SysRoot` and
//! `proofkeel-sensor`'s `pk_snapshot::SysRoot`. They disagreed in exactly two
//! places, and in both the disagreement is a real decision rather than an
//! accident, so both behaviours are kept under distinct names:
//!
//! - [`SysRoot::path`] returns a [`Result`] naming the offending path;
//!   [`SysRoot::path_opt`] returns an [`Option`] for call sites that only
//!   branch on presence.
//! - [`SysRoot::read_to_string`] is strict UTF-8; [`SysRoot::read_to_string_lossy`]
//!   substitutes replacement characters. The choice is security-relevant, not
//!   stylistic. A posture collector that silently reports `U+FFFD` in place of
//!   a byte it could not decode turns corrupt input into a *finding*; a
//!   telemetry collector reading `/proc/<pid>/cmdline`, whose bytes are chosen
//!   by the observed process, must not let one hostile process blank the
//!   reading for the other four hundred. Neither caller is wrong, so neither
//!   name is the "default".

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

/// Errors from confined reads.
#[derive(Debug, thiserror::Error)]
pub enum SysError {
    /// The path escaped the root.
    #[error("path {path:?} escapes the collection root")]
    Escapes {
        /// The offending relative path.
        path: String,
    },
    /// A filesystem read failed.
    #[error("read {path}: {source}")]
    Io {
        /// Root-relative path.
        path: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
}

/// Convenience result alias for confined reads.
pub type Result<T> = std::result::Result<T, SysError>;

/// A filesystem root that all collector reads are relative to.
#[derive(Debug, Clone)]
pub struct SysRoot {
    root: PathBuf,
}

impl SysRoot {
    /// Root at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The live host root (`/`).
    #[must_use]
    pub fn host() -> Self {
        Self::new("/")
    }

    /// The root path.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve a root-relative path, refusing to escape.
    ///
    /// A leading `/` is tolerated and normalized rather than treated as an
    /// absolute path that would escape the root.
    ///
    /// # Errors
    /// Returns [`SysError::Escapes`] for any `..` component.
    pub fn path(&self, rel: &str) -> Result<PathBuf> {
        let mut out = self.root.clone();
        for component in rel.trim_start_matches('/').split('/') {
            match component {
                "" | "." => {}
                ".." => {
                    return Err(SysError::Escapes {
                        path: rel.to_string(),
                    });
                }
                c => out.push(c),
            }
        }
        Ok(out)
    }

    /// [`SysRoot::path`] for call sites that only branch on presence.
    #[must_use]
    pub fn path_opt(&self, rel: &str) -> Option<PathBuf> {
        self.path(rel).ok()
    }

    /// Read a file to bytes.
    ///
    /// # Errors
    /// Fails on escape or read error.
    pub fn read(&self, rel: &str) -> Result<Vec<u8>> {
        let path = self.path(rel)?;
        std::fs::read(&path).map_err(|source| SysError::Io {
            path: rel.to_string(),
            source,
        })
    }

    /// Read a file to a string, requiring valid UTF-8.
    ///
    /// Invalid UTF-8 is an error, not a substitution: for a posture collector,
    /// reporting `U+FFFD` where a byte could not be decoded would turn
    /// undecodable input into an apparently well-formed finding. Use
    /// [`SysRoot::read_to_string_lossy`] when the bytes are attacker- or
    /// process-controlled and partial data beats no data.
    ///
    /// # Errors
    /// Fails on escape, read error, or invalid UTF-8.
    pub fn read_to_string(&self, rel: &str) -> Result<String> {
        let path = self.path(rel)?;
        std::fs::read_to_string(&path).map_err(|source| SysError::Io {
            path: rel.to_string(),
            source,
        })
    }

    /// Read a file to a string, lossily decoding invalid UTF-8.
    ///
    /// Lossy rather than strict because several of these files carry
    /// process-controlled bytes — `/proc/<pid>/cmdline` most obviously — and a
    /// collector that errors on one weird process would report nothing about
    /// the other four hundred.
    ///
    /// # Errors
    /// Fails on escape or read error, never on encoding.
    pub fn read_to_string_lossy(&self, rel: &str) -> Result<String> {
        let bytes = self.read(rel)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// List the entry names of a directory, sorted.
    ///
    /// Sorted because collector output feeds a content hash: unsorted directory
    /// order would make an unchanged host look like it changed on every read.
    ///
    /// # Errors
    /// Fails on escape or read error.
    pub fn read_dir(&self, rel: &str) -> Result<Vec<String>> {
        let path = self.path(rel)?;
        let entries = std::fs::read_dir(&path).map_err(|source| SysError::Io {
            path: rel.to_string(),
            source,
        })?;
        let mut names: Vec<String> = entries
            .filter_map(std::result::Result::ok)
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .collect();
        names.sort();
        Ok(names)
    }

    /// Whether a root-relative path exists.
    #[must_use]
    pub fn exists(&self, rel: &str) -> bool {
        self.path(rel).is_ok_and(|p| p.exists())
    }

    /// Whether a root-relative path is a directory.
    #[must_use]
    pub fn is_dir(&self, rel: &str) -> bool {
        self.path(rel).is_ok_and(|p| p.is_dir())
    }

    /// Read the target of a symlink, if it is one.
    ///
    /// Used for `/proc/<pid>/exe`, where the link target is the datum.
    #[must_use]
    pub fn read_link(&self, rel: &str) -> Option<String> {
        let path = self.path(rel).ok()?;
        std::fs::read_link(path)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_relative_paths_under_the_root() {
        let sys = SysRoot::new("/fixtures/host");
        assert_eq!(
            sys.path("proc/1/stat").unwrap(),
            PathBuf::from("/fixtures/host/proc/1/stat")
        );
        // A leading slash is tolerated and normalized rather than treated as an
        // absolute path that would escape the root.
        assert_eq!(
            sys.path("/etc/passwd").unwrap(),
            PathBuf::from("/fixtures/host/etc/passwd")
        );
    }

    #[test]
    fn traversal_is_refused_not_normalized() {
        // Filenames encountered while walking /proc are not trusted input.
        let sys = SysRoot::new("/fixtures/host");
        assert!(sys.path("../etc/shadow").is_err());
        assert!(sys.path("proc/../../etc/shadow").is_err());
        assert!(sys.path("a/b/../../../..").is_err());
        // The Option spelling agrees with the Result spelling on every input.
        assert!(sys.path_opt("../etc/shadow").is_none());
        assert!(sys.path_opt("a/../../b").is_none());
        assert!(sys.path_opt("dpkg/status").is_some());
    }

    #[test]
    fn reads_and_lists_through_the_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("etc")).unwrap();
        std::fs::write(dir.path().join("etc/passwd"), "root:x:0:0::/root:/bin/sh\n").unwrap();
        std::fs::write(dir.path().join("etc/group"), "root:x:0:\n").unwrap();

        let sys = SysRoot::new(dir.path());
        assert!(sys
            .read_to_string("etc/passwd")
            .unwrap()
            .starts_with("root:"));
        assert_eq!(sys.read("etc/group").unwrap(), b"root:x:0:\n");
        assert_eq!(sys.read_dir("etc").unwrap(), vec!["group", "passwd"]);
        assert!(sys.exists("etc/passwd"));
        assert!(!sys.exists("etc/nope"));
        assert!(sys.is_dir("etc"));
        assert!(!sys.is_dir("etc/passwd"));
    }

    #[test]
    fn directory_listings_are_sorted_so_hashes_are_stable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("proc")).unwrap();
        for pid in ["10", "2", "1", "300"] {
            std::fs::create_dir(dir.path().join("proc").join(pid)).unwrap();
        }
        let sys = SysRoot::new(dir.path());
        assert_eq!(sys.read_dir("proc").unwrap(), vec!["1", "10", "2", "300"]);
    }

    #[test]
    fn strict_and_lossy_reads_differ_only_on_undecodable_bytes() {
        // /proc/<pid>/cmdline contains whatever bytes the process chose. The
        // strict reader must refuse it; the lossy reader must not, and the two
        // must agree on everything that does decode.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cmdline"), [0xff, 0xfe, b'o', b'k']).unwrap();
        std::fs::write(dir.path().join("clean"), "hello\n").unwrap();
        let sys = SysRoot::new(dir.path());

        assert!(sys.read_to_string("cmdline").is_err());
        assert!(sys.read_to_string_lossy("cmdline").unwrap().ends_with("ok"));
        assert_eq!(
            sys.read_to_string("clean").unwrap(),
            sys.read_to_string_lossy("clean").unwrap()
        );
    }

    #[test]
    fn missing_files_are_errors_not_panics() {
        let sys = SysRoot::new("/definitely/not/here");
        assert!(matches!(
            sys.read_to_string("anything"),
            Err(SysError::Io { .. })
        ));
        assert!(matches!(
            sys.read_to_string_lossy("anything"),
            Err(SysError::Io { .. })
        ));
        assert!(matches!(sys.read_dir("anything"), Err(SysError::Io { .. })));
    }

    #[test]
    fn escaping_reads_report_escape_not_io() {
        // The distinction matters: an escape is a bug or an attack, an I/O
        // error is an ordinary absent file.
        let sys = SysRoot::new("/fixtures/host");
        assert!(matches!(
            sys.read("../etc/shadow"),
            Err(SysError::Escapes { .. })
        ));
        assert!(matches!(
            sys.read_to_string("../etc/shadow"),
            Err(SysError::Escapes { .. })
        ));
        assert!(!sys.exists("../etc/shadow"));
        assert!(sys.read_link("../etc/shadow").is_none());
    }

    #[test]
    fn symlink_targets_are_readable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("target"), "x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.path().join("target"), dir.path().join("exe")).unwrap();
        let sys = SysRoot::new(dir.path());
        #[cfg(unix)]
        assert!(sys.read_link("exe").unwrap().ends_with("target"));
        // A regular file is not a symlink.
        assert!(sys.read_link("target").is_none());
    }
}
