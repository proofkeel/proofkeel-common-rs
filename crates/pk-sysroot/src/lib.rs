//! Root-confined filesystem access for ProofKeel host collectors.
//!
//! Every read a collector performs goes through [`SysRoot`], which roots it at
//! a configurable path. Two things follow, and both matter:
//!
//! - **Tests run against fixture directories.** A collector that opens `/proc`
//!   directly can only be tested on a host that happens to look right; one that
//!   reads through a root can be tested against a checked-in `/proc` snapshot on
//!   any machine, including CI and a developer's macOS laptop.
//! - **`..` is rejected, not normalized.** A relative path containing `..` is
//!   an error rather than something to collapse, so no filename encountered
//!   while walking `/proc` or `/etc/cron.d` can lexically walk itself back out
//!   of the root.
//!
//! # What is (and isn't) guaranteed about symlinks
//!
//! [`SysRoot::path`] is a **lexical** helper: it validates and joins a
//! string, and performs no filesystem access at all. It gives no guarantee
//! about what the resulting path resolves to on disk — in particular, it does
//! *not* mean a symlink cannot make that path resolve outside `root`.
//!
//! The accessor methods ([`SysRoot::read`], [`SysRoot::read_to_string`],
//! [`SysRoot::read_dir`], [`SysRoot::exists`], [`SysRoot::is_dir`]) are the
//! ones that actually touch disk, and on unix they resolve `rel` one
//! component at a time, opening each component with `O_NOFOLLOW` relative to
//! the file descriptor of its already-opened parent (never by re-resolving a
//! joined path string). Two things follow:
//!
//! - A symlink anywhere in `rel` — including the final component — is
//!   refused outright ([`SysError::Symlink`]), never followed. This is what
//!   makes `root` an actual confinement boundary rather than a lexical
//!   convention: a non-`/` root (container image, chroot, mounted snapshot)
//!   containing a symlink cannot be used to read a file outside it, and a
//!   file a collector expects to be a plain file (`/var/lib/dpkg/status`, an
//!   `authorized_keys`, ...) cannot be swapped for a symlink to exfiltrate an
//!   unrelated file through the collector.
//! - Because each step is a single `openat`/`statat` call gated on
//!   `O_NOFOLLOW`/`AT_SYMLINK_NOFOLLOW`, there is no separate stat-then-open
//!   window in which a component could be swapped after being checked and
//!   before being used — including between [`SysRoot::exists`]/
//!   [`SysRoot::is_dir`] and a subsequent read, since both go through the
//!   same resolution and will refuse the same symlinks.
//!
//! `root` itself is trusted (it is developer/caller-configured, not derived
//! from `rel`) and is opened normally, following whatever `root` resolves to;
//! only the path *relative* to it gets this treatment.
//!
//! On non-unix targets there is no fd-chained syscall to do this atomically,
//! so the fallback is a best-effort walk that checks
//! [`std::fs::symlink_metadata`] at each component before using it. That
//! fallback has a real, if narrow, TOCTOU window and is documented as weaker
//! than the unix path.
//!
//! # Reads are capped by default
//!
//! [`SysRoot::read`], [`SysRoot::read_to_string`], and
//! [`SysRoot::read_to_string_lossy`] apply [`DEFAULT_MAX_BYTES`] so that a
//! pseudo-file with an unreliable declared size (most `/proc` and `/sys`
//! entries report `st_size` as `0` regardless of actual content) or a
//! maliciously large file cannot pull an unbounded amount of data into
//! memory. Callers that need a tighter or looser bound should use the
//! `_capped` variants ([`SysRoot::read_capped`],
//! [`SysRoot::read_to_string_capped`],
//! [`SysRoot::read_to_string_lossy_capped`]) with an explicit limit.
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
///
/// `#[non_exhaustive]`: this crate is the chassis for two privileged binaries
/// in separate repositories that pin it by git revision, so a consumer's
/// exhaustive `match` turns any new variant into a compile break they discover
/// only when they bump the pin — long after the change was made, and with no
/// signal at the time it was made. Adding `Symlink` and `TooLarge` did exactly
/// that. Consumers must carry a wildcard arm; new variants are then additive.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SysError {
    /// The path escaped the root.
    #[error("path {path:?} escapes the collection root")]
    Escapes {
        /// The offending relative path.
        path: String,
    },
    /// A path component resolved to (or through) a symlink and was refused.
    ///
    /// See the crate-level docs for exactly what this does and does not
    /// guarantee on unix vs. other targets.
    #[error("path {path:?} contains a symlink; refusing to follow it")]
    Symlink {
        /// The offending relative path.
        path: String,
    },
    /// A read exceeded its byte cap.
    #[error("read {path}: exceeds the {limit}-byte cap")]
    TooLarge {
        /// Root-relative path.
        path: String,
        /// The cap that was exceeded.
        limit: u64,
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

impl SysError {
    /// The root-relative path this error is about.
    ///
    /// Every variant carries one, so this is total. It exists because the enum
    /// is `#[non_exhaustive]`: a consumer that only needs the path should not
    /// have to match variants it cannot exhaustively name, and should not break
    /// when a new refusal kind is added.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::Escapes { path }
            | Self::Symlink { path }
            | Self::TooLarge { path, .. }
            | Self::Io { path, .. } => path,
        }
    }
}

/// Convenience result alias for confined reads.
pub type Result<T> = std::result::Result<T, SysError>;

/// Default cap applied by [`SysRoot::read`], [`SysRoot::read_to_string`], and
/// [`SysRoot::read_to_string_lossy`] when no explicit limit is given.
///
/// Generous enough for the largest legitimate file these crates read in
/// practice (a heavily-packaged host's `dpkg/status` can run several MiB)
/// while still bounding a read against a hostile or malformed file — most
/// importantly `/proc` and `/sys` pseudo-files, whose declared `st_size` is
/// not trustworthy input and is commonly `0` regardless of actual content.
pub const DEFAULT_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// What a confined path resolved to, for [`SysRoot::exists`]/[`SysRoot::is_dir`].
///
/// Deliberately coarse (and deliberately not exposing the full
/// [`std::fs::FileType`] surface): a symlink is always [`ConfinedKind::Other`]
/// here, never [`ConfinedKind::Dir`], because these accessors report on
/// exactly what the confined read/read_dir accessors would do — refuse it —
/// not on what the symlink's target happens to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfinedKind {
    Dir,
    Other,
}

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

    /// Split and validate `rel` into path components, rejecting `..`.
    ///
    /// Shared by [`SysRoot::path`] (which only needs this lexical result) and
    /// the confined accessors (which use it to drive a component-by-component
    /// on-disk resolution).
    fn components<'a>(&self, rel: &'a str) -> Result<Vec<&'a str>> {
        let mut out = Vec::new();
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

    /// Resolve a root-relative path *lexically*, refusing to escape.
    ///
    /// This performs **no filesystem access** and gives no guarantee about
    /// symlinks encountered on disk — see the crate-level docs. It exists for
    /// call sites that need a joined [`PathBuf`] for display or for a
    /// non-opening use (e.g. passing to an external tool); anything that
    /// opens or reads should use the accessor methods below instead, which
    /// perform the on-disk symlink refusal this does not.
    ///
    /// A leading `/` is tolerated and normalized rather than treated as an
    /// absolute path that would escape the root.
    ///
    /// # Errors
    /// Returns [`SysError::Escapes`] for any `..` component.
    pub fn path(&self, rel: &str) -> Result<PathBuf> {
        let components = self.components(rel)?;
        let mut out = self.root.clone();
        out.extend(components);
        Ok(out)
    }

    /// [`SysRoot::path`] for call sites that only branch on presence.
    #[must_use]
    pub fn path_opt(&self, rel: &str) -> Option<PathBuf> {
        self.path(rel).ok()
    }

    /// Read a file to bytes, capped at [`DEFAULT_MAX_BYTES`].
    ///
    /// # Errors
    /// Fails on escape, symlink, oversize, or read error.
    pub fn read(&self, rel: &str) -> Result<Vec<u8>> {
        self.read_capped(rel, DEFAULT_MAX_BYTES)
    }

    /// Read a file to bytes, refusing to read past `max_bytes`.
    ///
    /// The cap is enforced during the read itself, not via a preceding
    /// `stat`: several files this crate reads report an unreliable or
    /// meaningless declared size (`/proc`, `/sys`), and some are writable by
    /// an account other than the one running the collector, so a size check
    /// that races the read would defeat the point.
    ///
    /// # Errors
    /// Fails on escape, symlink, oversize, or read error.
    pub fn read_capped(&self, rel: &str, max_bytes: u64) -> Result<Vec<u8>> {
        use std::io::Read as _;

        let components = self.components(rel)?;
        let mut file = confined_open_file(&self.root, rel, &components)?;
        let mut buf = Vec::new();
        // One byte past the cap so an exactly-at-the-limit file is not
        // mistaken for oversized, while never holding more than
        // `max_bytes + 1` in memory regardless of the file's actual size.
        file.by_ref()
            .take(max_bytes + 1)
            .read_to_end(&mut buf)
            .map_err(|source| SysError::Io {
                path: rel.to_string(),
                source,
            })?;
        if buf.len() as u64 > max_bytes {
            return Err(SysError::TooLarge {
                path: rel.to_string(),
                limit: max_bytes,
            });
        }
        Ok(buf)
    }

    /// Read a file to a string, requiring valid UTF-8, capped at
    /// [`DEFAULT_MAX_BYTES`].
    ///
    /// Invalid UTF-8 is an error, not a substitution: for a posture collector,
    /// reporting `U+FFFD` where a byte could not be decoded would turn
    /// undecodable input into an apparently well-formed finding. Use
    /// [`SysRoot::read_to_string_lossy`] when the bytes are attacker- or
    /// process-controlled and partial data beats no data.
    ///
    /// # Errors
    /// Fails on escape, symlink, oversize, read error, or invalid UTF-8.
    pub fn read_to_string(&self, rel: &str) -> Result<String> {
        self.read_to_string_capped(rel, DEFAULT_MAX_BYTES)
    }

    /// [`SysRoot::read_to_string`] with an explicit byte cap.
    ///
    /// # Errors
    /// Fails on escape, symlink, oversize, read error, or invalid UTF-8.
    pub fn read_to_string_capped(&self, rel: &str, max_bytes: u64) -> Result<String> {
        let bytes = self.read_capped(rel, max_bytes)?;
        String::from_utf8(bytes).map_err(|err| SysError::Io {
            path: rel.to_string(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, err.utf8_error()),
        })
    }

    /// Read a file to a string, lossily decoding invalid UTF-8, capped at
    /// [`DEFAULT_MAX_BYTES`].
    ///
    /// Lossy rather than strict because several of these files carry
    /// process-controlled bytes — `/proc/<pid>/cmdline` most obviously — and a
    /// collector that errors on one weird process would report nothing about
    /// the other four hundred.
    ///
    /// # Errors
    /// Fails on escape, symlink, oversize, or read error, never on encoding.
    pub fn read_to_string_lossy(&self, rel: &str) -> Result<String> {
        self.read_to_string_lossy_capped(rel, DEFAULT_MAX_BYTES)
    }

    /// [`SysRoot::read_to_string_lossy`] with an explicit byte cap.
    ///
    /// # Errors
    /// Fails on escape, symlink, oversize, or read error, never on encoding.
    pub fn read_to_string_lossy_capped(&self, rel: &str, max_bytes: u64) -> Result<String> {
        let bytes = self.read_capped(rel, max_bytes)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// List the entry names of a directory, sorted.
    ///
    /// Sorted because collector output feeds a content hash: unsorted directory
    /// order would make an unchanged host look like it changed on every read.
    ///
    /// # Errors
    /// Fails on escape, symlink, or read error.
    pub fn read_dir(&self, rel: &str) -> Result<Vec<String>> {
        let components = self.components(rel)?;
        let mut names = confined_read_dir(&self.root, rel, &components)?;
        names.sort();
        Ok(names)
    }

    /// Whether a root-relative path exists.
    ///
    /// A symlink at `rel` counts as existing (something is there) but never
    /// as a directory — see [`SysRoot::is_dir`] and the crate-level docs on
    /// why this is deliberately consistent with what the read accessors will
    /// do, rather than a separate check that could disagree with them.
    #[must_use]
    pub fn exists(&self, rel: &str) -> bool {
        self.components(rel)
            .ok()
            .is_some_and(|components| confined_kind(&self.root, rel, &components).is_ok())
    }

    /// Whether a root-relative path is a real directory.
    ///
    /// A symlink — even one whose target is a directory — is never reported
    /// as a directory here, matching that [`SysRoot::read_dir`] would refuse
    /// to follow it.
    #[must_use]
    pub fn is_dir(&self, rel: &str) -> bool {
        self.components(rel)
            .ok()
            .and_then(|components| confined_kind(&self.root, rel, &components).ok())
            .is_some_and(|kind| kind == ConfinedKind::Dir)
    }

    /// Read the target of a symlink, if it is one.
    ///
    /// Used for `/proc/<pid>/exe`, where the link target is the datum. Unlike
    /// the other accessors this deliberately expects the final component to
    /// be a symlink — it reads the link's target text via `readlinkat`
    /// without ever opening what the link points to, so there is nothing to
    /// escape. Path components *before* the final one are still resolved
    /// with the same symlink refusal as every other accessor.
    #[must_use]
    pub fn read_link(&self, rel: &str) -> Option<String> {
        let components = self.components(rel).ok()?;
        confined_readlink(&self.root, rel, &components).ok()
    }
}

// ---------------------------------------------------------------------------
// Confined resolution: unix
//
// Each accessor resolves `rel` by opening one component at a time relative to
// the file descriptor of its parent, with `O_NOFOLLOW` (or, for the leaf of a
// stat/readlink, `AT_SYMLINK_NOFOLLOW`) on every step. Because each step is a
// single syscall gated on that flag, there is no separate stat-then-open
// window: a component is checked and used atomically. `root` itself is opened
// normally (it is caller-configured, not derived from `rel`).
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn confined<T>(rel: &str, result: std::result::Result<T, rustix::io::Errno>) -> Result<T> {
    result.map_err(|err| {
        if err == rustix::io::Errno::LOOP {
            SysError::Symlink {
                path: rel.to_string(),
            }
        } else {
            SysError::Io {
                path: rel.to_string(),
                source: err.into(),
            }
        }
    })
}

/// `lstat`-equivalent of one entry directly inside an already-open directory.
///
/// Used to classify `name` (symlink vs. directory vs. other) *before*
/// opening it, since `O_NOFOLLOW`'s errno on a rejected symlink is not
/// portable: combined with `O_DIRECTORY` it is `ELOOP` on Linux but
/// `ENOTDIR` on Apple platforms, and `ENOTDIR` is also the ordinary error
/// for "this is a plain file, not a directory" — a case that must NOT be
/// reported as [`SysError::Symlink`]. Because `parent` is already an open fd
/// for a real, confined directory and `name` is a single path segment with
/// no further components to resolve, this call itself cannot be redirected
/// by a symlink.
#[cfg(unix)]
fn lstat_component(
    rel: &str,
    parent: &rustix::fd::OwnedFd,
    name: &str,
) -> Result<rustix::fs::Stat> {
    confined(
        rel,
        rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW),
    )
}

/// Open `name` inside `parent`, refusing it outright if it is a symlink.
///
/// The `lstat` classification above makes the refusal portable and
/// unambiguous; `O_NOFOLLOW` on the subsequent `openat` is kept as
/// defense-in-depth against `name` being swapped between the two calls, even
/// though on that narrow race window a swap may surface as a generic
/// [`SysError::Io`] rather than [`SysError::Symlink`] on some platforms — the
/// read is refused either way, only the label may differ.
#[cfg(unix)]
fn open_component(
    rel: &str,
    parent: &rustix::fd::OwnedFd,
    name: &str,
    extra: rustix::fs::OFlags,
) -> Result<rustix::fd::OwnedFd> {
    use rustix::fs::{openat, FileType, Mode, OFlags};

    let st = lstat_component(rel, parent, name)?;
    if FileType::from_raw_mode(st.st_mode) == FileType::Symlink {
        return Err(SysError::Symlink {
            path: rel.to_string(),
        });
    }
    confined(
        rel,
        openat(
            parent,
            name,
            extra | OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ),
    )
}

/// Open every component up to (but excluding) the last, as directories.
/// Returns the root's own fd, opened normally, if `parents` is empty.
#[cfg(unix)]
fn resolve_parent_fd(root: &Path, rel: &str, parents: &[&str]) -> Result<rustix::fd::OwnedFd> {
    let root_file = std::fs::File::open(root).map_err(|source| SysError::Io {
        path: rel.to_string(),
        source,
    })?;
    let mut current: rustix::fd::OwnedFd = root_file.into();
    for name in parents {
        current = open_component(rel, &current, name, rustix::fs::OFlags::DIRECTORY)?;
    }
    Ok(current)
}

/// Resolve every component of `components`, opening the final one with
/// `extra` flags in addition to the symlink refusal every component gets.
/// Returns the root's own fd, opened normally, if `components` is empty
/// (i.e. `rel` names the root).
#[cfg(unix)]
fn resolve_fd(
    root: &Path,
    rel: &str,
    components: &[&str],
    extra: rustix::fs::OFlags,
) -> Result<rustix::fd::OwnedFd> {
    let Some((leaf, parents)) = components.split_last() else {
        return std::fs::File::open(root)
            .map(Into::into)
            .map_err(|source| SysError::Io {
                path: rel.to_string(),
                source,
            });
    };
    let parent = resolve_parent_fd(root, rel, parents)?;
    open_component(rel, &parent, leaf, extra)
}

#[cfg(unix)]
fn confined_open_file(root: &Path, rel: &str, components: &[&str]) -> Result<std::fs::File> {
    resolve_fd(root, rel, components, rustix::fs::OFlags::empty()).map(std::fs::File::from)
}

#[cfg(unix)]
fn confined_read_dir(root: &Path, rel: &str, components: &[&str]) -> Result<Vec<String>> {
    let fd = resolve_fd(root, rel, components, rustix::fs::OFlags::DIRECTORY)?;
    let dir = confined(rel, rustix::fs::Dir::new(fd))?;
    let mut names = Vec::new();
    for entry in dir {
        let entry = confined(rel, entry)?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        if let Ok(s) = name.to_str() {
            names.push(s.to_string());
        }
    }
    Ok(names)
}

#[cfg(unix)]
fn confined_stat(root: &Path, rel: &str, components: &[&str]) -> Result<rustix::fs::Stat> {
    let Some((leaf, parents)) = components.split_last() else {
        return rustix::fs::stat(root).map_err(|source| SysError::Io {
            path: rel.to_string(),
            source: source.into(),
        });
    };
    let parent = resolve_parent_fd(root, rel, parents)?;
    lstat_component(rel, &parent, leaf)
}

#[cfg(unix)]
fn confined_kind(root: &Path, rel: &str, components: &[&str]) -> Result<ConfinedKind> {
    let st = confined_stat(root, rel, components)?;
    Ok(
        if rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::Directory {
            ConfinedKind::Dir
        } else {
            ConfinedKind::Other
        },
    )
}

#[cfg(unix)]
fn confined_readlink(root: &Path, rel: &str, components: &[&str]) -> Result<String> {
    let Some((leaf, parents)) = components.split_last() else {
        return Err(SysError::Io {
            path: rel.to_string(),
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        });
    };
    let parent = resolve_parent_fd(root, rel, parents)?;
    let target = confined(rel, rustix::fs::readlinkat(&parent, *leaf, Vec::new()))?;
    Ok(target.to_string_lossy().into_owned())
}

// ---------------------------------------------------------------------------
// Confined resolution: non-unix fallback
//
// There is no portable fd-chained syscall here, so this walks the joined path
// component by component, checking `symlink_metadata` before using each one.
// This closes the same gap in the common case but, unlike the unix path,
// has a real TOCTOU window between a component's check and its use.
// ---------------------------------------------------------------------------

#[cfg(not(unix))]
fn confined_join(root: &Path, rel: &str, components: &[&str], check_leaf: bool) -> Result<PathBuf> {
    let mut current = root.to_path_buf();
    let Some((leaf, parents)) = components.split_last() else {
        return Ok(current);
    };
    for name in parents {
        current.push(name);
        refuse_symlink(rel, &current)?;
    }
    current.push(leaf);
    if check_leaf {
        refuse_symlink(rel, &current)?;
    }
    Ok(current)
}

#[cfg(not(unix))]
fn refuse_symlink(rel: &str, path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(SysError::Symlink {
            path: rel.to_string(),
        }),
        Ok(_) => Ok(()),
        Err(source) => Err(SysError::Io {
            path: rel.to_string(),
            source,
        }),
    }
}

#[cfg(not(unix))]
fn confined_open_file(root: &Path, rel: &str, components: &[&str]) -> Result<std::fs::File> {
    let path = confined_join(root, rel, components, true)?;
    std::fs::File::open(&path).map_err(|source| SysError::Io {
        path: rel.to_string(),
        source,
    })
}

#[cfg(not(unix))]
fn confined_read_dir(root: &Path, rel: &str, components: &[&str]) -> Result<Vec<String>> {
    let path = confined_join(root, rel, components, true)?;
    let entries = std::fs::read_dir(&path).map_err(|source| SysError::Io {
        path: rel.to_string(),
        source,
    })?;
    Ok(entries
        .filter_map(std::result::Result::ok)
        .filter_map(|e| e.file_name().to_str().map(String::from))
        .collect())
}

#[cfg(not(unix))]
fn confined_kind(root: &Path, rel: &str, components: &[&str]) -> Result<ConfinedKind> {
    let path = confined_join(root, rel, components, false)?;
    let meta = std::fs::symlink_metadata(&path).map_err(|source| SysError::Io {
        path: rel.to_string(),
        source,
    })?;
    Ok(if !meta.file_type().is_symlink() && meta.is_dir() {
        ConfinedKind::Dir
    } else {
        ConfinedKind::Other
    })
}

#[cfg(not(unix))]
fn confined_readlink(root: &Path, rel: &str, components: &[&str]) -> Result<String> {
    let path = confined_join(root, rel, components, false)?;
    let target = std::fs::read_link(&path).map_err(|source| SysError::Io {
        path: rel.to_string(),
        source,
    })?;
    Ok(target.to_string_lossy().into_owned())
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

    #[cfg(unix)]
    #[test]
    fn read_refuses_a_symlink_leaf() {
        // A file a collector expects to be plain (dpkg/status, an
        // authorized_keys, a sudoers drop-in...) must not have its target
        // read, hashed, or shipped in its place just because it was replaced
        // by a symlink.
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "root:$6$hash\n").unwrap();
        std::os::unix::fs::symlink(&secret, dir.path().join("status")).unwrap();
        let sys = SysRoot::new(dir.path());

        assert!(matches!(sys.read("status"), Err(SysError::Symlink { .. })));
        assert!(matches!(
            sys.read_to_string("status"),
            Err(SysError::Symlink { .. })
        ));
        assert!(matches!(
            sys.read_to_string_lossy("status"),
            Err(SysError::Symlink { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn read_refuses_an_escaping_intermediate_symlink() {
        // A root that is a container image, chroot, or mounted snapshot must
        // not let a symlink partway through `rel` step outside it onto the
        // real host filesystem.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("real")).unwrap();
        std::fs::write(dir.path().join("real/status"), "inside\n").unwrap();
        // "var" looks like a normal subdirectory but actually points at the
        // real, live "/etc" — an attempt to read "var/passwd" through it must
        // not resolve to the host's real /etc/passwd.
        std::os::unix::fs::symlink("/etc", dir.path().join("var")).unwrap();

        let sys = SysRoot::new(dir.path());
        assert!(matches!(
            sys.read("var/passwd"),
            Err(SysError::Symlink { .. })
        ));
        assert!(!sys.exists("var/passwd"));
        // The legitimate, non-symlinked path still works.
        assert_eq!(sys.read_to_string("real/status").unwrap(), "inside\n");
    }

    #[cfg(unix)]
    #[test]
    fn exists_and_is_dir_agree_with_what_reads_would_do() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("realdir")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("realdir"), dir.path().join("dirlink")).unwrap();
        std::fs::write(dir.path().join("file"), "x").unwrap();
        std::os::unix::fs::symlink(dir.path().join("file"), dir.path().join("filelink")).unwrap();
        let sys = SysRoot::new(dir.path());

        // A symlink to a directory is not reported as a directory...
        assert!(!sys.is_dir("dirlink"));
        // ...but it is reported as present, since something is there.
        assert!(sys.exists("dirlink"));
        // read_dir agrees: it refuses the same symlink is_dir already said
        // was not a safe directory to descend into.
        assert!(matches!(
            sys.read_dir("dirlink"),
            Err(SysError::Symlink { .. })
        ));

        assert!(sys.exists("filelink"));
        assert!(!sys.is_dir("filelink"));
        assert!(matches!(
            sys.read("filelink"),
            Err(SysError::Symlink { .. })
        ));
    }

    #[test]
    fn read_capped_rejects_oversized_reads() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("big"), vec![b'x'; 100]).unwrap();
        let sys = SysRoot::new(dir.path());

        assert!(matches!(
            sys.read_capped("big", 10),
            Err(SysError::TooLarge { limit: 10, .. })
        ));
        // Exactly at the cap is not mistaken for oversized.
        assert_eq!(sys.read_capped("big", 100).unwrap().len(), 100);
        assert!(sys.read_to_string_capped("big", 10).is_err());
        assert!(sys.read_to_string_lossy_capped("big", 10).is_err());
    }
}
