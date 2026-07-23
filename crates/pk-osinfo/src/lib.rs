//! Host operating-system discovery for the ProofKeel agent.
//!
//! Produces the security-scoped [`OsInfo`] facts reported at enrollment and in
//! heartbeats (see `HostFacts` in the gateway contract). Detection is
//! deliberately conservative: every probe reads through a caller-supplied root
//! path so the same code runs against the live `/` and against test fixtures.
//!
//! # Least-data principle
//! These facts identify a host's *platform* (distro family, init system,
//! virtualization) — never hardware serials, cloud instance metadata, or
//! cost/lifecycle attributes. The raw `machine_id` is returned un-hashed; the
//! caller hashes it (BLAKE3) before transmission, matching the
//! `HostFacts.machine_id_hash` contract field.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Security-scoped host platform facts.
///
/// Maps 1:1 onto the `HostFacts` proto message (minus `agent_version`, which
/// the transport layer injects). Field semantics mirror the contract comments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsInfo {
    /// Hostname from `/etc/hostname` (best-effort; `"unknown"` if unreadable).
    pub hostname: String,
    /// Raw `/etc/machine-id`. **Hash before transmission** (see crate docs).
    pub machine_id: String,
    /// Distro family: `"debian" | "rhel" | "alpine" | "suse" | <id>`.
    pub os_family: String,
    /// Concrete release: `"ubuntu:24.04"`, `"debian:12"`, `"alma:9"`, ...
    pub os_release: String,
    /// Kernel release string (e.g. `6.8.0-40-generic`).
    pub kernel: String,
    /// Machine architecture: `"x86_64" | "aarch64" | ...`.
    pub arch: String,
    /// Virtualization: `"kvm" | "qemu" | "vmware" | "hyperv" | "xen" | "none"`.
    pub virtualization: String,
    /// Init system: `"systemd" | "openrc" | "unknown"`.
    pub init_system: String,
}

impl OsInfo {
    /// Detect platform facts using `/` as the root.
    #[must_use]
    pub fn detect_host() -> Self {
        Self::detect(Path::new("/"))
    }

    /// Detect platform facts with all filesystem reads relative to `root`.
    ///
    /// Pass a fixture directory in tests; pass `/` in production.
    #[must_use]
    pub fn detect(root: &Path) -> Self {
        let osr = OsRelease::load(&root.join("etc/os-release"));
        Self {
            hostname: read_trimmed(&root.join("etc/hostname")).unwrap_or_else(|| "unknown".into()),
            machine_id: read_trimmed(&root.join("etc/machine-id")).unwrap_or_default(),
            os_family: osr.family(),
            os_release: osr.release(),
            kernel: read_trimmed(&root.join("proc/sys/kernel/osrelease"))
                .unwrap_or_else(|| "unknown".into()),
            arch: normalize_arch(std::env::consts::ARCH),
            virtualization: detect_virt(root),
            init_system: detect_init(root),
        }
    }
}

/// Read a file, trim surrounding whitespace, and collapse to a single line.
fn read_trimmed(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.lines().next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Map a distro `ID` (or `ID_LIKE` token) onto its family, if recognised.
fn family_of(id: &str) -> Option<&'static str> {
    match id {
        "debian" | "ubuntu" | "linuxmint" | "pop" | "raspbian" | "kali" => Some("debian"),
        "rhel" | "centos" | "fedora" | "almalinux" | "alma" | "rocky" | "ol" | "amzn" => {
            Some("rhel")
        }
        "alpine" => Some("alpine"),
        "opensuse" | "opensuse-leap" | "opensuse-tumbleweed" | "sles" | "suse" => Some("suse"),
        "arch" => Some("arch"),
        _ => None,
    }
}

/// Map Rust's `env::consts::ARCH` vocabulary onto the contract's.
fn normalize_arch(arch: &str) -> String {
    match arch {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => other,
    }
    .to_string()
}

/// Parsed `/etc/os-release` (only the keys we care about).
#[derive(Debug, Default)]
struct OsRelease {
    fields: BTreeMap<String, String>,
}

impl OsRelease {
    fn load(path: &Path) -> Self {
        let mut fields = BTreeMap::new();
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((key, value)) = line.split_once('=') {
                    fields.insert(key.trim().to_string(), unquote(value.trim()));
                }
            }
        }
        Self { fields }
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .get(key)
            .map(String::as_str)
            .filter(|s| !s.is_empty())
    }

    /// Distro family, normalising derivative distros onto their base.
    fn family(&self) -> String {
        let id = self.get("ID").unwrap_or("unknown");
        let id_like = self.get("ID_LIKE").unwrap_or("");
        let candidates = std::iter::once(id).chain(id_like.split_whitespace());
        for c in candidates {
            if let Some(fam) = family_of(c) {
                return fam.to_string();
            }
        }
        id.to_string()
    }

    /// Concrete release string `"<id>:<version_id>"`.
    fn release(&self) -> String {
        let id = self.get("ID").unwrap_or("unknown");
        match self.get("VERSION_ID") {
            Some(v) => format!("{id}:{v}"),
            None => id.to_string(),
        }
    }
}

/// Strip one layer of surrounding single or double quotes.
fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    if value.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

/// Heuristic virtualization detection from sysfs/DMI markers under `root`.
fn detect_virt(root: &Path) -> String {
    // Xen publishes a hypervisor type here.
    if let Ok(t) = std::fs::read_to_string(root.join("sys/hypervisor/type")) {
        if t.trim().eq_ignore_ascii_case("xen") {
            return "xen".to_string();
        }
    }
    // KVM/QEMU/VMware/Hyper-V are identifiable from DMI vendor/product strings.
    let probes = [
        "sys/class/dmi/id/sys_vendor",
        "sys/class/dmi/id/product_name",
        "sys/class/dmi/id/bios_vendor",
        "sys/class/dmi/id/board_vendor",
    ];
    for rel in probes {
        if let Ok(content) = std::fs::read_to_string(root.join(rel)) {
            let lower = content.to_lowercase();
            let hit = if lower.contains("kvm") {
                "kvm"
            } else if lower.contains("qemu") {
                "qemu"
            } else if lower.contains("vmware") {
                "vmware"
            } else if lower.contains("microsoft") || lower.contains("hyper-v") {
                "hyperv"
            } else if lower.contains("xen") {
                "xen"
            } else if lower.contains("virtualbox") || lower.contains("oracle") {
                "virtualbox"
            } else {
                continue;
            };
            return hit.to_string();
        }
    }
    "none".to_string()
}

/// Init-system detection from well-known runtime markers under `root`.
fn detect_init(root: &Path) -> String {
    // systemd creates this directory early in boot.
    if root.join("run/systemd/system").is_dir() {
        return "systemd".to_string();
    }
    // OpenRC's marker.
    if root.join("run/openrc").exists() || root.join("sbin/openrc").exists() {
        return "openrc".to_string();
    }
    "unknown".to_string()
}

/// Convenience: the absolute path of the live root.
#[must_use]
pub fn live_root() -> PathBuf {
    PathBuf::from("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(root: &Path, rel: &str, content: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }

    #[test]
    fn parses_ubuntu_os_release() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "etc/os-release",
            "NAME=\"Ubuntu\"\nVERSION=\"24.04 LTS (Noble Numbat)\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n",
        );
        write(root, "etc/hostname", "web01\n");
        write(root, "etc/machine-id", "0123456789abcdef0123456789abcdef\n");
        write(root, "proc/sys/kernel/osrelease", "6.8.0-40-generic\n");
        fs::create_dir_all(root.join("run/systemd/system")).unwrap();
        write(root, "sys/class/dmi/id/sys_vendor", "QEMU\n");

        let info = OsInfo::detect(root);
        assert_eq!(info.hostname, "web01");
        assert_eq!(info.machine_id, "0123456789abcdef0123456789abcdef");
        assert_eq!(info.os_family, "debian"); // ubuntu normalises to debian family
        assert_eq!(info.os_release, "ubuntu:24.04");
        assert_eq!(info.kernel, "6.8.0-40-generic");
        assert_eq!(info.virtualization, "qemu");
        assert_eq!(info.init_system, "systemd");
    }

    #[test]
    fn parses_alma_rhel_family() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "etc/os-release",
            "ID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.3\"\n",
        );
        let info = OsInfo::detect(root);
        assert_eq!(info.os_family, "rhel");
        assert_eq!(info.os_release, "almalinux:9.3");
    }

    #[test]
    fn alpine_and_openrc_and_no_virt() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "etc/os-release", "ID=alpine\nVERSION_ID=3.20.0\n");
        write(root, "sbin/openrc", "#!/bin/sh\n");
        let info = OsInfo::detect(root);
        assert_eq!(info.os_family, "alpine");
        assert_eq!(info.os_release, "alpine:3.20.0");
        assert_eq!(info.init_system, "openrc");
        assert_eq!(info.virtualization, "none");
    }

    #[test]
    fn missing_files_yield_safe_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        let info = OsInfo::detect(tmp.path());
        assert_eq!(info.hostname, "unknown");
        assert_eq!(info.machine_id, "");
        assert_eq!(info.os_family, "unknown");
        assert_eq!(info.init_system, "unknown");
        assert_eq!(info.virtualization, "none");
    }

    #[test]
    fn unquote_handles_quotes_and_plain() {
        assert_eq!(unquote("\"24.04\""), "24.04");
        assert_eq!(unquote("'x'"), "x");
        assert_eq!(unquote("plain"), "plain");
    }
}
