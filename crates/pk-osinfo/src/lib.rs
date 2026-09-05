//! Host operating-system discovery for the ProofKeel agents.
//!
//! Produces the security-scoped [`OsInfo`] facts `proofkeel-agent` reports at
//! enrollment and in heartbeats (see `HostFacts` in the gateway contract), and
//! exposes the individual probes so `proofkeel-sensor` can build its OCSF
//! `device` object from the same readings rather than a second implementation
//! of `/etc/os-release` parsing.
//!
//! Detection is deliberately conservative: every probe reads through a
//! [`SysRoot`], so the same code runs against the live `/` and against test
//! fixtures.
//!
//! # Projections stay with their callers
//!
//! This crate stops at *facts*. [`OsInfo`] is `proofkeel-agent`'s projection of
//! them; the sensor's OCSF `Device`/`Os` projection stays in the sensor. The
//! two agents disagree about vocabulary — the agent reports
//! `virtualization: "kvm"`, the sensor reports an OCSF `type_id` of
//! `VIRTUAL` — and collapsing that into one shared enum would force a wire
//! change on one of them to serve the other's schema.
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

use pk_sysroot::SysRoot;
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
        Self::detect_in(&SysRoot::new(root))
    }

    /// Detect platform facts through an existing [`SysRoot`].
    #[must_use]
    pub fn detect_in(sys: &SysRoot) -> Self {
        let osr = OsRelease::load(sys);
        Self {
            // `/etc/hostname`, not `/proc/sys/kernel/hostname`: this value is
            // reported as `HostFacts.hostname` and changing which file it comes
            // from is a wire-visible change, not a refactor. See
            // `hostname_proc` for the live-kernel reading the sensor prefers.
            hostname: hostname_etc(sys).unwrap_or_else(|| "unknown".into()),
            machine_id: machine_id(sys).unwrap_or_default(),
            os_family: osr.family(),
            os_release: osr.release(),
            kernel: kernel_release(sys).unwrap_or_else(|| "unknown".into()),
            arch: normalize_arch(std::env::consts::ARCH),
            virtualization: detect_virt(sys),
            init_system: detect_init(sys),
        }
    }
}

/// Cap for the single-line identity/version facts this crate probes
/// (hostname, machine-id, kernel release, boot id, DMI attributes...).
///
/// These are always a short line in practice; the cap exists so a hostile or
/// malformed file (most of what this reads is `/proc` or `/sys`, whose
/// declared size is not trustworthy input) cannot pull an unbounded amount of
/// data into memory just to keep the first line of it.
const MAX_FACT_BYTES: u64 = 4 * 1024;

/// Cap for the small multi-line documents this crate parses
/// (`/etc/os-release`, `/proc/1/cgroup`). Larger than [`MAX_FACT_BYTES`]
/// because these legitimately have more than one line, but still far above
/// any real instance of either file.
const MAX_DOC_BYTES: u64 = 64 * 1024;

/// Read a root-relative file, trim surrounding whitespace, and collapse to a
/// single line. `None` for absent, unreadable, empty, or oversized files.
#[must_use]
pub fn read_trimmed(sys: &SysRoot, rel: &str) -> Option<String> {
    sys.read_to_string_capped(rel, MAX_FACT_BYTES)
        .ok()
        .map(|s| s.lines().next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
}

/// The hostname as configured in `/etc/hostname`.
#[must_use]
pub fn hostname_etc(sys: &SysRoot) -> Option<String> {
    read_trimmed(sys, "etc/hostname")
}

/// The hostname as the kernel currently reports it.
///
/// Preferred over [`hostname_etc`] when the *live* name matters: a host renamed
/// since boot, or one whose name is set by DHCP rather than a config file, has
/// a `/etc/hostname` that disagrees with reality.
#[must_use]
pub fn hostname_proc(sys: &SysRoot) -> Option<String> {
    read_trimmed(sys, "proc/sys/kernel/hostname")
}

/// The raw `/etc/machine-id`. Hash before transmission (see crate docs).
#[must_use]
pub fn machine_id(sys: &SysRoot) -> Option<String> {
    read_trimmed(sys, "etc/machine-id")
}

/// The kernel release string (e.g. `6.8.0-40-generic`).
#[must_use]
pub fn kernel_release(sys: &SysRoot) -> Option<String> {
    read_trimmed(sys, "proc/sys/kernel/osrelease")
}

/// The boot id, which changes on every reboot.
///
/// What lets a consumer tell "the agent restarted" apart from "the host
/// rebooted" when reconciling a gap in reporting.
#[must_use]
pub fn boot_id(sys: &SysRoot) -> Option<String> {
    read_trimmed(sys, "proc/sys/kernel/random/boot_id")
}

/// Read one DMI attribute (`sys_vendor`, `product_name`, `bios_vendor`,
/// `board_vendor`, ...) from `/sys/class/dmi/id/`.
///
/// Absent inside containers and on most non-x86 hardware, which is itself a
/// signal — see [`detect_container`].
#[must_use]
pub fn dmi(sys: &SysRoot, attribute: &str) -> Option<String> {
    read_trimmed(sys, &format!("sys/class/dmi/id/{attribute}"))
}

/// Map a distro `ID` (or `ID_LIKE` token) onto its family, if recognised.
#[must_use]
pub fn family_of(id: &str) -> Option<&'static str> {
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
#[must_use]
pub fn normalize_arch(arch: &str) -> String {
    match arch {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => other,
    }
    .to_string()
}

/// Parsed `/etc/os-release`.
///
/// Comment lines and blanks are skipped, and one layer of matched `"` or `'`
/// quoting is stripped from each value. The single-quote case is why this
/// parser exists rather than a `trim_matches('"')` one-liner: `ID='alpine'` is
/// valid `os-release` and a naive parser reports the family as `'alpine'`,
/// which matches nothing.
#[derive(Debug, Default, Clone)]
pub struct OsRelease {
    fields: BTreeMap<String, String>,
}

impl OsRelease {
    /// Parse `/etc/os-release` under `sys`. An unreadable file yields an empty
    /// set rather than an error — a minimal image legitimately has none.
    #[must_use]
    pub fn load(sys: &SysRoot) -> Self {
        Self::parse(
            &sys.read_to_string_capped("etc/os-release", MAX_DOC_BYTES)
                .unwrap_or_default(),
        )
    }

    /// Parse `os-release` content that has already been read.
    #[must_use]
    pub fn parse(content: &str) -> Self {
        let mut fields = BTreeMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                fields.insert(key.trim().to_string(), unquote(value.trim()));
            }
        }
        Self { fields }
    }

    /// One field, if present and non-empty.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .get(key)
            .map(String::as_str)
            .filter(|s| !s.is_empty())
    }

    /// Distro family, normalising derivative distros onto their base.
    #[must_use]
    pub fn family(&self) -> String {
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
    #[must_use]
    pub fn release(&self) -> String {
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

/// Heuristic virtualization detection from sysfs/DMI markers.
///
/// Returns `"none"` rather than `Option` because the agent's `HostFacts`
/// contract has no null virtualization. Note that this reports the *hypervisor*
/// and says nothing about containerization — a container on a KVM guest reports
/// `"kvm"`. Use [`detect_container`] for that axis.
#[must_use]
pub fn detect_virt(sys: &SysRoot) -> String {
    // Xen publishes a hypervisor type here.
    if let Ok(t) = sys.read_to_string_capped("sys/hypervisor/type", MAX_FACT_BYTES) {
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
        if let Ok(content) = sys.read_to_string_capped(rel, MAX_FACT_BYTES) {
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

/// Detect whether this is a container, naming the marker that said so.
///
/// `/proc/1/cgroup` is read rather than checking for `/.dockerenv`, which only
/// Docker writes. The distinction matters to an analyst: "root on a container"
/// and "root on the host" are very different findings from otherwise identical
/// telemetry.
#[must_use]
pub fn detect_container(sys: &SysRoot) -> Option<&'static str> {
    if let Ok(cgroup) = sys.read_to_string_lossy_capped("proc/1/cgroup", MAX_DOC_BYTES) {
        for marker in ["/docker/", "/lxc/", "/kubepods", "containerd"] {
            if cgroup.contains(marker) {
                return Some(marker.trim_matches('/'));
            }
        }
    }
    if sys.exists("run/.containerenv") {
        return Some("containerenv");
    }
    if sys.exists(".dockerenv") {
        return Some("dockerenv");
    }
    None
}

/// Init-system detection from well-known runtime markers.
#[must_use]
pub fn detect_init(sys: &SysRoot) -> String {
    // systemd creates this directory early in boot.
    if sys.is_dir("run/systemd/system") {
        return "systemd".to_string();
    }
    // OpenRC's marker.
    if sys.exists("run/openrc") || sys.exists("sbin/openrc") {
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

    // ---- probes the sensor's OCSF device projection is built from --------

    #[test]
    fn os_release_quoting_is_handled_for_every_field() {
        // Covers proofkeel-sensor's `os_release_field` cases. `VERSION_ID=3.19.1`
        // is unquoted, `PRETTY_NAME` is double-quoted, `EMPTY=""` collapses to
        // absent, and single quotes — which the sensor's original
        // `trim_matches('"')` would have left in place — are stripped.
        let osr = OsRelease::parse(
            "PRETTY_NAME=\"Alpine Linux v3.19\"\nVERSION_ID=3.19.1\nEMPTY=\"\"\nID='alpine'\n",
        );
        assert_eq!(osr.get("PRETTY_NAME"), Some("Alpine Linux v3.19"));
        assert_eq!(osr.get("VERSION_ID"), Some("3.19.1"));
        assert_eq!(osr.get("EMPTY"), None);
        assert_eq!(osr.get("ABSENT"), None);
        assert_eq!(osr.get("ID"), Some("alpine"));
        assert_eq!(osr.family(), "alpine");
    }

    #[test]
    fn a_commented_out_key_does_not_shadow_the_real_one() {
        let osr = OsRelease::parse("#VERSION_ID=\"8\"\nVERSION_ID=\"9\"\n");
        assert_eq!(osr.get("VERSION_ID"), Some("9"));
    }

    #[test]
    fn hostname_has_a_configured_and_a_live_reading() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "etc/hostname", "configured.example\n");
        write(root, "proc/sys/kernel/hostname", "live.example\n");
        let sys = SysRoot::new(root);
        assert_eq!(hostname_etc(&sys).as_deref(), Some("configured.example"));
        assert_eq!(hostname_proc(&sys).as_deref(), Some("live.example"));
        // OsInfo reports the configured one; changing that is a wire change.
        assert_eq!(OsInfo::detect_in(&sys).hostname, "configured.example");
    }

    #[test]
    fn boot_id_and_dmi_are_readable() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "proc/sys/kernel/random/boot_id",
            "11111111-2222-3333-4444-555555555555\n",
        );
        write(root, "sys/class/dmi/id/sys_vendor", "QEMU\n");
        let sys = SysRoot::new(root);
        assert_eq!(
            boot_id(&sys).as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );
        assert_eq!(dmi(&sys, "sys_vendor").as_deref(), Some("QEMU"));
        assert_eq!(dmi(&sys, "product_name"), None);
    }

    #[test]
    fn containers_are_distinguished_from_hosts() {
        // "root on a container" and "root on the host" are very different
        // findings from otherwise identical telemetry.
        for (cgroup, expected) in [
            ("0::/docker/8f2c1b9e0a3d4f5e6a7b8c9d0e1f2a3b\n", "docker"),
            ("0::/kubepods/besteffort/pod123\n", "kubepods"),
            ("0::/lxc/ct1\n", "lxc"),
            ("0::/system.slice/containerd.service\n", "containerd"),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write(tmp.path(), "proc/1/cgroup", cgroup);
            assert_eq!(
                detect_container(&SysRoot::new(tmp.path())),
                Some(expected),
                "cgroup {cgroup:?}"
            );
        }
    }

    #[test]
    fn a_bare_host_is_not_a_container() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "proc/1/cgroup", "0::/init.scope\n");
        assert_eq!(detect_container(&SysRoot::new(tmp.path())), None);
    }

    #[test]
    fn podman_and_docker_marker_files_are_honoured() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "run/.containerenv", "");
        assert_eq!(
            detect_container(&SysRoot::new(tmp.path())),
            Some("containerenv")
        );

        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), ".dockerenv", "");
        assert_eq!(
            detect_container(&SysRoot::new(tmp.path())),
            Some("dockerenv")
        );
    }

    #[test]
    fn a_container_cgroup_with_undecodable_bytes_still_classifies() {
        // /proc/1/cgroup is read lossily: a byte sequence that fails UTF-8
        // must not make a container look like a bare host.
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("proc/1");
        fs::create_dir_all(&p).unwrap();
        let mut bytes = b"0::/docker/abc".to_vec();
        bytes.extend_from_slice(&[0xff, 0xfe]);
        fs::write(p.join("cgroup"), bytes).unwrap();
        assert_eq!(detect_container(&SysRoot::new(tmp.path())), Some("docker"));
    }
}
