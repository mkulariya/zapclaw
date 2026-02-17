//! Bubblewrap sandbox enforcement.
//!
//! ZapClaw runs inside a bubblewrap (bwrap) sandbox by default.
//! This module provides:
//! - Detection of sandbox state via `ZAPCLAW_SANDBOXED` env var
//! - VERIFIED sandbox state using runtime evidence (hostname, mountinfo)
//! - Self-wrapping: if not sandboxed, re-exec the binary inside bwrap
//! - Fail-closed behavior when sandbox cannot be established
//!
//! Security properties of the sandbox:
//! - Read-only root filesystem
//! - Isolated PID, IPC, UTS namespaces
//! - All capabilities dropped
//! - Writable workspace directory only
//! - Isolated /tmp
//! - Process dies with parent
//! - Network enabled by default (needed for LLM APIs)

use anyhow::{anyhow, Context, Result};
use std::path::Path;

/// Whether the process is currently sandboxed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SandboxState {
    /// Running inside bubblewrap sandbox (VERIFIED).
    Active,
    /// User explicitly disabled sandbox with --no-sandbox.
    Disabled,
}

/// Runtime evidence collected to verify sandbox state.
#[derive(Debug, Clone, PartialEq)]
struct RuntimeEvidence {
    /// Environment variable ZAPCLAW_SANDBOXED is set to "1"
    env_claimed: bool,
    /// Hostname matches expected sandbox hostname
    hostname_matches_sandbox: bool,
    /// Root filesystem is mounted read-only
    root_mount_read_only: bool,
}

/// Bootstrap action determined from evidence and bwrap availability.
#[derive(Debug, Clone, Copy, PartialEq)]
enum BootstrapAction {
    /// Sandbox is verified and active - continue execution
    VerifiedActive,
    /// Need to re-exec into sandbox
    ReExec,
    /// Sandbox unavailable and bwrap missing - fail closed
    FailClosed,
}

/// Check if bubblewrap (bwrap) is available on the system.
pub fn is_bwrap_available() -> bool {
    std::process::Command::new("bwrap")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Check if environment claims we're sandboxed.
fn sandbox_claimed_by_env() -> bool {
    std::env::var("ZAPCLAW_SANDBOXED")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Check if we're already inside a sandbox (VERIFIED state).
///
/// This now requires BOTH env claim AND runtime evidence verification.
pub fn is_sandboxed() -> bool {
    let evidence = collect_runtime_evidence();
    runtime_evidence_verified(&evidence)
}

/// Collect runtime evidence about sandbox state.
fn collect_runtime_evidence() -> RuntimeEvidence {
    RuntimeEvidence {
        env_claimed: sandbox_claimed_by_env(),
        hostname_matches_sandbox: check_hostname(),
        root_mount_read_only: check_root_readonly(),
    }
}

/// Verify that runtime evidence indicates a verified sandbox.
///
/// A sandbox is only verified when ALL three conditions are true:
/// 1. Environment sentinel is set (ZAPCLAW_SANDBOXED=1)
/// 2. Hostname is "zapclaw-sandbox"
/// 3. Root filesystem is mounted read-only
fn runtime_evidence_verified(evidence: &RuntimeEvidence) -> bool {
    evidence.env_claimed
        && evidence.hostname_matches_sandbox
        && evidence.root_mount_read_only
}

/// Check if hostname matches expected sandbox hostname.
fn check_hostname() -> bool {
    hostname::get()
        .map(|h| h.to_string_lossy() == "zapclaw-sandbox")
        .unwrap_or(false)
}

/// Check if root filesystem is mounted read-only.
///
/// Parses /proc/self/mountinfo to find the "/" mount point
/// and checks if it has the "ro" flag.
fn check_root_readonly() -> bool {
    std::fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .and_then(|content| parse_root_readonly(&content))
        .unwrap_or(false)
}

/// Parse mountinfo to check if root is read-only.
///
/// Looks for a line with mount point "/" and checks for "ro" flag.
///
/// Format from man 5 proc for /proc/[pid]/mountinfo:
/// 36 35 98:0 /1 /sys rw,nosuid,nodev,noexec,relatime shared:2 - sysfs sysfs rw
/// Fields (0-indexed):
/// 0: mount ID
/// 1: parent ID
/// 2: major:minor
/// 3: root
/// 4: mount point (THIS IS WHAT WE MATCH)
/// 5: mount options (THIS IS WHERE WE CHECK FOR "ro")
/// 6+: optional fields (terminated by "-")
/// - separator
/// After separator: filesystem type, mount source, super options
fn parse_root_readonly(mountinfo: &str) -> Option<bool> {
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }

        // Field 4 is mount point
        if fields[4] == "/" {
            // Field 5 is mount options - check for "ro"
            let options = fields[5];
            return Some(options.contains("ro"));
        }
    }
    None
}

/// Resolve bootstrap action from evidence and bwrap availability.
///
/// This is a pure function for easier testing.
fn resolve_bootstrap_action(
    evidence: &RuntimeEvidence,
    bwrap_available: bool,
) -> BootstrapAction {
    // If evidence is fully verified, we're good
    if runtime_evidence_verified(evidence) {
        return BootstrapAction::VerifiedActive;
    }

    // Evidence not verified - need to do something
    if bwrap_available {
        // Can re-exec into sandbox
        BootstrapAction::ReExec
    } else {
        // No bwrap available and not sandboxed - fail closed
        BootstrapAction::FailClosed
    }
}

/// Ensure the current process is running inside a bubblewrap sandbox.
///
/// This function implements FAIL-CLOSED behavior:
/// - If sandbox is verified (env + runtime evidence), returns `SandboxState::Active`
/// - If sandbox is not verified but bwrap is available, re-execs into sandbox (does not return)
/// - If sandbox is not verified AND bwrap is missing, returns a HARD ERROR
///
/// # Arguments
/// * `workspace` - Path to the workspace directory (will be bind-mounted writable)
/// * `no_network` - If true, network is isolated (`--unshare-net`)
///
/// # Errors
/// Returns an error if:
/// - Sandbox is not verified AND bwrap is not installed (fail-closed)
/// - Re-exec into sandbox fails
pub fn ensure_sandboxed(workspace: &Path, no_network: bool) -> Result<SandboxState> {
    // Collect runtime evidence
    let evidence = collect_runtime_evidence();

    // Check for bootstrap loop guard (prevent infinite re-exec loops)
    const MAX_ATTEMPTS: u8 = 2;
    let attempt = std::env::var("ZAPCLAW_SANDBOX_ATTEMPT")
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(0);

    // Detect spoofed environment: env claims sandboxed but runtime evidence disagrees
    let is_spoofed = evidence.env_claimed && !runtime_evidence_verified(&evidence);

    if is_spoofed && attempt >= MAX_ATTEMPTS {
        return Err(anyhow!(
            "Sandbox environment appears to be spoofed (ZAPCLAW_SANDBOXED=1 but runtime evidence doesn't match).\n\
            After {} re-exec attempts, sandbox verification still fails.\n\
            This may indicate a system configuration issue or active interference.\n\
            Either:\n\
            1. Unset ZAPCLAW_SANDBOXED and let ZapClaw manage the sandbox, or\n\
            2. Use --no-sandbox to explicitly disable sandboxing (NOT recommended)",
            attempt
        ));
    }

    // Determine what action to take
    let bwrap_avail = is_bwrap_available();
    let action = resolve_bootstrap_action(&evidence, bwrap_avail);

    match action {
        BootstrapAction::VerifiedActive => {
            // Sandbox is verified - good to go
            Ok(SandboxState::Active)
        }
        BootstrapAction::ReExec => {
            // Need to re-exec into sandbox
            if is_spoofed {
                eprintln!("⚠️  WARNING: ZAPCLAW_SANDBOXED=1 is set but runtime verification failed.");
                eprintln!("   Re-executing into real sandbox to correct this...");
            }
            reexec_into_sandbox(workspace, no_network, attempt + 1)
        }
        BootstrapAction::FailClosed => {
            // No bwrap and not sandboxed - FAIL CLOSED with helpful error
            Err(anyhow!(
                "Sandbox is required but bubblewrap (bwrap) is not installed.\n\
                \n\
                ZapClaw runs inside a bubblewrap sandbox for security by default.\n\
                To install bubblewrap:\n\
                \n\
                Ubuntu/Debian:  sudo apt install bubblewrap\n\
                Fedora:         sudo dnf install bubblewrap\n\
                Arch Linux:     sudo pacman -S bubblewrap\n\
                macOS:          brew install bubblewrap\n\
                \n\
                Alternatively, to DISABLE the sandbox (NOT recommended for production):\n\
                --no-sandbox\n\
                \n\
                For more information, see: https://github.com/containers/bubblewrap"
            ))
        }
    }
}

/// Re-exec the current process inside a bubblewrap sandbox.
///
/// This function does NOT return on success (the process is replaced via exec()).
fn reexec_into_sandbox(workspace: &Path, no_network: bool, attempt: u8) -> Result<SandboxState> {
    // Get current executable path and args
    let exe = std::env::current_exe()
        .context("Failed to get current executable path")?;
    let exe_str = exe.to_string_lossy();

    // Resolve workspace to absolute path for bind mount
    let workspace_abs = if workspace.is_absolute() {
        workspace.to_path_buf()
    } else {
        std::env::current_dir()
            .context("Failed to get current directory")?
            .join(workspace)
    };

    // Create workspace if it doesn't exist (needed before bind mount)
    if !workspace_abs.exists() {
        std::fs::create_dir_all(&workspace_abs)
            .context("Failed to create workspace directory")?;
    }
    let workspace_str = workspace_abs.to_string_lossy();

    // Collect original CLI args (skip argv[0])
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Build bwrap command
    let mut cmd = std::process::Command::new("bwrap");

    // Core isolation — matches scripts/sandbox.sh
    cmd.args(["--ro-bind", "/", "/"]);                          // Read-only root FS
    cmd.args(["--bind", &workspace_str, &workspace_str]);       // Writable workspace
    cmd.args(["--tmpfs", "/tmp"]);                               // Isolated /tmp
    cmd.args(["--dev", "/dev"]);                                 // Minimal /dev
    cmd.args(["--proc", "/proc"]);                               // New proc
    cmd.args(["--unshare-pid"]);                                 // PID namespace
    cmd.args(["--unshare-ipc"]);                                 // IPC namespace
    cmd.args(["--unshare-uts"]);                                 // UTS namespace
    cmd.args(["--hostname", "zapclaw-sandbox"]);
    cmd.args(["--new-session"]);
    cmd.args(["--cap-drop", "ALL"]);                             // Drop all capabilities
    cmd.args(["--die-with-parent"]);                             // Clean up on parent exit
    cmd.args(["--setenv", "HOME", &workspace_str]);              // HOME = workspace
    cmd.args(["--setenv", "ZAPCLAW_SANDBOXED", "1"]);            // Signal to child
    cmd.args(["--setenv", "ZAPCLAW_SANDBOX_ATTEMPT", &attempt.to_string()]); // Loop guard

    // Ensure the binary itself is readable inside sandbox
    cmd.args(["--ro-bind", &exe_str, &exe_str]);

    // Network isolation (disabled by default — LLM APIs need network)
    if no_network {
        cmd.arg("--unshare-net");
    }

    // Re-exec self with original arguments
    cmd.arg(&*exe_str);
    cmd.args(&args);

    // On Unix, exec() replaces this process — never returns on success
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        // exec() only returns on error
        Err(anyhow!("Failed to exec into sandbox: {}", err))
    }

    // Non-Unix fallback: spawn child and exit with its status
    #[cfg(not(unix))]
    {
        let status = cmd.status()
            .context("Failed to spawn sandboxed process")?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sandboxed_false_by_default() {
        // In test environment, ZAPCLAW_SANDBOXED should not be set
        // (unless tests are run inside the sandbox)
        if std::env::var("ZAPCLAW_SANDBOXED").is_err() {
            assert!(!is_sandboxed());
        }
    }

    #[test]
    fn test_sandbox_state_variants() {
        assert_eq!(SandboxState::Active, SandboxState::Active);
        assert_ne!(SandboxState::Active, SandboxState::Disabled);
    }

    #[test]
    fn test_parse_root_readonly_ro() {
        // Real mountinfo format with read-only root
        let mountinfo = "36 35 98:0 / / ro,relatime shared:1 - ext4 /dev/sda1 rw\n\
                         22 18 0:19 /1 /sys rw,nosuid,nodev,noexec,relatime shared:2 - sysfs sysfs rw";

        // The "/" mount with "ro" flag should return true
        assert_eq!(parse_root_readonly(mountinfo), Some(true));
    }

    #[test]
    fn test_parse_root_readonly_rw() {
        // Real mountinfo format with read-write root
        let mountinfo = "22 18 0:19 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
                         36 35 98:0 /1 /sys rw,nosuid,nodev,noexec,relatime shared:2 - sysfs sysfs rw";

        // The "/" mount with "rw" flag should return false
        assert_eq!(parse_root_readonly(mountinfo), Some(false));
    }

    #[test]
    fn test_parse_root_readonly_malformed() {
        let mountinfo = "invalid mount info";

        // Malformed input should return None/false
        assert_eq!(parse_root_readonly(mountinfo), None);
    }

    #[test]
    fn test_resolve_bootstrap_action_verified() {
        // Verified sandbox (env + hostname + ro mount)
        let evidence = RuntimeEvidence {
            env_claimed: true,
            hostname_matches_sandbox: true,
            root_mount_read_only: true,
        };

        assert_eq!(
            resolve_bootstrap_action(&evidence, true),
            BootstrapAction::VerifiedActive
        );
        assert_eq!(
            resolve_bootstrap_action(&evidence, false),
            BootstrapAction::VerifiedActive
        );
    }

    #[test]
    fn test_resolve_bootstrap_action_needs_reexec() {
        // Not verified, bwrap available
        let evidence = RuntimeEvidence {
            env_claimed: false,
            hostname_matches_sandbox: false,
            root_mount_read_only: false,
        };

        assert_eq!(
            resolve_bootstrap_action(&evidence, true),
            BootstrapAction::ReExec
        );
    }

    #[test]
    fn test_resolve_bootstrap_action_fail_closed() {
        // Not verified, bwrap missing
        let evidence = RuntimeEvidence {
            env_claimed: false,
            hostname_matches_sandbox: false,
            root_mount_read_only: false,
        };

        assert_eq!(
            resolve_bootstrap_action(&evidence, false),
            BootstrapAction::FailClosed
        );
    }

    #[test]
    fn test_runtime_evidence_verified_all_true() {
        let evidence = RuntimeEvidence {
            env_claimed: true,
            hostname_matches_sandbox: true,
            root_mount_read_only: true,
        };

        assert!(runtime_evidence_verified(&evidence));
    }

    #[test]
    fn test_runtime_evidence_verified_partial() {
        // Env only is NOT enough
        let evidence = RuntimeEvidence {
            env_claimed: true,
            hostname_matches_sandbox: false,
            root_mount_read_only: false,
        };

        assert!(!runtime_evidence_verified(&evidence));
    }

    #[test]
    fn test_runtime_evidence_verified_none() {
        let evidence = RuntimeEvidence {
            env_claimed: false,
            hostname_matches_sandbox: false,
            root_mount_read_only: false,
        };

        assert!(!runtime_evidence_verified(&evidence));
    }

    #[test]
    fn test_sandbox_state_no_longer_has_unavailable() {
        // SandboxState enum no longer has Unavailable variant
        // This test documents that change
        let active = SandboxState::Active;
        let disabled = SandboxState::Disabled;

        // These should compile and be distinct
        assert_ne!(active, disabled);
    }
}
