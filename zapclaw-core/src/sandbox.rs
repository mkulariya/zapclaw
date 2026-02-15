//! Bubblewrap sandbox enforcement.
//!
//! ZapClaw runs inside a bubblewrap (bwrap) sandbox by default.
//! This module provides:
//! - Detection of sandbox state via `ZAPCLAW_SANDBOXED` env var
//! - Self-wrapping: if not sandboxed, re-exec the binary inside bwrap
//! - `--no-sandbox` escape hatch for development
//!
//! Security properties of the sandbox:
//! - Read-only root filesystem
//! - Isolated PID, IPC, UTS namespaces
//! - All capabilities dropped
//! - Writable workspace directory only
//! - Isolated /tmp
//! - Process dies with parent
//! - Network enabled by default (needed for LLM APIs)

use anyhow::Result;
use std::path::Path;

/// Whether the process is currently sandboxed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SandboxState {
    /// Running inside bubblewrap sandbox.
    Active,
    /// User explicitly disabled sandbox with --no-sandbox.
    Disabled,
    /// bwrap not installed — running without sandbox (warning printed).
    Unavailable,
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

/// Check if we're already inside a sandbox (env var sentinel).
pub fn is_sandboxed() -> bool {
    std::env::var("ZAPCLAW_SANDBOXED")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Ensure the current process is running inside a bubblewrap sandbox.
///
/// If already sandboxed (`ZAPCLAW_SANDBOXED=1`), returns `SandboxState::Active`.
/// If bwrap is not installed, prints a warning and returns `SandboxState::Unavailable`.
/// Otherwise, re-execs the current binary inside bwrap — this function does NOT return
/// on success (the process is replaced via `exec()`).
///
/// # Arguments
/// * `workspace` - Path to the workspace directory (will be bind-mounted writable)
/// * `no_network` - If true, network is isolated (`--unshare-net`)
pub fn ensure_sandboxed(workspace: &Path, no_network: bool) -> Result<SandboxState> {
    // Already sandboxed — nothing to do
    if is_sandboxed() {
        return Ok(SandboxState::Active);
    }

    // Check bwrap availability
    if !is_bwrap_available() {
        eprintln!("WARNING: bubblewrap (bwrap) is not installed. Running WITHOUT sandbox.");
        eprintln!("  Install it:");
        eprintln!("    Debian/Ubuntu: sudo apt install bubblewrap");
        eprintln!("    Fedora:        sudo dnf install bubblewrap");
        eprintln!("    Arch:          sudo pacman -S bubblewrap");
        eprintln!("    macOS:         brew install bubblewrap");
        eprintln!();
        return Ok(SandboxState::Unavailable);
    }

    // Get current executable path and args
    let exe = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("Failed to get current executable path: {}", e))?;
    let exe_str = exe.to_string_lossy();

    // Resolve workspace to absolute path for bind mount
    let workspace_abs = if workspace.is_absolute() {
        workspace.to_path_buf()
    } else {
        std::env::current_dir()?.join(workspace)
    };

    // Create workspace if it doesn't exist (needed before bind mount)
    if !workspace_abs.exists() {
        std::fs::create_dir_all(&workspace_abs)?;
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
        Err(anyhow::anyhow!("Failed to exec into sandbox: {}", err))
    }

    // Non-Unix fallback: spawn child and exit with its status
    #[cfg(not(unix))]
    {
        let status = cmd.status()?;
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
        assert_ne!(SandboxState::Active, SandboxState::Unavailable);
    }
}
