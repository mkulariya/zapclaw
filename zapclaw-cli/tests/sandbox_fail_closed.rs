//! CLI integration/smoke tests for sandbox fail-closed behavior.
//!
//! These tests verify that ZapClaw properly fails closed when sandbox
//! cannot be established, per WP2 requirements.

use std::process::Command;
use std::path::PathBuf;

/// Get the path to the zapclaw binary.
fn zapclaw_binary() -> PathBuf {
    // In development, use the debug build
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Remove test binary name
    if path.ends_with("deps") || path.ends_with("release") || path.ends_with("debug") {
        path.pop();
    }
    path.push("zapclaw");
    #[cfg(unix)]
    {
        path.set_extension("");
    }
    path
}

#[test]
#[ignore] // This test is expensive and requires controlling PATH
fn test_missing_bwrap_fail_closed() {
    // This test requires setting PATH to an empty temp directory
    // to simulate missing bwrap, then verifying non-zero exit

    let bin = zapclaw_binary();
    assert!(bin.exists(), "zapclaw binary not found at {:?}", bin);

    // Run with empty PATH (no bwrap available)
    let output = Command::new(&bin)
        .env("PATH", "") // Empty PATH = no bwrap
        .arg("--help") // Use --help to avoid actually running
        .output();

    // Should fail because bwrap is missing and --no-sandbox not set
    match output {
        Ok(output) => {
            // If it ran, it should have failed
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // Should mention bwrap installation
                assert!(stderr.contains("bubblewrap") || stderr.contains("bwrap"),
                    "Error message should mention bwrap installation. Got: {}", stderr);
                // Should mention --no-sandbox override
                assert!(stderr.contains("--no-sandbox"),
                    "Error message should mention --no-sandbox override. Got: {}", stderr);
            } else {
                panic!("Process should have failed when bwrap is missing");
            }
        }
        Err(e) => {
            // Failed to execute - this is also acceptable
            println!("Process failed to execute: {}", e);
        }
    }
}

#[test]
#[ignore] // This test is expensive and requires controlling PATH
fn test_spoofed_env_fail_closed() {
    // Test that ZAPCLAW_SANDBOXED=1 with missing bwrap fails closed

    let bin = zapclaw_binary();
    assert!(bin.exists(), "zapclaw binary not found at {:?}", bin);

    // Set spoofed environment
    let output = Command::new(&bin)
        .env("PATH", "") // No bwrap
        .env("ZAPCLAW_SANDBOXED", "1") // Spoofed env
        .arg("--help")
        .output();

    match output {
        Ok(output) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // Should detect spoofing
                assert!(stderr.contains("spoof") || stderr.contains("verification"),
                    "Error should detect spoofed environment. Got: {}", stderr);
            } else {
                panic!("Process should have failed with spoofed env and no bwrap");
            }
        }
        Err(e) => {
            println!("Process failed to execute: {}", e);
        }
    }
}

#[test]
#[ignore] // This test is expensive and requires controlling PATH
fn test_explicit_bypass_works() {
    // Test that --no-sandbox allows execution even without bwrap

    let bin = zapclaw_binary();
    assert!(bin.exists(), "zapclaw binary not found at {:?}", bin);

    // Run with --no-sandbox override
    let output = Command::new(&bin)
        .env("PATH", "") // No bwrap
        .arg("--no-sandbox")
        .arg("--help")
        .output();

    match output {
        Ok(output) => {
            // Should succeed (exit 0 for --help)
            assert!(output.status.success(),
                "Process should succeed with --no-sandbox. stderr: {}",
                String::from_utf8_lossy(&output.stderr));

            let stdout = String::from_utf8_lossy(&output.stdout);
            // Should show help output
            assert!(stdout.contains("ZapClaw") || stdout.contains("USAGE"),
                "Should show help output. Got: {}", stdout);
        }
        Err(e) => {
            panic!("Process should execute with --no-sandbox: {}", e);
        }
    }
}
