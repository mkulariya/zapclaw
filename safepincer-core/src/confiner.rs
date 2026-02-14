use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// Workspace path confiner.
///
/// Enforces that ALL file operations are restricted to the workspace directory.
/// Prevents path traversal attacks, symlink escapes, and any access outside the
/// confined workspace.
///
/// Security properties:
/// - Resolves symlinks before validation (prevents symlink escape)
/// - Canonicalizes paths to eliminate ../ traversals
/// - Validates both the target path and any intermediate components
#[derive(Debug, Clone)]
pub struct Confiner {
    /// Canonical path to the workspace root
    workspace_root: PathBuf,
}

impl Confiner {
    /// Create a new Confiner for the given workspace directory.
    ///
    /// The workspace path must exist and will be canonicalized.
    pub fn new(workspace_path: &Path) -> Result<Self> {
        let workspace_root = std::fs::canonicalize(workspace_path)
            .with_context(|| format!("Failed to canonicalize workspace path: {}", workspace_path.display()))?;

        if !workspace_root.is_dir() {
            bail!("Workspace path is not a directory: {}", workspace_root.display());
        }

        Ok(Self { workspace_root })
    }

    /// Validate that a path is within the workspace.
    ///
    /// Returns the canonicalized path if valid, or an error if the path
    /// escapes the workspace boundary.
    pub fn validate_path(&self, path: &Path) -> Result<PathBuf> {
        // Resolve the path relative to workspace if not absolute
        let resolved = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.workspace_root.join(path)
        };

        // For existing paths, canonicalize to resolve symlinks
        let canonical = if resolved.exists() {
            std::fs::canonicalize(&resolved)
                .with_context(|| format!("Failed to canonicalize path: {}", resolved.display()))?
        } else {
            // For new files, canonicalize the parent directory and append the filename
            let parent = resolved.parent()
                .ok_or_else(|| anyhow::anyhow!("Path has no parent: {}", resolved.display()))?;

            if !parent.exists() {
                bail!(
                    "Parent directory does not exist: {} (workspace: {})",
                    parent.display(),
                    self.workspace_root.display()
                );
            }

            let canonical_parent = std::fs::canonicalize(parent)
                .with_context(|| format!("Failed to canonicalize parent: {}", parent.display()))?;

            let file_name = resolved.file_name()
                .ok_or_else(|| anyhow::anyhow!("Path has no filename: {}", resolved.display()))?;

            canonical_parent.join(file_name)
        };

        // Security check: ensure the canonical path starts with workspace root
        if !canonical.starts_with(&self.workspace_root) {
            bail!(
                "🚫 Path escape attempt blocked! Path '{}' resolves to '{}' which is outside workspace '{}'",
                path.display(),
                canonical.display(),
                self.workspace_root.display()
            );
        }

        Ok(canonical)
    }

    /// Validate that a path is a valid file within the workspace.
    pub fn validate_file(&self, path: &Path) -> Result<PathBuf> {
        let canonical = self.validate_path(path)?;
        if canonical.exists() && !canonical.is_file() {
            bail!("Path is not a file: {}", canonical.display());
        }
        Ok(canonical)
    }

    /// Validate that a path is a valid directory within the workspace.
    pub fn validate_dir(&self, path: &Path) -> Result<PathBuf> {
        let canonical = self.validate_path(path)?;
        if canonical.exists() && !canonical.is_dir() {
            bail!("Path is not a directory: {}", canonical.display());
        }
        Ok(canonical)
    }

    /// Get the workspace root path.
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_workspace() -> (tempfile::TempDir, Confiner) {
        let tmp = tempfile::tempdir().unwrap();
        let confiner = Confiner::new(tmp.path()).unwrap();
        (tmp, confiner)
    }

    #[test]
    fn test_valid_path_within_workspace() {
        let (tmp, confiner) = setup_workspace();
        let file_path = tmp.path().join("test.txt");
        fs::write(&file_path, "hello").unwrap();

        let result = confiner.validate_path(&file_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_relative_path_within_workspace() {
        let (tmp, confiner) = setup_workspace();
        let file_path = tmp.path().join("test.txt");
        fs::write(&file_path, "hello").unwrap();

        let result = confiner.validate_path(Path::new("test.txt"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_path_traversal_blocked() {
        let (_tmp, confiner) = setup_workspace();

        let result = confiner.validate_path(Path::new("/etc/passwd"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("escape attempt blocked"));
    }

    #[test]
    fn test_dotdot_traversal_blocked() {
        let (tmp, confiner) = setup_workspace();

        // Create a subdirectory
        let subdir = tmp.path().join("subdir");
        fs::create_dir(&subdir).unwrap();

        // Try to escape via ../
        let escape_path = subdir.join("../../etc/passwd");
        let result = confiner.validate_path(&escape_path);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_escape_blocked() {
        let (tmp, confiner) = setup_workspace();

        // Create a symlink pointing outside workspace
        let link_path = tmp.path().join("escape_link");
        std::os::unix::fs::symlink("/etc", &link_path).unwrap();

        let target = link_path.join("passwd");
        let result = confiner.validate_path(&target);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_file_in_workspace() {
        let (_tmp, confiner) = setup_workspace();

        let result = confiner.validate_file(Path::new("new_file.txt"));
        assert!(result.is_ok());
    }
}
