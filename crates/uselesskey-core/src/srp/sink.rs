//! Sink types for writing key material to temporary files or in-memory buffers.
//!
//! This crate provides [`TempArtifact`], a tempfile-backed container that holds
//! generated key material on disk and cleans up automatically on drop.  It is
//! useful when downstream libraries require `Path`-based APIs rather than
//! in-memory byte slices.

use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

/// A tempfile-backed artifact that cleans up on drop.
///
/// Useful when downstream libraries insist on `Path`-based APIs.
/// The temporary file is automatically deleted when the `TempArtifact` is dropped.
///
/// # Examples
///
/// ```
/// use uselesskey_core::srp::sink::TempArtifact;
///
/// // Create a temp file with string content
/// let temp = TempArtifact::new_string("prefix-", ".pem", "-----BEGIN KEY-----\n").unwrap();
///
/// // Get the path to pass to other libraries
/// let path = temp.path();
/// assert!(path.exists());
///
/// // Read the content back
/// let content = temp.read_to_string().unwrap();
/// assert!(content.contains("BEGIN KEY"));
///
/// // File is deleted when `temp` goes out of scope
/// ```
pub struct TempArtifact {
    /// The temp file handle; kept to ensure cleanup on drop.
    _file: NamedTempFile,
    path: PathBuf,
}

impl fmt::Debug for TempArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TempArtifact")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl TempArtifact {
    /// Create a new temporary artifact with the provided bytes.
    ///
    /// The file is created with a name like `{prefix}XXXXXX{suffix}` where `XXXXXX`
    /// is random characters.
    ///
    /// # Examples
    ///
    /// ```
    /// use uselesskey_core::srp::sink::TempArtifact;
    ///
    /// let der_bytes = vec![0x30, 0x82, 0x01, 0x22];
    /// let temp = TempArtifact::new_bytes("key-", ".der", &der_bytes).unwrap();
    ///
    /// let read_back = temp.read_to_bytes().unwrap();
    /// assert_eq!(read_back, der_bytes);
    /// ```
    pub fn new_bytes(prefix: &str, suffix: &str, bytes: &[u8]) -> std::io::Result<Self> {
        let mut builder = tempfile::Builder::new();
        builder.prefix(prefix).suffix(suffix);

        let mut file = builder.tempfile()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perm = fs::Permissions::from_mode(0o600);
            file.as_file().set_permissions(perm)?;
        }

        file.as_file_mut().write_all(bytes)?;
        file.as_file_mut().flush()?;

        let path = file.path().to_path_buf();
        Ok(Self { _file: file, path })
    }

    /// Create a new temporary artifact with the provided UTF-8 string.
    ///
    /// This is a convenience wrapper around [`new_bytes`](Self::new_bytes).
    ///
    /// # Examples
    ///
    /// ```
    /// use uselesskey_core::srp::sink::TempArtifact;
    ///
    /// let pem = "-----BEGIN PRIVATE KEY-----\nMIIBVQ==\n-----END PRIVATE KEY-----\n";
    /// let temp = TempArtifact::new_string("key-", ".pem", pem).unwrap();
    ///
    /// assert!(temp.path().extension().unwrap() == "pem");
    /// ```
    pub fn new_string(prefix: &str, suffix: &str, s: &str) -> std::io::Result<Self> {
        Self::new_bytes(prefix, suffix, s.as_bytes())
    }

    /// Returns the path to the temporary file.
    ///
    /// This path can be passed to libraries that require file paths.
    /// The file exists as long as this `TempArtifact` is alive.
    ///
    /// # Examples
    ///
    /// ```
    /// use uselesskey_core::srp::sink::TempArtifact;
    ///
    /// let temp = TempArtifact::new_string("test-", ".txt", "hello").unwrap();
    /// let path = temp.path();
    ///
    /// assert!(path.exists());
    /// assert!(path.is_file());
    /// ```
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read the file contents as bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use uselesskey_core::srp::sink::TempArtifact;
    ///
    /// let data = vec![1, 2, 3, 4, 5];
    /// let temp = TempArtifact::new_bytes("test-", ".bin", &data).unwrap();
    ///
    /// let read_back = temp.read_to_bytes().unwrap();
    /// assert_eq!(read_back, data);
    /// ```
    pub fn read_to_bytes(&self) -> std::io::Result<Vec<u8>> {
        let mut f = fs::File::open(&self.path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Ok(buf)
    }

    /// Read the file contents as a UTF-8 string.
    ///
    /// Invalid UTF-8 sequences are replaced with the Unicode replacement character.
    ///
    /// # Examples
    ///
    /// ```
    /// use uselesskey_core::srp::sink::TempArtifact;
    ///
    /// let temp = TempArtifact::new_string("test-", ".txt", "Hello, World!").unwrap();
    ///
    /// let content = temp.read_to_string().unwrap();
    /// assert_eq!(content, "Hello, World!");
    /// ```
    pub fn read_to_string(&self) -> std::io::Result<String> {
        let bytes = self.read_to_bytes()?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;
    use uselesskey_test_support::{TestResult, ensure, ensure_eq, require_ok};

    #[test]
    fn new_bytes_round_trip() -> TestResult<()> {
        let data = vec![1u8, 2, 3, 4, 5];
        let temp = require_ok(
            TempArtifact::new_bytes("uk-test-", ".bin", &data),
            "create byte artifact",
        )?;

        let read_back = require_ok(temp.read_to_bytes(), "read artifact bytes")?;
        ensure_eq!(read_back, data);
        Ok(())
    }

    #[test]
    fn new_string_round_trip() -> TestResult<()> {
        let text = "hello temp";
        let temp = require_ok(
            TempArtifact::new_string("uk-test-", ".txt", text),
            "create string artifact",
        )?;

        let read_back = require_ok(temp.read_to_string(), "read artifact text")?;
        ensure_eq!(read_back, text);
        Ok(())
    }

    #[test]
    fn read_to_string_replaces_invalid_utf8() -> TestResult<()> {
        let bytes = [0xff, 0xfe, 0xfd];
        let temp = require_ok(
            TempArtifact::new_bytes("uk-test-", ".bin", &bytes),
            "create non-UTF-8 artifact",
        )?;

        let read_back = require_ok(temp.read_to_string(), "read artifact text")?;
        ensure!(read_back.contains('\u{FFFD}'));
        Ok(())
    }

    #[test]
    fn tempfile_deleted_on_drop() -> TestResult<()> {
        let path = {
            let temp = require_ok(
                TempArtifact::new_string("uk-test-", ".txt", "cleanup"),
                "create cleanup artifact",
            )?;
            let path = temp.path().to_path_buf();
            ensure!(path.exists());
            path
        };

        let mut attempts = 0;
        loop {
            thread::sleep(Duration::from_millis(10));
            attempts += 1;
            if !path.exists() || attempts >= 5 {
                break;
            }
        }

        ensure!(!path.exists(), "tempfile should be deleted on drop");
        Ok(())
    }

    #[test]
    fn debug_includes_type_name() -> TestResult<()> {
        let temp = require_ok(
            TempArtifact::new_string("uk-test-", ".txt", "dbg"),
            "create debug artifact",
        )?;
        let dbg = format!("{:?}", temp);
        ensure!(dbg.contains("TempArtifact"));
        Ok(())
    }

    #[test]
    fn empty_bytes_round_trip() -> TestResult<()> {
        let temp = require_ok(
            TempArtifact::new_bytes("uk-test-", ".bin", &[]),
            "create empty artifact",
        )?;
        ensure!(require_ok(temp.read_to_bytes(), "read empty bytes")?.is_empty());
        ensure_eq!(require_ok(temp.read_to_string(), "read empty text")?, "");
        Ok(())
    }

    #[test]
    fn debug_does_not_include_material() -> TestResult<()> {
        let material = "test-only-material-must-not-appear-in-debug";
        let temp = require_ok(
            TempArtifact::new_string("uk-test-", ".txt", material),
            "create redaction artifact",
        )?;
        let debug = format!("{temp:?}");
        ensure!(debug.contains("TempArtifact"));
        ensure!(
            !debug.contains(material),
            "debug output must not expose material"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn tempfile_permissions_are_owner_read_write_only() -> TestResult<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = require_ok(
            TempArtifact::new_bytes("uk-test-", ".bin", b"test-only"),
            "create permission-check artifact",
        )?;
        let metadata = require_ok(fs::metadata(temp.path()), "read artifact permissions")?;
        ensure_eq!(metadata.permissions().mode() & 0o777, 0o600);
        Ok(())
    }
}
