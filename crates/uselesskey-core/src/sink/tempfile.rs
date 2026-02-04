use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

use crate::Error;

/// A tempfile-backed artifact that cleans up on drop.
///
/// Useful when downstream libraries insist on `Path`-based APIs.
/// The temporary file is automatically deleted when the `TempArtifact` is dropped.
///
/// # Examples
///
/// ```
/// use uselesskey_core::sink::TempArtifact;
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
    /// use uselesskey_core::sink::TempArtifact;
    ///
    /// let der_bytes = vec![0x30, 0x82, 0x01, 0x22];
    /// let temp = TempArtifact::new_bytes("key-", ".der", &der_bytes).unwrap();
    ///
    /// let read_back = temp.read_to_bytes().unwrap();
    /// assert_eq!(read_back, der_bytes);
    /// ```
    pub fn new_bytes(prefix: &str, suffix: &str, bytes: &[u8]) -> Result<Self, Error> {
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
    /// use uselesskey_core::sink::TempArtifact;
    ///
    /// let pem = "-----BEGIN PRIVATE KEY-----\nMIIBVQ==\n-----END PRIVATE KEY-----\n";
    /// let temp = TempArtifact::new_string("key-", ".pem", pem).unwrap();
    ///
    /// assert!(temp.path().extension().unwrap() == "pem");
    /// ```
    pub fn new_string(prefix: &str, suffix: &str, s: &str) -> Result<Self, Error> {
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
    /// use uselesskey_core::sink::TempArtifact;
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
    /// use uselesskey_core::sink::TempArtifact;
    ///
    /// let data = vec![1, 2, 3, 4, 5];
    /// let temp = TempArtifact::new_bytes("test-", ".bin", &data).unwrap();
    ///
    /// let read_back = temp.read_to_bytes().unwrap();
    /// assert_eq!(read_back, data);
    /// ```
    pub fn read_to_bytes(&self) -> Result<Vec<u8>, Error> {
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
    /// use uselesskey_core::sink::TempArtifact;
    ///
    /// let temp = TempArtifact::new_string("test-", ".txt", "Hello, World!").unwrap();
    ///
    /// let content = temp.read_to_string().unwrap();
    /// assert_eq!(content, "Hello, World!");
    /// ```
    pub fn read_to_string(&self) -> Result<String, Error> {
        let bytes = self.read_to_bytes()?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}
