use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

use crate::Error;

/// A tempfile-backed artifact that cleans up on drop.
///
/// Useful when downstream libraries insist on `Path`-based APIs.
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
    pub fn new_string(prefix: &str, suffix: &str, s: &str) -> Result<Self, Error> {
        Self::new_bytes(prefix, suffix, s.as_bytes())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn read_to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut f = fs::File::open(&self.path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Ok(buf)
    }

    pub fn read_to_string(&self) -> Result<String, Error> {
        let bytes = self.read_to_bytes()?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}
