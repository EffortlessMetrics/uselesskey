use std::fmt;
use std::path::Path;

use crate::Error;
use uselesskey_core_sink::TempArtifact as RawTempArtifact;

pub struct TempArtifact {
    inner: RawTempArtifact,
}

impl fmt::Debug for TempArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TempArtifact")
            .field("path", &self.inner.path())
            .finish_non_exhaustive()
    }
}

impl TempArtifact {
    pub fn new_bytes(prefix: &str, suffix: &str, bytes: &[u8]) -> Result<Self, Error> {
        let inner = RawTempArtifact::new_bytes(prefix, suffix, bytes)?;
        Ok(Self { inner })
    }

    pub fn new_string(prefix: &str, suffix: &str, s: &str) -> Result<Self, Error> {
        let inner = RawTempArtifact::new_string(prefix, suffix, s)?;
        Ok(Self { inner })
    }

    pub fn path(&self) -> &Path {
        self.inner.path()
    }

    pub fn read_to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.inner.read_to_bytes().map_err(Error::from)
    }

    pub fn read_to_string(&self) -> Result<String, Error> {
        self.inner.read_to_string().map_err(Error::from)
    }
}
