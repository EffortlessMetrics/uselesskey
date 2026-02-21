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

#[cfg(test)]
mod tests {
    use super::TempArtifact;

    #[test]
    fn temp_artifact_string_round_trips_and_debug_mentions_path() {
        let artifact = TempArtifact::new_string("uselesskey-", ".unit.txt", "hello-world")
            .expect("create TempArtifact");

        let dbg = format!("{artifact:?}");
        assert!(dbg.contains("TempArtifact"));
        assert!(dbg.contains(".unit.txt"));

        let text = artifact.read_to_string().expect("read_to_string");
        assert_eq!(text, "hello-world");
    }

    #[test]
    fn temp_artifact_bytes_round_trip() {
        let bytes = vec![0x01, 0x02, 0x03, 0xFF];
        let artifact = TempArtifact::new_bytes("uselesskey-", ".unit.bin", &bytes)
            .expect("create TempArtifact");

        let read = artifact.read_to_bytes().expect("read_to_bytes");
        assert_eq!(read, bytes);
    }
}
