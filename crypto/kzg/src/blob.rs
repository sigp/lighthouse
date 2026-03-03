use crate::{Error, BYTES_PER_BLOB};

/// A KZG blob: a byte array of `BYTES_PER_BLOB` length.
///
/// This is a local replacement for `c_kzg::Blob`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Blob {
    bytes: [u8; BYTES_PER_BLOB],
}

impl Blob {
    pub const fn new(bytes: [u8; BYTES_PER_BLOB]) -> Self {
        Self { bytes }
    }

    /// Create a `Blob` from a byte slice, returning an error if the length is wrong.
    #[allow(clippy::large_stack_frames)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BYTES_PER_BLOB {
            return Err(Error::InvalidBytesLength(format!(
                "Invalid blob length: expected {}, got {}",
                BYTES_PER_BLOB,
                bytes.len()
            )));
        }
        let mut new_bytes = [0u8; BYTES_PER_BLOB];
        new_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: new_bytes })
    }

    pub fn into_inner(self) -> [u8; BYTES_PER_BLOB] {
        self.bytes
    }
}

impl std::ops::Deref for Blob {
    type Target = [u8; BYTES_PER_BLOB];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl AsRef<[u8; BYTES_PER_BLOB]> for Blob {
    fn as_ref(&self) -> &[u8; BYTES_PER_BLOB] {
        &self.bytes
    }
}
