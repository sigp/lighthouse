use std::sync::Arc;
use types::{BlobSidecar, BlobSidecarList};

#[derive(Debug, Clone)]
pub enum BlobSidecarListFromRoot {
    /// Valid root that exists in the DB, but has no blobs associated with it.
    NoBlobs,
    /// Contains > 1 blob for the requested root.
    Blobs(BlobSidecarList),
    /// No root exists in the db or cache for the requested root.
    NoRoot,
}

impl From<BlobSidecarList> for BlobSidecarListFromRoot {
    fn from(value: BlobSidecarList) -> Self {
        Self::Blobs(value)
    }
}

impl BlobSidecarListFromRoot {
    pub fn blobs(self) -> Option<BlobSidecarList> {
        match self {
            Self::NoBlobs | Self::NoRoot => None,
            Self::Blobs(blobs) => Some(blobs),
        }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            Self::NoBlobs | Self::NoRoot => 0,
            Self::Blobs(blobs) => blobs.len(),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<BlobSidecar>> {
        match self {
            Self::NoBlobs | Self::NoRoot => [].iter(),
            Self::Blobs(list) => list.iter(),
        }
    }
}
