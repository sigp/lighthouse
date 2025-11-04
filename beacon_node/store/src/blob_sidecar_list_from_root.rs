use std::sync::Arc;
use types::{BlobSidecar, BlobSidecarList, EthSpec};

#[derive(Debug, Clone)]
pub enum BlobSidecarListFromRoot<E: EthSpec> {
    /// Valid root that exists in the DB, but has no blobs associated with it.
    NoBlobs,
    /// Contains > 1 blob for the requested root.
    Blobs(BlobSidecarList<E>),
    /// No root exists in the db or cache for the requested root.
    NoRoot,
}

impl<E: EthSpec> From<BlobSidecarList<E>> for BlobSidecarListFromRoot<E> {
    fn from(value: BlobSidecarList<E>) -> Self {
        Self::Blobs(value)
    }
}

impl<E: EthSpec> BlobSidecarListFromRoot<E> {
    pub fn blobs(self) -> Option<BlobSidecarList<E>> {
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

    pub fn iter(&self) -> impl Iterator<Item = &Arc<BlobSidecar<E>>> {
        match self {
            Self::NoBlobs | Self::NoRoot => [].iter(),
            Self::Blobs(list) => list.iter(),
        }
    }
}
