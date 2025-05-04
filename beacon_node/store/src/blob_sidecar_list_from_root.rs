use crate::StoreError as Error;
use types::{BlobSidecar, BlobSidecarList, EthSpec, Hash256};

#[derive(Debug, Clone, PartialEq)]
pub enum BlobSidecarListFromRoot<E: EthSpec> {
    Present(BlobSidecarList<E>),
    Missing(Hash256),
}

impl<E: EthSpec> BlobSidecarListFromRoot<E> {
    pub fn present(blobs: BlobSidecarList<E>) -> Self {
        Self::Present(blobs)
    }

    pub fn missing(block_root: Hash256) -> Self {
        Self::Missing(block_root)
    }

    pub fn is_present(&self) -> bool {
        matches!(self, Self::Present(_))
    }

    pub fn is_missing(&self) -> bool {
        matches!(self, Self::Missing(_))
    }

    pub fn unwrap(self) -> BlobSidecarList<E> {
        match self {
            Self::Present(blobs) => blobs,
            Self::Missing(block_root) => panic!("Missing blobs for block {}", block_root),
        }
    }

    pub fn as_ref(&self) -> Option<&BlobSidecarList<E>> {
        match self {
            Self::Present(blobs) => Some(blobs),
            Self::Missing(_) => None,
        }
    }
}

impl<E: EthSpec> From<BlobSidecarList<E>> for BlobSidecarListFromRoot<E> {
    fn from(value: BlobSidecarList<E>) -> Self {
        Self::Present(value)
    }
}

impl<E: EthSpec> BlobSidecarListFromRoot<E> {
    pub fn blobs(self) -> Option<BlobSidecarList<E>> {
        match self {
            Self::Present(blobs) => Some(blobs),
            Self::Missing(_) => None,
        }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            Self::Present(blobs) => blobs.len(),
            Self::Missing(_) => 0,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<BlobSidecar<E>>> {
        match self {
            Self::Present(blobs) => blobs.iter(),
            Self::Missing(_) => [].iter(),
        }
    }
}
