use crate::kzg_utils::{validate_blob, validate_blobs};
use educe::Educe;
use kzg::{Error as KzgError, Kzg, KzgCommitment};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;
use types::{BlobSidecar, EthSpec};

/// Wrapper over a `BlobSidecar` for which we have completed kzg verification.
/// i.e. `verify_blob_kzg_proof(blob, commitment, proof) == true`.
#[derive(Debug, Educe, Clone, Encode, Decode)]
#[educe(PartialEq, Eq)]
#[ssz(struct_behaviour = "transparent")]
pub struct KzgVerifiedBlob<E: EthSpec> {
    blob: Arc<BlobSidecar<E>>,
    #[ssz(skip_serializing, skip_deserializing)]
    seen_timestamp: Duration,
}

impl<E: EthSpec> PartialOrd for KzgVerifiedBlob<E> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<E: EthSpec> Ord for KzgVerifiedBlob<E> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.blob.cmp(&other.blob)
    }
}

impl<E: EthSpec> KzgVerifiedBlob<E> {
    pub fn new(
        blob: Arc<BlobSidecar<E>>,
        kzg: &Kzg,
        seen_timestamp: Duration,
    ) -> Result<Self, KzgError> {
        verify_kzg_for_blob(blob, kzg, seen_timestamp)
    }
    pub fn to_blob(self) -> Arc<BlobSidecar<E>> {
        self.blob
    }
    pub fn as_blob(&self) -> &BlobSidecar<E> {
        &self.blob
    }
    pub fn get_commitment(&self) -> &KzgCommitment {
        &self.blob.kzg_commitment
    }
    /// This is cheap as we're calling clone on an Arc
    pub fn clone_blob(&self) -> Arc<BlobSidecar<E>> {
        self.blob.clone()
    }
    pub fn blob_index(&self) -> u64 {
        self.blob.index
    }
    pub fn seen_timestamp(&self) -> Duration {
        self.seen_timestamp
    }
    /// Construct a `KzgVerifiedBlob` that is assumed to be valid.
    ///
    /// This should ONLY be used for testing.
    #[cfg(test)]
    pub fn __assumed_valid(blob: Arc<BlobSidecar<E>>) -> Self {
        Self {
            blob,
            seen_timestamp: Duration::from_secs(0),
        }
    }
    /// Mark a blob as KZG verified. Caller must ONLY use this on blob sidecars constructed
    /// from EL blobs.
    pub fn from_execution_verified(blob: Arc<BlobSidecar<E>>, seen_timestamp: Duration) -> Self {
        Self {
            blob,
            seen_timestamp,
        }
    }
}

/// Complete kzg verification for a `BlobSidecar`.
///
/// Returns an error if the kzg verification check fails.
pub fn verify_kzg_for_blob<E: EthSpec>(
    blob: Arc<BlobSidecar<E>>,
    kzg: &Kzg,
    seen_timestamp: Duration,
) -> Result<KzgVerifiedBlob<E>, KzgError> {
    validate_blob::<E>(kzg, &blob.blob, blob.kzg_commitment, blob.kzg_proof)?;
    Ok(KzgVerifiedBlob {
        blob,
        seen_timestamp,
    })
}

pub struct KzgVerifiedBlobList<E: EthSpec> {
    verified_blobs: Vec<KzgVerifiedBlob<E>>,
}

impl<E: EthSpec> KzgVerifiedBlobList<E> {
    pub fn new<I: IntoIterator<Item = Arc<BlobSidecar<E>>>>(
        blob_list: I,
        kzg: &Kzg,
        seen_timestamp: Duration,
    ) -> Result<Self, KzgError> {
        let blobs = blob_list
            .into_iter()
            .map(|blob| KzgVerifiedBlob {
                blob,
                seen_timestamp,
            })
            .collect::<Vec<_>>();
        verify_kzg_for_blob_list(blobs.iter().map(|b| &b.blob), kzg)?;
        Ok(Self {
            verified_blobs: blobs,
        })
    }

    /// Create a `KzgVerifiedBlobList` from `blobs` that are already KZG verified.
    pub fn from_verified<I: IntoIterator<Item = KzgVerifiedBlob<E>>>(blobs: I) -> Self {
        Self {
            verified_blobs: blobs.into_iter().collect(),
        }
    }
}

impl<E: EthSpec> IntoIterator for KzgVerifiedBlobList<E> {
    type Item = KzgVerifiedBlob<E>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.verified_blobs.into_iter()
    }
}

/// Complete kzg verification for a list of `BlobSidecar`s.
/// Returns an error if any of the `BlobSidecar`s fails kzg verification.
///
/// Note: This function should be preferred over calling `verify_kzg_for_blob`
/// in a loop since this function kzg verifies a list of blobs more efficiently.
#[instrument(skip_all, level = "debug")]
pub fn verify_kzg_for_blob_list<'a, E: EthSpec, I>(
    blob_iter: I,
    kzg: &'a Kzg,
) -> Result<(), KzgError>
where
    I: Iterator<Item = &'a Arc<BlobSidecar<E>>>,
{
    let (blobs, (commitments, proofs)): (Vec<_>, (Vec<_>, Vec<_>)) = blob_iter
        .map(|blob| (&blob.blob, (blob.kzg_commitment, blob.kzg_proof)))
        .unzip();
    validate_blobs::<E>(kzg, commitments.as_slice(), blobs, proofs.as_slice())
}
