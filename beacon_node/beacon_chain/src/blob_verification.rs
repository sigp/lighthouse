use crate::kzg_utils::{validate_blob, validate_blobs};
use educe::Educe;
use kzg::{Error as KzgError, Kzg, KzgCommitment};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;
use types::BlobSidecar;

/// Wrapper over a `BlobSidecar` for which we have completed kzg verification.
/// i.e. `verify_blob_kzg_proof(blob, commitment, proof) == true`.
#[derive(Debug, Educe, Clone, Encode, Decode)]
#[educe(PartialEq, Eq)]
#[ssz(struct_behaviour = "transparent")]
pub struct KzgVerifiedBlob {
    blob: Arc<BlobSidecar>,
    #[ssz(skip_serializing, skip_deserializing)]
    seen_timestamp: Duration,
}

impl PartialOrd for KzgVerifiedBlob {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KzgVerifiedBlob {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.blob.cmp(&other.blob)
    }
}

impl KzgVerifiedBlob {
    pub fn new(
        blob: Arc<BlobSidecar>,
        kzg: &Kzg,
        seen_timestamp: Duration,
    ) -> Result<Self, KzgError> {
        verify_kzg_for_blob(blob, kzg, seen_timestamp)
    }
    pub fn to_blob(self) -> Arc<BlobSidecar> {
        self.blob
    }
    pub fn as_blob(&self) -> &BlobSidecar {
        &self.blob
    }
    pub fn get_commitment(&self) -> &KzgCommitment {
        &self.blob.kzg_commitment
    }
    /// This is cheap as we're calling clone on an Arc
    pub fn clone_blob(&self) -> Arc<BlobSidecar> {
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
    pub fn __assumed_valid(blob: Arc<BlobSidecar>) -> Self {
        Self {
            blob,
            seen_timestamp: Duration::from_secs(0),
        }
    }
    /// Mark a blob as KZG verified. Caller must ONLY use this on blob sidecars constructed
    /// from EL blobs.
    pub fn from_execution_verified(blob: Arc<BlobSidecar>, seen_timestamp: Duration) -> Self {
        Self {
            blob,
            seen_timestamp,
        }
    }
}

/// Complete kzg verification for a `BlobSidecar`.
///
/// Returns an error if the kzg verification check fails.
pub fn verify_kzg_for_blob(
    blob: Arc<BlobSidecar>,
    kzg: &Kzg,
    seen_timestamp: Duration,
) -> Result<KzgVerifiedBlob, KzgError> {
    validate_blob(kzg, &blob.blob, blob.kzg_commitment, blob.kzg_proof)?;
    Ok(KzgVerifiedBlob {
        blob,
        seen_timestamp,
    })
}

pub struct KzgVerifiedBlobList {
    verified_blobs: Vec<KzgVerifiedBlob>,
}

impl KzgVerifiedBlobList {
    pub fn new<I: IntoIterator<Item = Arc<BlobSidecar>>>(
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
    pub fn from_verified<I: IntoIterator<Item = KzgVerifiedBlob>>(blobs: I) -> Self {
        Self {
            verified_blobs: blobs.into_iter().collect(),
        }
    }
}

impl IntoIterator for KzgVerifiedBlobList {
    type Item = KzgVerifiedBlob;
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
pub fn verify_kzg_for_blob_list<'a, I>(blob_iter: I, kzg: &'a Kzg) -> Result<(), KzgError>
where
    I: Iterator<Item = &'a Arc<BlobSidecar>>,
{
    let (blobs, (commitments, proofs)): (Vec<_>, (Vec<_>, Vec<_>)) = blob_iter
        .map(|blob| (&blob.blob, (blob.kzg_commitment, blob.kzg_proof)))
        .unzip();
    validate_blobs(kzg, commitments.as_slice(), blobs, proofs.as_slice())
}
