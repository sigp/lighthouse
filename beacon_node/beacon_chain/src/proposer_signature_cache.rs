//! Blocks and each of `MAX_BLOBS_PER_BLOCK` blobs should contain the same
//! proposal signature.
//!
//! This cache avoids verifying the same signature multiple times.

use crate::block_verification::BlockBlobError;
use std::collections::HashMap;
use std::marker::PhantomData;

use types::{EthSpec, Fork, Hash256, Signature, SignedBeaconBlockHeader};

#[derive(Debug)]
pub enum Error<Err: BlockBlobError> {
    InvalidSignature,
    VerificationError(Err),
}

/// Caches a valid proposal signature for a given `block_root`.
pub struct ProposerSignatureCache<E: EthSpec> {
    items: HashMap<Hash256, Signature>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> Default for ProposerSignatureCache<E> {
    fn default() -> Self {
        Self {
            items: Default::default(),
            _phantom: PhantomData,
        }
    }
}

pub enum SeenSignature {
    Seen,
    New,
}

impl<E: EthSpec> ProposerSignatureCache<E> {
    /// Observe a valid signature for the given `block_root`.
    ///
    /// Returns `Ok(SeenSignature::Seen)` if the same (block_root, signature) tuple already exists in the cache.
    /// Returns `Err(Error::InvalidSignature)` if the given signature is invalid for the block header.
    /// Returns `Ok(SeenSignature::New)` if the `(block_root, signature)` tuple did not exist in the cache
    /// after completing the signature verification using the `verification_fn`.
    pub fn observe_signature<F, Err: BlockBlobError>(
        &mut self,
        block_root: Hash256,
        signed_block_header: &SignedBeaconBlockHeader,
        fork: &Fork,
        verification_fn: F,
    ) -> Result<SeenSignature, Error<Err>>
    where
        F: Fn(&SignedBeaconBlockHeader, &Fork) -> Result<(), Err>,
    {
        let signature = signed_block_header.signature.clone();
        if let Some(cached_signature) = self.items.get(&block_root) {
            if *cached_signature == signature {
                Ok(SeenSignature::Seen)
            } else {
                // We always verify the proposer signature before adding it to the cache.
                // Hence, if the signature does not match, it implies that the given `signed_block_header`
                // has an invalid signature.
                Err(Error::InvalidSignature)
            }
        } else {
            // (block_root, signature) tuple does not exist in cache, run the verification
            // and add to cache if verification passes
            verification_fn(signed_block_header, fork).map_err(Error::VerificationError)?;
            self.items.insert(block_root, signature);
            Ok(SeenSignature::New)
        }
    }

    /// Checks if the `(block_root, signature)` tuple exists in the cache.
    ///
    /// Returns `Ok(true)` if it exists and the signature matches the verified value in the cache.
    /// Returns `Ok(false)` if it does not exist.
    /// Returns an error if it exists but the signature is different.
    pub fn signature_exists<Err: BlockBlobError>(
        &self,
        block_root: Hash256,
        signed_block_header: &SignedBeaconBlockHeader,
    ) -> Result<bool, Error<Err>> {
        let signature = signed_block_header.signature.clone();
        if let Some(cached_signature) = self.items.get(&block_root) {
            if *cached_signature == signature {
                Ok(true)
            } else {
                // We always verify the proposer signature before adding it to the cache.
                // Hence, if the signature does not match, it implies that the given `signed_block_header`
                // has an invalid signature.
                Err(Error::InvalidSignature)
            }
        } else {
            Ok(false)
        }
    }
}
