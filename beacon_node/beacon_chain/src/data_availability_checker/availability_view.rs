use super::child_components::ChildComponents;
use super::state_lru_cache::DietAvailabilityPendingExecutedBlock;
use crate::blob_verification::KzgVerifiedBlob;
use crate::block_verification_types::AsBlock;
use crate::data_availability_checker::overflow_lru_cache::PendingComponents;
use crate::data_availability_checker::ProcessingComponents;
use kzg::KzgCommitment;
use ssz_types::FixedVector;
use std::sync::Arc;
use types::beacon_block_body::KzgCommitments;
use types::{BlobSidecar, EthSpec, SignedBeaconBlock};

/// Defines an interface for managing data availability with two key invariants:
///
/// 1. If we haven't seen a block yet, we will insert the first blob for a given (block_root, index)
///    but we won't insert subsequent blobs for the same (block_root, index) if they have a different
///    commitment.
/// 2. On block insertion, any non-matching blob commitments are evicted.
///
/// Types implementing this trait can be used for validating and managing availability
/// of blocks and blobs in a cache-like data structure.
pub trait AvailabilityView<E: EthSpec> {
    /// The type representing a block in the implementation.
    type BlockType: GetCommitments<E>;

    /// The type representing a blob in the implementation. Must implement `Clone`.
    type BlobType: Clone + GetCommitment<E>;

    /// Returns an immutable reference to the cached block.
    fn get_cached_block(&self) -> &Option<Self::BlockType>;

    /// Returns an immutable reference to the fixed vector of cached blobs.
    fn get_cached_blobs(&self) -> &FixedVector<Option<Self::BlobType>, E::MaxBlobsPerBlock>;

    /// Returns a mutable reference to the cached block.
    fn get_cached_block_mut(&mut self) -> &mut Option<Self::BlockType>;

    /// Returns a mutable reference to the fixed vector of cached blobs.
    fn get_cached_blobs_mut(
        &mut self,
    ) -> &mut FixedVector<Option<Self::BlobType>, E::MaxBlobsPerBlock>;

    /// Checks if a block exists in the cache.
    ///
    /// Returns:
    /// - `true` if a block exists.
    /// - `false` otherwise.
    fn block_exists(&self) -> bool {
        self.get_cached_block().is_some()
    }

    /// Checks if a blob exists at the given index in the cache.
    ///
    /// Returns:
    /// - `true` if a blob exists at the given index.
    /// - `false` otherwise.
    fn blob_exists(&self, blob_index: usize) -> bool {
        self.get_cached_blobs()
            .get(blob_index)
            .map(|b| b.is_some())
            .unwrap_or(false)
    }

    /// Returns the number of blobs that are expected to be present. Returns `None` if we don't have a
    /// block.
    ///
    /// This corresponds to the number of commitments that are present in a block.
    fn num_expected_blobs(&self) -> Option<usize> {
        self.get_cached_block()
            .as_ref()
            .map(|b| b.get_commitments().len())
    }

    /// Returns the number of blobs that have been received and are stored in the cache.
    fn num_received_blobs(&self) -> usize {
        self.get_cached_blobs().iter().flatten().count()
    }

    /// Inserts a block into the cache.
    fn insert_block(&mut self, block: Self::BlockType) {
        *self.get_cached_block_mut() = Some(block)
    }

    /// Inserts a blob at a specific index in the cache.
    ///
    /// Existing blob at the index will be replaced.
    fn insert_blob_at_index(&mut self, blob_index: usize, blob: Self::BlobType) {
        if let Some(b) = self.get_cached_blobs_mut().get_mut(blob_index) {
            *b = Some(blob);
        }
    }

    /// Merges a given set of blobs into the cache.
    ///
    /// Blobs are only inserted if:
    /// 1. The blob entry at the index is empty and no block exists.
    /// 2. The block exists and its commitment matches the blob's commitment.
    fn merge_blobs(&mut self, blobs: FixedVector<Option<Self::BlobType>, E::MaxBlobsPerBlock>) {
        for (index, blob) in blobs.iter().cloned().enumerate() {
            let Some(blob) = blob else { continue };
            self.merge_single_blob(index, blob);
        }
    }

    /// Merges a single blob into the cache.
    ///
    /// Blobs are only inserted if:
    /// 1. The blob entry at the index is empty and no block exists, or
    /// 2. The block exists and its commitment matches the blob's commitment.
    fn merge_single_blob(&mut self, index: usize, blob: Self::BlobType) {
        let commitment = *blob.get_commitment();
        if let Some(cached_block) = self.get_cached_block() {
            let block_commitment_opt = cached_block.get_commitments().get(index).copied();
            if let Some(block_commitment) = block_commitment_opt {
                if block_commitment == commitment {
                    self.insert_blob_at_index(index, blob)
                }
            }
        } else if !self.blob_exists(index) {
            self.insert_blob_at_index(index, blob)
        }
    }

    /// Inserts a new block and revalidates the existing blobs against it.
    ///
    /// Blobs that don't match the new block's commitments are evicted.
    fn merge_block(&mut self, block: Self::BlockType) {
        self.insert_block(block);
        let reinsert = std::mem::take(self.get_cached_blobs_mut());
        self.merge_blobs(reinsert);
    }

    /// Checks if the block and all of its expected blobs are available in the cache.
    ///
    /// Returns `true` if both the block exists and the number of received blobs matches the number
    /// of expected blobs.
    fn is_available(&self) -> bool {
        if let Some(num_expected_blobs) = self.num_expected_blobs() {
            num_expected_blobs == self.num_received_blobs()
        } else {
            false
        }
    }
}

/// Implements the `AvailabilityView` trait for a given struct.
///
/// - `$struct_name`: The name of the struct for which to implement `AvailabilityView`.
/// - `$block_type`: The type to use for `BlockType` in the `AvailabilityView` trait.
/// - `$blob_type`: The type to use for `BlobType` in the `AvailabilityView` trait.
/// - `$block_field`: The field name in the struct that holds the cached block.
/// - `$blob_field`: The field name in the struct that holds the cached blobs.
#[macro_export]
macro_rules! impl_availability_view {
    ($struct_name:ident, $block_type:ty, $blob_type:ty, $block_field:ident, $blob_field:ident) => {
        impl<E: EthSpec> AvailabilityView<E> for $struct_name<E> {
            type BlockType = $block_type;
            type BlobType = $blob_type;

            fn get_cached_block(&self) -> &Option<Self::BlockType> {
                &self.$block_field
            }

            fn get_cached_blobs(
                &self,
            ) -> &FixedVector<Option<Self::BlobType>, E::MaxBlobsPerBlock> {
                &self.$blob_field
            }

            fn get_cached_block_mut(&mut self) -> &mut Option<Self::BlockType> {
                &mut self.$block_field
            }

            fn get_cached_blobs_mut(
                &mut self,
            ) -> &mut FixedVector<Option<Self::BlobType>, E::MaxBlobsPerBlock> {
                &mut self.$blob_field
            }
        }
    };
}

impl_availability_view!(
    ProcessingComponents,
    Arc<SignedBeaconBlock<E>>,
    KzgCommitment,
    block,
    blob_commitments
);

impl_availability_view!(
    PendingComponents,
    DietAvailabilityPendingExecutedBlock<E>,
    KzgVerifiedBlob<E>,
    executed_block,
    verified_blobs
);

impl_availability_view!(
    ChildComponents,
    Arc<SignedBeaconBlock<E>>,
    Arc<BlobSidecar<E>>,
    downloaded_block,
    downloaded_blobs
);

pub trait GetCommitments<E: EthSpec> {
    fn get_commitments(&self) -> KzgCommitments<E>;
}

pub trait GetCommitment<E: EthSpec> {
    fn get_commitment(&self) -> &KzgCommitment;
}

impl<E: EthSpec> GetCommitment<E> for KzgCommitment {
    fn get_commitment(&self) -> &KzgCommitment {
        self
    }
}

// These implementations are required to implement `AvailabilityView` for `PendingComponents`.
impl<E: EthSpec> GetCommitments<E> for DietAvailabilityPendingExecutedBlock<E> {
    fn get_commitments(&self) -> KzgCommitments<E> {
        self.as_block()
            .message()
            .body()
            .blob_kzg_commitments()
            .cloned()
            .unwrap_or_default()
    }
}

impl<E: EthSpec> GetCommitment<E> for KzgVerifiedBlob<E> {
    fn get_commitment(&self) -> &KzgCommitment {
        &self.as_blob().kzg_commitment
    }
}

// These implementations are required to implement `AvailabilityView` for `ChildComponents`.
impl<E: EthSpec> GetCommitments<E> for Arc<SignedBeaconBlock<E>> {
    fn get_commitments(&self) -> KzgCommitments<E> {
        self.message()
            .body()
            .blob_kzg_commitments()
            .ok()
            .cloned()
            .unwrap_or_default()
    }
}
impl<E: EthSpec> GetCommitment<E> for Arc<BlobSidecar<E>> {
    fn get_commitment(&self) -> &KzgCommitment {
        &self.kzg_commitment
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::block_verification_types::BlockImportData;
    use crate::eth1_finalization_cache::Eth1FinalizationData;
    use crate::test_utils::{generate_rand_block_and_blobs, NumBlobs};
    use crate::AvailabilityPendingExecutedBlock;
    use crate::PayloadVerificationOutcome;
    use fork_choice::PayloadVerificationStatus;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use state_processing::ConsensusContext;
    use types::test_utils::TestRandom;
    use types::{BeaconState, ChainSpec, ForkName, MainnetEthSpec, Slot};

    type E = MainnetEthSpec;

    type Setup<E> = (
        SignedBeaconBlock<E>,
        FixedVector<Option<Arc<BlobSidecar<E>>>, <E as EthSpec>::MaxBlobsPerBlock>,
        FixedVector<Option<Arc<BlobSidecar<E>>>, <E as EthSpec>::MaxBlobsPerBlock>,
    );

    pub fn pre_setup() -> Setup<E> {
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF0BAD5EEDu64);
        let (block, blobs_vec) =
            generate_rand_block_and_blobs::<E>(ForkName::Deneb, NumBlobs::Random, &mut rng);
        let mut blobs: FixedVector<_, <E as EthSpec>::MaxBlobsPerBlock> = FixedVector::default();

        for blob in blobs_vec {
            if let Some(b) = blobs.get_mut(blob.index as usize) {
                *b = Some(Arc::new(blob));
            }
        }

        let mut invalid_blobs: FixedVector<
            Option<Arc<BlobSidecar<E>>>,
            <E as EthSpec>::MaxBlobsPerBlock,
        > = FixedVector::default();
        for (index, blob) in blobs.iter().enumerate() {
            if let Some(invalid_blob) = blob {
                let mut blob_copy = invalid_blob.as_ref().clone();
                blob_copy.kzg_commitment = KzgCommitment::random_for_test(&mut rng);
                *invalid_blobs.get_mut(index).unwrap() = Some(Arc::new(blob_copy));
            }
        }

        (block, blobs, invalid_blobs)
    }

    type ProcessingViewSetup<E> = (
        Arc<SignedBeaconBlock<E>>,
        FixedVector<Option<KzgCommitment>, <E as EthSpec>::MaxBlobsPerBlock>,
        FixedVector<Option<KzgCommitment>, <E as EthSpec>::MaxBlobsPerBlock>,
    );

    pub fn setup_processing_components(
        block: SignedBeaconBlock<E>,
        valid_blobs: FixedVector<Option<Arc<BlobSidecar<E>>>, <E as EthSpec>::MaxBlobsPerBlock>,
        invalid_blobs: FixedVector<Option<Arc<BlobSidecar<E>>>, <E as EthSpec>::MaxBlobsPerBlock>,
    ) -> ProcessingViewSetup<E> {
        let blobs = FixedVector::from(
            valid_blobs
                .iter()
                .map(|blob_opt| blob_opt.as_ref().map(|blob| blob.kzg_commitment))
                .collect::<Vec<_>>(),
        );
        let invalid_blobs = FixedVector::from(
            invalid_blobs
                .iter()
                .map(|blob_opt| blob_opt.as_ref().map(|blob| blob.kzg_commitment))
                .collect::<Vec<_>>(),
        );
        (Arc::new(block), blobs, invalid_blobs)
    }

    type PendingComponentsSetup<E> = (
        DietAvailabilityPendingExecutedBlock<E>,
        FixedVector<Option<KzgVerifiedBlob<E>>, <E as EthSpec>::MaxBlobsPerBlock>,
        FixedVector<Option<KzgVerifiedBlob<E>>, <E as EthSpec>::MaxBlobsPerBlock>,
    );

    pub fn setup_pending_components(
        block: SignedBeaconBlock<E>,
        valid_blobs: FixedVector<Option<Arc<BlobSidecar<E>>>, <E as EthSpec>::MaxBlobsPerBlock>,
        invalid_blobs: FixedVector<Option<Arc<BlobSidecar<E>>>, <E as EthSpec>::MaxBlobsPerBlock>,
    ) -> PendingComponentsSetup<E> {
        let blobs = FixedVector::from(
            valid_blobs
                .iter()
                .map(|blob_opt| {
                    blob_opt
                        .as_ref()
                        .map(|blob| KzgVerifiedBlob::__assumed_valid(blob.clone()))
                })
                .collect::<Vec<_>>(),
        );
        let invalid_blobs = FixedVector::from(
            invalid_blobs
                .iter()
                .map(|blob_opt| {
                    blob_opt
                        .as_ref()
                        .map(|blob| KzgVerifiedBlob::__assumed_valid(blob.clone()))
                })
                .collect::<Vec<_>>(),
        );
        let dummy_parent = block.clone_as_blinded();
        let block = AvailabilityPendingExecutedBlock {
            block: Arc::new(block),
            import_data: BlockImportData {
                block_root: Default::default(),
                state: BeaconState::new(0, Default::default(), &ChainSpec::minimal()),
                parent_block: dummy_parent,
                parent_eth1_finalization_data: Eth1FinalizationData {
                    eth1_data: Default::default(),
                    eth1_deposit_index: 0,
                },
                confirmed_state_roots: vec![],
                consensus_context: ConsensusContext::new(Slot::new(0)),
            },
            payload_verification_outcome: PayloadVerificationOutcome {
                payload_verification_status: PayloadVerificationStatus::Verified,
                is_valid_merge_transition_block: false,
            },
        };
        (block.into(), blobs, invalid_blobs)
    }

    type ChildComponentsSetup<E> = (
        Arc<SignedBeaconBlock<E>>,
        FixedVector<Option<Arc<BlobSidecar<E>>>, <E as EthSpec>::MaxBlobsPerBlock>,
        FixedVector<Option<Arc<BlobSidecar<E>>>, <E as EthSpec>::MaxBlobsPerBlock>,
    );

    pub fn setup_child_components(
        block: SignedBeaconBlock<E>,
        valid_blobs: FixedVector<Option<Arc<BlobSidecar<E>>>, <E as EthSpec>::MaxBlobsPerBlock>,
        invalid_blobs: FixedVector<Option<Arc<BlobSidecar<E>>>, <E as EthSpec>::MaxBlobsPerBlock>,
    ) -> ChildComponentsSetup<E> {
        let blobs = FixedVector::from(valid_blobs.into_iter().cloned().collect::<Vec<_>>());
        let invalid_blobs =
            FixedVector::from(invalid_blobs.into_iter().cloned().collect::<Vec<_>>());
        (Arc::new(block), blobs, invalid_blobs)
    }

    pub fn assert_cache_consistent<V: AvailabilityView<E>>(cache: V) {
        if let Some(cached_block) = cache.get_cached_block() {
            let cached_block_commitments = cached_block.get_commitments();
            for index in 0..E::max_blobs_per_block() {
                let block_commitment = cached_block_commitments.get(index).copied();
                let blob_commitment_opt = cache.get_cached_blobs().get(index).unwrap();
                let blob_commitment = blob_commitment_opt.as_ref().map(|b| *b.get_commitment());
                assert_eq!(block_commitment, blob_commitment);
            }
        } else {
            panic!("No cached block")
        }
    }

    pub fn assert_empty_blob_cache<V: AvailabilityView<E>>(cache: V) {
        for blob in cache.get_cached_blobs().iter() {
            assert!(blob.is_none());
        }
    }

    #[macro_export]
    macro_rules! generate_tests {
        ($module_name:ident, $type_name:ty, $block_field:ident, $blob_field:ident, $setup_fn:ident) => {
            mod $module_name {
                use super::*;
                use types::Hash256;

                #[test]
                fn valid_block_invalid_blobs_valid_blobs() {
                    let (block_commitments, blobs, random_blobs) = pre_setup();
                    let (block_commitments, blobs, random_blobs) =
                        $setup_fn(block_commitments, blobs, random_blobs);
                    let block_root = Hash256::zero();
                    let mut cache = <$type_name>::empty(block_root);
                    cache.merge_block(block_commitments);
                    cache.merge_blobs(random_blobs);
                    cache.merge_blobs(blobs);

                    assert_cache_consistent(cache);
                }

                #[test]
                fn invalid_blobs_block_valid_blobs() {
                    let (block_commitments, blobs, random_blobs) = pre_setup();
                    let (block_commitments, blobs, random_blobs) =
                        $setup_fn(block_commitments, blobs, random_blobs);
                    let block_root = Hash256::zero();
                    let mut cache = <$type_name>::empty(block_root);
                    cache.merge_blobs(random_blobs);
                    cache.merge_block(block_commitments);
                    cache.merge_blobs(blobs);

                    assert_cache_consistent(cache);
                }

                #[test]
                fn invalid_blobs_valid_blobs_block() {
                    let (block_commitments, blobs, random_blobs) = pre_setup();
                    let (block_commitments, blobs, random_blobs) =
                        $setup_fn(block_commitments, blobs, random_blobs);

                    let block_root = Hash256::zero();
                    let mut cache = <$type_name>::empty(block_root);
                    cache.merge_blobs(random_blobs);
                    cache.merge_blobs(blobs);
                    cache.merge_block(block_commitments);

                    assert_empty_blob_cache(cache);
                }

                #[test]
                fn block_valid_blobs_invalid_blobs() {
                    let (block_commitments, blobs, random_blobs) = pre_setup();
                    let (block_commitments, blobs, random_blobs) =
                        $setup_fn(block_commitments, blobs, random_blobs);

                    let block_root = Hash256::zero();
                    let mut cache = <$type_name>::empty(block_root);
                    cache.merge_block(block_commitments);
                    cache.merge_blobs(blobs);
                    cache.merge_blobs(random_blobs);

                    assert_cache_consistent(cache);
                }

                #[test]
                fn valid_blobs_block_invalid_blobs() {
                    let (block_commitments, blobs, random_blobs) = pre_setup();
                    let (block_commitments, blobs, random_blobs) =
                        $setup_fn(block_commitments, blobs, random_blobs);

                    let block_root = Hash256::zero();
                    let mut cache = <$type_name>::empty(block_root);
                    cache.merge_blobs(blobs);
                    cache.merge_block(block_commitments);
                    cache.merge_blobs(random_blobs);

                    assert_cache_consistent(cache);
                }

                #[test]
                fn valid_blobs_invalid_blobs_block() {
                    let (block_commitments, blobs, random_blobs) = pre_setup();
                    let (block_commitments, blobs, random_blobs) =
                        $setup_fn(block_commitments, blobs, random_blobs);

                    let block_root = Hash256::zero();
                    let mut cache = <$type_name>::empty(block_root);
                    cache.merge_blobs(blobs);
                    cache.merge_blobs(random_blobs);
                    cache.merge_block(block_commitments);

                    assert_cache_consistent(cache);
                }
            }
        };
    }

    generate_tests!(
        processing_components_tests,
        ProcessingComponents::<E>,
        kzg_commitments,
        processing_blobs,
        setup_processing_components
    );
    generate_tests!(
        pending_components_tests,
        PendingComponents<E>,
        executed_block,
        verified_blobs,
        setup_pending_components
    );
    generate_tests!(
        child_component_tests,
        ChildComponents::<E>,
        downloaded_block,
        downloaded_blobs,
        setup_child_components
    );
}
