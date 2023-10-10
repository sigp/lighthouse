use crate::{block_hash::calculate_execution_block_hash, metrics, Error};

use crate::versioned_hashes::verify_versioned_hashes;
use state_processing::per_block_processing::deneb::kzg_commitment_to_versioned_hash;
use superstruct::superstruct;
use types::{
    BeaconBlockRef, BeaconStateError, EthSpec, ExecutionBlockHash, ExecutionPayload,
    ExecutionPayloadRef, Hash256, VersionedHash,
};
use types::{ExecutionPayloadCapella, ExecutionPayloadDeneb, ExecutionPayloadMerge};

#[superstruct(
    variants(Merge, Capella, Deneb),
    variant_attributes(derive(Clone, Debug, PartialEq),),
    map_into(ExecutionPayload),
    map_ref_into(ExecutionPayloadRef),
    cast_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    )
)]
#[derive(Clone, Debug, PartialEq)]
pub struct NewPayloadRequest<'block, E: EthSpec> {
    #[superstruct(only(Merge), partial_getter(rename = "execution_payload_merge"))]
    pub execution_payload: &'block ExecutionPayloadMerge<E>,
    #[superstruct(only(Capella), partial_getter(rename = "execution_payload_capella"))]
    pub execution_payload: &'block ExecutionPayloadCapella<E>,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_deneb"))]
    pub execution_payload: &'block ExecutionPayloadDeneb<E>,
    #[superstruct(only(Deneb))]
    pub versioned_hashes: Vec<VersionedHash>,
    #[superstruct(only(Deneb))]
    pub parent_beacon_block_root: Hash256,
}

impl<'block, E: EthSpec> NewPayloadRequest<'block, E> {
    pub fn parent_hash(&self) -> ExecutionBlockHash {
        match self {
            Self::Merge(payload) => payload.execution_payload.parent_hash,
            Self::Capella(payload) => payload.execution_payload.parent_hash,
            Self::Deneb(payload) => payload.execution_payload.parent_hash,
        }
    }

    pub fn block_hash(&self) -> ExecutionBlockHash {
        match self {
            Self::Merge(payload) => payload.execution_payload.block_hash,
            Self::Capella(payload) => payload.execution_payload.block_hash,
            Self::Deneb(payload) => payload.execution_payload.block_hash,
        }
    }

    pub fn block_number(&self) -> u64 {
        match self {
            Self::Merge(payload) => payload.execution_payload.block_number,
            Self::Capella(payload) => payload.execution_payload.block_number,
            Self::Deneb(payload) => payload.execution_payload.block_number,
        }
    }

    pub fn execution_payload_ref(&self) -> ExecutionPayloadRef<'block, E> {
        match self {
            Self::Merge(request) => ExecutionPayloadRef::Merge(request.execution_payload),
            Self::Capella(request) => ExecutionPayloadRef::Capella(request.execution_payload),
            Self::Deneb(request) => ExecutionPayloadRef::Deneb(request.execution_payload),
        }
    }

    pub fn into_execution_payload(self) -> ExecutionPayload<E> {
        match self {
            Self::Merge(request) => ExecutionPayload::Merge(request.execution_payload.clone()),
            Self::Capella(request) => ExecutionPayload::Capella(request.execution_payload.clone()),
            Self::Deneb(request) => ExecutionPayload::Deneb(request.execution_payload.clone()),
        }
    }

    /// Performs the required verifications of the payload when the chain is optimistically syncing.
    ///
    /// ## Specification
    ///
    /// Performs the verifications in the `verify_and_notify_new_payload` function:
    ///
    /// https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.2/specs/deneb/beacon-chain.md#modified-verify_and_notify_new_payload
    pub fn perform_optimistic_sync_verifications(&self) -> Result<(), Error> {
        self.verfiy_payload_block_hash()?;
        self.verify_versioned_hashes()?;

        Ok(())
    }

    /// Verify the block hash is consistent locally within Lighthouse.
    ///
    /// ## Specification
    ///
    /// Equivalent to `is_valid_block_hash` in the spec:
    /// https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.2/specs/deneb/beacon-chain.md#is_valid_block_hash
    pub fn verfiy_payload_block_hash(&self) -> Result<(), Error> {
        let payload = self.execution_payload_ref();
        let parent_beacon_block_root = self.parent_beacon_block_root().ok().cloned();

        let _timer = metrics::start_timer(&metrics::EXECUTION_LAYER_VERIFY_BLOCK_HASH);

        let (header_hash, rlp_transactions_root) =
            calculate_execution_block_hash(payload, parent_beacon_block_root);

        if header_hash != self.block_hash() {
            return Err(Error::BlockHashMismatch {
                computed: header_hash,
                payload: payload.block_hash(),
                transactions_root: rlp_transactions_root,
            });
        }

        Ok(())
    }

    /// Verify the version hashes computed by the blob transactions match the version hashes computed from the commitments
    ///
    /// ## Specification
    ///
    /// Equivalent to `is_valid_versioned_hashes` in the spec:
    /// https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.2/specs/deneb/beacon-chain.md#is_valid_versioned_hashes
    pub fn verify_versioned_hashes(&self) -> Result<(), Error> {
        if let Ok(versioned_hashes) = self.versioned_hashes() {
            verify_versioned_hashes(self.execution_payload_ref(), versioned_hashes)
                .map_err(Error::VerifyingVersionedHashes)?;
        }
        Ok(())
    }
}

impl<'a, E: EthSpec> TryFrom<BeaconBlockRef<'a, E>> for NewPayloadRequest<'a, E> {
    type Error = BeaconStateError;

    fn try_from(block: BeaconBlockRef<'a, E>) -> Result<Self, Self::Error> {
        match block {
            BeaconBlockRef::Base(_) | BeaconBlockRef::Altair(_) => {
                Err(Self::Error::IncorrectStateVariant)
            }
            BeaconBlockRef::Merge(block_ref) => Ok(Self::Merge(NewPayloadRequestMerge {
                execution_payload: &block_ref.body.execution_payload.execution_payload,
            })),
            BeaconBlockRef::Capella(block_ref) => Ok(Self::Capella(NewPayloadRequestCapella {
                execution_payload: &block_ref.body.execution_payload.execution_payload,
            })),
            BeaconBlockRef::Deneb(block_ref) => Ok(Self::Deneb(NewPayloadRequestDeneb {
                execution_payload: &block_ref.body.execution_payload.execution_payload,
                versioned_hashes: block_ref
                    .body
                    .blob_kzg_commitments
                    .iter()
                    .map(kzg_commitment_to_versioned_hash)
                    .collect(),
                parent_beacon_block_root: block_ref.parent_root,
            })),
        }
    }
}

impl<'a, E: EthSpec> TryFrom<ExecutionPayloadRef<'a, E>> for NewPayloadRequest<'a, E> {
    type Error = BeaconStateError;

    fn try_from(payload: ExecutionPayloadRef<'a, E>) -> Result<Self, Self::Error> {
        match payload {
            ExecutionPayloadRef::Merge(payload) => Ok(Self::Merge(NewPayloadRequestMerge {
                execution_payload: payload,
            })),
            ExecutionPayloadRef::Capella(payload) => Ok(Self::Capella(NewPayloadRequestCapella {
                execution_payload: payload,
            })),
            ExecutionPayloadRef::Deneb(_) => Err(Self::Error::IncorrectStateVariant),
        }
    }
}
