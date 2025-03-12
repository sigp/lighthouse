use std::sync::Arc;

use beacon_chain::{BeaconChain, BeaconChainTypes};
use either::Either;
use serde_json::Value;
use types::{IndexedAttestation, SignedBeaconBlock, SignedBlindedBeaconBlock};

#[allow(clippy::type_complexity)]
pub fn deserialize_block_payload<T: BeaconChainTypes>(
    payload: Value,
) -> Option<Either<SignedBeaconBlock<T::EthSpec>, SignedBlindedBeaconBlock<T::EthSpec>>> {
    if let Ok(block) = serde_json::from_value::<SignedBeaconBlock<T::EthSpec>>(payload.clone()) {
        Some(Either::Left(block))
    } else {
        serde_json::from_value::<SignedBlindedBeaconBlock<T::EthSpec>>(payload)
            .ok()
            .map(Either::Right)
    }
}

pub fn import_indexed_attestations<T: BeaconChainTypes>(
    indexed_attestations: Vec<IndexedAttestation<T::EthSpec>>,
    chain: Arc<BeaconChain<T>>,
) {
    if let Some(slasher) = chain.slasher.as_ref() {
        for indexed_attestation in indexed_attestations {
            slasher.accept_attestation(indexed_attestation);
        }
    }
}

pub fn export_indexed_attestations<T: BeaconChainTypes>(
    block: Either<SignedBeaconBlock<T::EthSpec>, SignedBlindedBeaconBlock<T::EthSpec>>,
    chain: Arc<BeaconChain<T>>,
) -> Option<Vec<IndexedAttestation<T::EthSpec>>> {
    let (block_root, attestation_epoch) = match &block {
        Either::Left(full_block) => (full_block.canonical_root(), full_block.message().epoch()),
        Either::Right(blinded_block) => (
            blinded_block.canonical_root(),
            blinded_block.message().epoch(),
        ),
    };

    chain
        .with_committee_cache(block_root, attestation_epoch, |committee_cache, _| {
            let mut result = vec![];
            let attestations = match &block {
                Either::Left(full_block) => full_block.message().body().attestations(),
                Either::Right(blinded_block) => blinded_block.message().body().attestations(),
            };
            for attestation in attestations {
                if let Ok(committees) =
                    committee_cache.get_beacon_committees_at_slot(attestation.data().slot)
                {
                    result.extend(IndexedAttestation::from_attestation(
                        attestation,
                        &committees,
                    ))
                };
            }
            Ok(result)
        })
        .ok()
}

pub fn import_block<T: BeaconChainTypes>(
    block: Either<SignedBeaconBlock<T::EthSpec>, SignedBlindedBeaconBlock<T::EthSpec>>,
    chain: Arc<BeaconChain<T>>,
) {
    if let Some(slasher) = chain.slasher.as_ref() {
        match block {
            Either::Left(full_block) => {
                slasher.accept_block_header(full_block.signed_block_header())
            }
            Either::Right(blinded_block) => {
                slasher.accept_block_header(blinded_block.signed_block_header())
            }
        }
    }
}
