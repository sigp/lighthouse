//! Consensus rules specific to the pinned PQ fork.

use crate::per_block_processing::errors::BlockProcessingError;
use alloy_primitives::keccak256_uncached;
use pq_prover::{Proof, ProverBackend, ReferenceBackend, Statement};
use safe_arith::{ArithError, SafeArith};
use types::*;

pub const MIN_ATTESTATION_INCLUSION_DELAY_PQ: u64 = 2;
pub const VRF_TREE_DEPTH: usize = 31;
pub const LEAF_OFFSET_BEACON_PROPOSER: u64 = 0;
pub const LEAF_OFFSET_AGGREGATE_AND_PROOF: u64 = 1;
pub const LEAF_OFFSET_PTC_ATTESTER: u64 = 2;
pub const LEAF_OFFSET_PROPOSER_PREFERENCES: u64 = 3;
pub const LEAF_OFFSET_PAYLOAD_ENVELOPE: u64 = 4;
const XMSS_RESERVED_LEAVES: u64 = 1 << 15;
const XMSS_ATTESTATION_LEAVES: u64 = 1 << 29;
const XMSS_BUILDER_BID_LEAVES: u64 = 1 << 30;
const XMSS_LEAVES_PER_SLOT: u64 = 8;
const XMSS_BUILDER_BID_START: u64 = XMSS_RESERVED_LEAVES + XMSS_ATTESTATION_LEAVES;
const XMSS_SLOT_START: u64 = XMSS_BUILDER_BID_START + XMSS_BUILDER_BID_LEAVES;

pub fn attestation_leaf_index(epoch: Epoch) -> Result<u64, ArithError> {
    XMSS_RESERVED_LEAVES.safe_add(epoch.as_u64())
}

pub fn slot_leaf_index(slot: Slot, offset: u64) -> Result<u64, ArithError> {
    XMSS_SLOT_START
        .safe_add(slot.as_u64().safe_mul(XMSS_LEAVES_PER_SLOT)?)?
        .safe_add(offset)
}

pub fn is_builder_bid_leaf_index(leaf: u64) -> bool {
    (XMSS_BUILDER_BID_START..XMSS_SLOT_START).contains(&leaf)
}

pub fn verify_signature(
    public_key: &XmssPublicKey,
    leaf: u64,
    message: Hash256,
    signature: &XmssSignature,
) -> bool {
    xmss::LeafIndex::try_from(leaf)
        .is_ok_and(|leaf| xmss::verify(public_key, leaf, &message.0, signature))
}

/// Verify the proposal using the public key in this chain state.
pub fn verify_proposer_signature<E: EthSpec, Payload: AbstractExecPayload<E>>(
    state: &BeaconState<E>,
    block: &SignedBeaconBlockPq<E, Payload>,
    block_root: Hash256,
    spec: &ChainSpec,
) -> Result<bool, BeaconStateError> {
    let slot = block.message.slot;
    let domain = spec.get_domain(
        slot.epoch(E::slots_per_epoch()),
        Domain::BeaconProposer,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let leaf = slot_leaf_index(slot, LEAF_OFFSET_BEACON_PROPOSER)?;
    let proposer = state.get_validator(block.message.proposer_index as usize)?;
    Ok(verify_signature(
        &proposer.pubkey,
        leaf,
        block_root.signing_root(domain),
        &block.signature,
    ))
}

/// Derive a slot secret without exposing the secrets for adjacent slots in its Merkle branch.
pub fn compute_vrf_secret(seed: &[u8; 32], index: u64) -> Hash256 {
    let mut input = [0; 50];
    let (domain, rest) = input.split_at_mut(10);
    domain.copy_from_slice(b"VRF_SECRET");
    let (seed_bytes, index_bytes) = rest.split_at_mut(32);
    seed_bytes.copy_from_slice(seed);
    index_bytes.copy_from_slice(&index.to_le_bytes());
    // VRF seed preimages must stay out of the shared Keccak cache.
    keccak256_uncached(input)
}

/// Commit to both the slot secret and its absolute index (PQ spec b5d422b2).
pub fn compute_vrf_leaf(secret: &[u8; 32], index: u64) -> Hash256 {
    let mut input = [0; 48];
    let (domain, rest) = input.split_at_mut(8);
    domain.copy_from_slice(b"VRF_LEAF");
    let (secret_bytes, index_bytes) = rest.split_at_mut(32);
    secret_bytes.copy_from_slice(secret);
    index_bytes.copy_from_slice(&index.to_le_bytes());
    keccak256_uncached(input)
}

pub fn hash_vrf_node(left: Hash256, right: Hash256) -> Hash256 {
    let mut input = [0; 64];
    let (left_bytes, right_bytes) = input.split_at_mut(32);
    left_bytes.copy_from_slice(left.as_slice());
    right_bytes.copy_from_slice(right.as_slice());
    keccak256_uncached(input)
}

pub fn is_valid_vrf_proof(proof: &VrfProof, slot: Slot, root: Hash256) -> bool {
    // The fixed-length branch uses the low VRF_TREE_DEPTH bits of the slot.
    proof.split_first().is_some_and(|(secret, branch)| {
        branch.iter().copied().enumerate().fold(
            compute_vrf_leaf(&secret.0, slot.as_u64()),
            |value, (height, sibling)| {
                if (slot.as_u64() >> height) & 1 == 1 {
                    hash_vrf_node(sibling, value)
                } else {
                    hash_vrf_node(value, sibling)
                }
            },
        ) == root
    })
}

/// Aggregation committees are computed at epoch processing and stored in the
/// window for the previous, current and lookahead epochs.
pub fn is_aggregator<E: EthSpec>(
    state: &BeaconState<E>,
    slot: Slot,
    committee_index: u64,
    validator_index: u64,
) -> Result<bool, BeaconStateError> {
    Ok(aggregator_position(state, slot, committee_index, validator_index)?.is_some())
}

pub fn aggregator_position<E: EthSpec>(
    state: &BeaconState<E>,
    slot: Slot,
    committee_index: u64,
    validator_index: u64,
) -> Result<Option<u64>, BeaconStateError> {
    let window_start = state
        .current_epoch()
        .saturating_sub(1u64)
        .start_slot(E::slots_per_epoch());
    // The genesis window always starts with the empty previous-epoch entries.
    let genesis_padding = if state.current_epoch() == Epoch::new(0) {
        E::slots_per_epoch()
    } else {
        0
    };
    let position = slot
        .safe_sub(window_start.as_u64())?
        .as_u64()
        .safe_add(genesis_padding)?;
    Ok(state
        .as_pq()?
        .aggregation_committee_window
        .get(position as usize)
        .ok_or(BeaconStateError::SlotOutOfBounds)?
        .get(committee_index as usize)
        .and_then(|committee| committee.iter().position(|index| *index == validator_index))
        .map(|position| position as u64))
}

/// Attesters in each selected committee's shuffle order, with committees in increasing order.
pub fn committee_attesters<E: EthSpec>(
    state: &BeaconState<E>,
    attestation: &AttestationPq<E>,
) -> Result<Vec<Vec<u64>>, BeaconStateError> {
    let mut groups = Vec::new();
    let mut offset = 0usize;
    for committee_index in attestation.get_committee_indices() {
        let committee = state.get_beacon_committee(attestation.data.slot, committee_index)?;
        let mut attesters = Vec::new();
        for (position, index) in committee.committee.iter().enumerate() {
            if attestation
                .aggregation_bits
                .get(offset.safe_add(position)?)
                .map_err(|_| BeaconStateError::InvalidBitfield)?
            {
                attesters.push(*index as u64);
            }
        }
        if attesters.is_empty() {
            return Err(BeaconStateError::EmptyCommittee);
        }
        groups.push(attesters);
        offset.safe_add_assign(committee.committee.len())?;
    }
    if offset != attestation.aggregation_bits.len() {
        return Err(BeaconStateError::InvalidBitfield);
    }
    Ok(groups)
}

pub fn attestation_statement<E: EthSpec>(
    state: &BeaconState<E>,
    data: &AttestationData,
    indices: &[u64],
    spec: &ChainSpec,
) -> Result<Statement, BeaconStateError> {
    let domain = spec.get_domain(
        data.target.epoch,
        Domain::BeaconAttester,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let pubkeys = indices
        .iter()
        .map(|index| {
            state
                .get_validator(*index as usize)
                .map(|validator| validator.pubkey)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Statement {
        pubkeys,
        leaf_index: attestation_leaf_index(data.target.epoch)?,
        message: data.signing_root(domain).0,
    })
}

pub fn attestation_statements<E: EthSpec>(
    state: &BeaconState<E>,
    attestation: &AttestationPq<E>,
    spec: &ChainSpec,
) -> Result<Vec<Statement>, BeaconStateError> {
    committee_attesters(state, attestation)?
        .iter()
        .map(|indices| attestation_statement(state, &attestation.data, indices, spec))
        .collect()
}

/// The pinned specification uses concatenated XMSS signatures as its reference proof format.
pub fn verify_attestation_proof<E: EthSpec>(
    statements: &[Statement],
    proof: &AttestationProof<E>,
) -> bool {
    ReferenceBackend
        .verify(statements, &Proof::from_bytes(proof.to_vec()))
        .unwrap_or(false)
}

pub(crate) fn process_stark<E: EthSpec, Payload: AbstractExecPayload<E>>(
    state: &BeaconState<E>,
    body: &BeaconBlockBodyPq<E, Payload>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    let mut statements = Vec::new();
    for attestation in body.attestations.iter() {
        statements.extend(attestation_statements(state, attestation, spec)?);
    }
    if !verify_attestation_proof::<E>(&statements, &body.proof) {
        return Err(BlockProcessingError::InvalidAttestationProof);
    }
    Ok(())
}

/// Populate the present and lookahead epochs at genesis or at a fork boundary.
pub fn initialize_aggregation_committee_window<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), BeaconStateError> {
    let current_epoch = state.current_epoch();
    let mut window = vec![AggregationCommittees::default(); E::slots_per_epoch() as usize];
    for offset in 0..=spec.min_seed_lookahead.as_u64() {
        let epoch = current_epoch.safe_add(offset)?;
        let cache = state.initialize_committee_cache_for_lookahead(epoch, spec)?;
        for slot in epoch.slot_iter(E::slots_per_epoch()) {
            window.push(state.compute_aggregation_committees(slot, &cache, spec)?);
        }
    }
    state.as_pq_mut()?.aggregation_committee_window = milhouse::Vector::new(window)?;
    Ok(())
}

pub fn process_aggregation_committee_window<E: EthSpec>(
    state: &mut BeaconState<E>,
    cache: &CommitteeCache,
    spec: &ChainSpec,
) -> Result<(), BeaconStateError> {
    let epoch = state
        .next_epoch()?
        .safe_add(spec.min_seed_lookahead.as_u64())?;
    let last_epoch = epoch
        .slot_iter(E::slots_per_epoch())
        .map(|slot| state.compute_aggregation_committees(slot, cache, spec))
        .collect::<Result<Vec<_>, _>>()?;

    let pq_state = state.as_pq_mut()?;
    let mut window: milhouse::List<_, E::AggregationCommitteeWindowLength> =
        pq_state.aggregation_committee_window.clone().into();
    window.pop_front(E::slots_per_epoch() as usize)?;
    for committees in last_epoch {
        window.push(committees)?;
    }
    pq_state.aggregation_committee_window = milhouse::Vector::try_from(window)?;
    Ok(())
}

pub fn expire_preregistrations<E: EthSpec>(
    state: &mut BeaconState<E>,
) -> Result<(), BeaconStateError> {
    let parent_slot = state.latest_execution_payload_bid()?.slot();
    let state = state.as_pq_mut()?;
    if state
        .validator_preregistrations
        .iter()
        .any(|record| record.expiry_slot <= parent_slot)
    {
        state.validator_preregistrations = milhouse::ProgressiveList::new(
            state
                .validator_preregistrations
                .iter()
                .filter(|record| record.expiry_slot > parent_slot)
                .cloned()
                .collect(),
        )?;
    }
    if state
        .builder_preregistrations
        .iter()
        .any(|record| record.expiry_slot <= parent_slot)
    {
        state.builder_preregistrations = milhouse::ProgressiveList::new(
            state
                .builder_preregistrations
                .iter()
                .filter(|record| record.expiry_slot > parent_slot)
                .cloned()
                .collect(),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
