use crate::attestation::AttMaxCover;
use crate::max_cover::MaxCover;
use eth2_serde_utils::quoted_u64::Quoted;
use serde::{Deserialize, Serialize};
use state_processing::common::get_attesting_indices;
use state_processing::per_block_processing::{
    verify_attestation_for_block_inclusion, VerifySignatures,
};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::path::Path;
use std::{
    fs::{self, File},
    io,
};
use tree_hash::TreeHash;
use types::{Attestation, BeaconState, BeaconStateError, ChainSpec, Epoch, EthSpec, Hash256, Slot};

/// Simplified `IndexedAttestation`.
#[derive(Serialize, Deserialize)]
pub struct IndexedAttestation {
    pub attesting_indices: Vec<u64>,
    pub data_root: Hash256,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<Slot>,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub index: u64,
}

#[derive(Serialize, Deserialize)]
pub struct AttestationPackingProblem<E: EthSpec> {
    /// The slot of the block being produced.
    pub slot: Slot,
    /// The slot of the parent block upon which we are building.
    ///
    /// If `parent_slot < slot - 1` then there's been a skipped slot and we have an opportunity to
    /// include more attestations.
    pub parent_slot: Slot,
    /// Unaggregated attestations seen on the network that are relevant to the current instance.
    ///
    /// Attestations from validators that have already had an attestation included in the relevant
    /// epoch are excluded (they have 0 value). A validator may only attest once per epoch so a
    /// given validator index can occur at most twice: for one slot in the previous epoch, and one
    /// slot in the current epoch.
    pub unaggregated_attestations: BTreeMap<Slot, Vec<IndexedAttestation>>,
    /// Aggregated attestations seen on the network that are relevant to the current instance.
    ///
    /// These are represented the same way as the unaggregated attestations but:
    ///
    /// - Vectors of attesting indices will usually contain >1 validator index.
    /// - A single validator index may occur in multiple distinct aggregates at a single slot
    ///   but not multiple aggregates at different slots _unless_ those slots are in different
    ///   epochs.
    pub aggregated_attestations: BTreeMap<Slot, Vec<IndexedAttestation>>,
    /// Mapping from `epoch -> validator_index -> gwei_reward`.
    ///
    /// The `reward_function` contains values for the previous and current epoch. It is intended
    /// that this is used to compute rewards for potential solutions. Query by:
    ///
    /// - `epoch = slot // 32`, where `slot` is the `slot` of an included attestation.
    /// - `validator_index`, where `validator_index` is an attesting index from an included
    ///    attestation at `slot`.
    ///
    /// For brevity, validators whose attestations pay 0 reward are omitted from this map. In other
    /// words it's safe to assume that the reward function is 0 if a look-up by validator index
    /// returns no result.
    pub reward_function: BTreeMap<Epoch, BTreeMap<Quoted<u64>, u64>>,
    /// The solution produced by Lighthouse as a vector of `(attestation_slot, attesting_indices)`.
    ///
    /// The quality of the solution can be reconstructed by summing
    /// `reward_function[att.data.slot][i]` for each `att` in `greedy_solution` and each `i` in
    /// `att.attesting_indices`.
    pub greedy_solution: Vec<IndexedAttestation>,
    #[serde(skip)]
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> AttestationPackingProblem<E> {
    pub fn new(
        state: &BeaconState<E>,
        unaggregated_attestations: BTreeMap<Slot, Vec<(Attestation<E>, Vec<u64>)>>,
        aggregated_attestations: BTreeMap<Slot, Vec<(Attestation<E>, Vec<u64>)>>,
        greedy_solution_attestations: &[Attestation<E>],
        spec: &ChainSpec,
    ) -> Result<Self, BeaconStateError> {
        let slot = state.slot();
        let parent_slot = state.latest_block_header().slot;

        let total_active_balance = state.get_total_active_balance()?;
        let mut reward_function: BTreeMap<Epoch, BTreeMap<Quoted<u64>, u64>> = BTreeMap::new();

        // Construct reward function.
        let mut update_reward_fn_and_filter =
            |attestation_map: BTreeMap<Slot, Vec<(Attestation<E>, Vec<u64>)>>| {
                let mut relevant_attestations = BTreeMap::new();

                for (slot, attestation, attesting_indices) in
                    attestation_map
                        .into_iter()
                        .flat_map(|(slot, attestations)| {
                            attestations
                                .into_iter()
                                .map(move |(attestation, indices)| (slot, attestation, indices))
                        })
                {
                    // Double check that the attestation is valid for block inclusion.
                    if verify_attestation_for_block_inclusion(
                        state,
                        &attestation,
                        VerifySignatures::False,
                        spec,
                    )
                    .is_err()
                    {
                        eprintln!(
                            "Invalid attestation at slot {}: att_slot={}, source={}, target={}",
                            state.slot(),
                            attestation.data.slot,
                            attestation.data.source.epoch.as_u64(),
                            attestation.data.target.epoch.as_u64()
                        );
                        continue;
                    }

                    let cover = if let Some(cover) =
                        AttMaxCover::new(&attestation, state, total_active_balance, spec)
                    {
                        cover
                    } else {
                        eprintln!(
                            "Invalid attestation cover at slot {}: \
                             att_slot={}, source={}, target={}",
                            state.slot(),
                            attestation.data.slot,
                            attestation.data.source.epoch.as_u64(),
                            attestation.data.target.epoch.as_u64()
                        );
                        continue;
                    };

                    let epoch = slot.epoch(E::slots_per_epoch());
                    let epoch_rewards = reward_function.entry(epoch).or_insert_with(BTreeMap::new);

                    for (&val_index, &reward) in &cover.fresh_validators_rewards {
                        if reward != 0 {
                            if let Some(prev_reward) =
                                epoch_rewards.insert(Quoted { value: val_index }, reward)
                            {
                                assert_eq!(
                                    prev_reward, reward,
                                    "we don't handle slashable atts here currently"
                                );
                            }
                        }
                    }

                    if cover.score() != 0 {
                        relevant_attestations
                            .entry(slot)
                            .or_insert_with(Vec::new)
                            .push(IndexedAttestation {
                                attesting_indices,
                                data_root: attestation.data.tree_hash_root(),
                                slot: None,
                                index: attestation.data.index,
                            })
                    }
                }
                relevant_attestations
            };

        let unaggregated_attestations = update_reward_fn_and_filter(unaggregated_attestations);
        let aggregated_attestations = update_reward_fn_and_filter(aggregated_attestations);

        // Convert greedy solution Attestations into sets of validators.
        let greedy_solution = greedy_solution_attestations
            .iter()
            .map(|att| {
                let committee = state.get_beacon_committee(att.data.slot, att.data.index)?;
                let indices =
                    get_attesting_indices::<E>(committee.committee, &att.aggregation_bits)?;
                let indexed_att = IndexedAttestation {
                    attesting_indices: indices.into_iter().map(|x| x as u64).collect(),
                    data_root: att.data.tree_hash_root(),
                    slot: Some(att.data.slot),
                    index: att.data.index,
                };
                Ok(indexed_att)
            })
            .collect::<Result<Vec<_>, BeaconStateError>>()?;

        Ok(Self {
            slot,
            parent_slot,
            unaggregated_attestations,
            aggregated_attestations,
            reward_function,
            greedy_solution,
            _phantom: PhantomData,
        })
    }

    pub fn write_to_dir(&self, dir: &Path) -> Result<(), io::Error> {
        fs::create_dir_all(dir)?;
        let f = File::create(dir.join(format!("slot_{}_instance.json", self.slot)))?;
        serde_json::to_writer(f, self)?;
        Ok(())
    }
}
