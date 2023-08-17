#![cfg(feature = "hydra")]

use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use arbitrary::Unstructured;
use eth2::types::ProposerData;
use parking_lot::RwLock;
use rand::rngs::SmallRng;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use slog::warn;
use state_processing::{state_advance::complete_state_advance, BlockReplayer};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use types::*;

/// For every head removed, I spawn another.
pub struct Hydra<T: BeaconChainTypes, C: HydraChoose> {
    /// Map from `block_root` to advanced state with that block as head.
    states: BTreeMap<Hash256, HydraState<T::EthSpec>>,
    /// Random number generator/choice maker.
    rng: C,
    /// Map of validator index and epoch to selected head block root.
    validator_to_block_root: BTreeMap<(usize, Epoch), Hash256>,
    /// Map of slot and committee index to selected head block root.
    ///
    /// It's possible that we get conflicts in this map if we're connected
    /// to a lot of validators spread across different VCs. In this case we will return
    /// `None` to the validators whose duties conflict.
    committee_index_to_block_root: BTreeMap<(Slot, u64), Hash256>,
    /// Map from proposal slot to proposer and head block root (key into `self.states`).
    proposers: BTreeMap<Slot, (ProposerData, Hash256)>,
    /// The epoch up to which Hydra has finished advancing heads.
    current_epoch: Epoch,
}

pub struct HydraState<E: EthSpec> {
    /// Unadvanced state for this block (state.slot == block.slot).
    pub unadvanced: BeaconState<E>,
    /// Advanced state for this block (state.slot.epoch() == current_epoch).
    pub advanced: BeaconState<E>,
}

pub trait HydraChoose {
    fn choose_slice<'a, T>(&mut self, values: &'a [T]) -> Option<&'a T>;
}

impl HydraChoose for SmallRng {
    fn choose_slice<'a, T>(&mut self, values: &'a [T]) -> Option<&'a T> {
        values.choose(self)
    }
}

impl<'a> HydraChoose for Arc<RwLock<Unstructured<'a>>> {
    fn choose_slice<'b, T>(&mut self, values: &'b [T]) -> Option<&'b T> {
        self.write().choose(values).ok()
    }
}

impl<T: BeaconChainTypes> Hydra<T, SmallRng> {
    pub fn new_random() -> Self {
        Self::new(SmallRng::from_entropy())
    }
}

impl<T: BeaconChainTypes, C: HydraChoose> Hydra<T, C> {
    pub fn new(rng: C) -> Self {
        Self {
            states: BTreeMap::new(),
            validator_to_block_root: BTreeMap::new(),
            committee_index_to_block_root: BTreeMap::new(),
            proposers: BTreeMap::new(),
            rng,
            current_epoch: Epoch::new(0),
        }
    }

    pub fn update(&mut self, chain: &BeaconChain<T>, current_epoch: Epoch) {
        let finalized_checkpoint = chain.canonical_head.cached_head().finalized_checkpoint();
        let finalized_slot = finalized_checkpoint
            .epoch
            .start_slot(T::EthSpec::slots_per_epoch());

        // Pull up every block on every viable chain that descends from finalization.
        for (head_block_root, _) in chain.heads() {
            let relevant_block_roots = match chain
                .rev_iter_block_roots_from(head_block_root)
                .and_then(|iter| {
                    itertools::process_results(iter, |iter| {
                        iter.take_while(|(_, slot)| *slot >= finalized_slot)
                            .collect::<Vec<_>>()
                    })
                }) {
                Ok(block_roots) => block_roots,
                Err(e) => {
                    warn!(
                        chain.log,
                        "Skipping outdated Hydra head";
                        "error" => ?e,
                    );
                    continue;
                }
            };

            // Discard this head if it isn't descended from the finalized checkpoint (special case
            // for genesis).
            if relevant_block_roots.last().map(|(root, _)| root) != Some(&finalized_checkpoint.root)
                && finalized_slot != 0
            {
                continue;
            }

            // Iterate in reverse order so we can hit the parent state in the cache.
            for (block_root, _) in relevant_block_roots.into_iter().rev() {
                self.ensure_block(chain, block_root, current_epoch, finalized_slot);
            }
        }
        // Prune all stale heads.
        self.prune(finalized_checkpoint);

        // Update current epoch.
        self.current_epoch = current_epoch;
    }

    fn ensure_block(
        &mut self,
        chain: &BeaconChain<T>,
        block_root: Hash256,
        current_epoch: Epoch,
        finalized_slot: Slot,
    ) {
        let spec = &chain.spec;
        let state = if let Some(hydra_state) = self.states.get_mut(&block_root) {
            hydra_state
        } else {
            let Ok(Some(block)) = chain.get_blinded_block(&block_root) else {
                slog::warn!(
                    chain.log,
                    "Skipping missing block";
                    "block_root" => ?block_root
                );
                return;
            };

            // This check necessary to prevent freakouts at skipped slots.
            if block.slot() < finalized_slot {
                return;
            }

            // Try to get the parent state from the cache so we can share memory with it.
            let mut state = if let Some(parent_state) = self.states.get(&block.parent_root()) {
                // Use advanced parent state if possible
                let pre_state = if parent_state.advanced.slot() < block.slot() {
                    parent_state.advanced.clone()
                } else {
                    parent_state.unadvanced.clone()
                };
                // Re-apply block.
                let block_slot = block.slot();
                match BlockReplayer::new(pre_state, &chain.spec)
                    .no_signature_verification()
                    .no_state_root_iter()
                    .minimal_block_root_verification()
                    .apply_blocks(vec![block], Some(block_slot))
                {
                    Ok(r) => r.into_state(),
                    Err(e) => {
                        let e: BeaconChainError = e;
                        slog::error!(
                            chain.log,
                            "Hydra block reconstruction error";
                            "error" => ?e,
                            "block_root" => ?block_root
                        );
                        return;
                    }
                }
            } else {
                // Cache miss, load the full state for this block from disk (slow).
                warn!(
                    chain.log,
                    "Missed Hydra state cache";
                    "slot" => block.slot(),
                    "block_root" => ?block_root
                );
                if let Some(state) = chain
                    .store
                    .get_state(&block.state_root(), Some(block.slot()))
                    .ok()
                    .flatten()
                {
                    state
                } else {
                    warn!(
                        chain.log,
                        "No state found";
                        "state_root" => ?block.state_root(),
                    );
                    return;
                }
            };
            state.build_caches(&chain.spec).unwrap();

            self.states.entry(block_root).or_insert(HydraState {
                unadvanced: state.clone(),
                advanced: state,
            })
        };

        if state.advanced.current_epoch() < current_epoch {
            complete_state_advance(
                &mut state.advanced,
                None,
                current_epoch.start_slot(T::EthSpec::slots_per_epoch()),
                spec,
            )
            .unwrap();
        }
    }

    pub fn prune(&mut self, finalized_checkpoint: Checkpoint) {
        let finalized_slot = finalized_checkpoint
            .epoch
            .start_slot(T::EthSpec::slots_per_epoch());
        let mut deleted_heads = vec![];
        self.states.retain(|block_root, state| {
            let keep = *block_root == finalized_checkpoint.root
                || state
                    .advanced
                    .get_block_root(finalized_slot)
                    .map_or(false, |ancestor| *ancestor == finalized_checkpoint.root);
            if !keep {
                deleted_heads.push(*block_root);
            }
            keep
        });

        // Blow away any duties that refer to the deleted blocks. This can happen if we choose
        // duties for the next epoch and then the state becomes unviable.
        self.validator_to_block_root
            .retain(|_, block_root| !deleted_heads.contains(block_root));
        self.committee_index_to_block_root
            .retain(|_, block_root| !deleted_heads.contains(block_root));
    }

    pub fn num_heads(&self) -> usize {
        self.states.len()
    }

    pub fn block_is_viable(&self, block_root: &Hash256) -> bool {
        self.states.contains_key(block_root)
    }

    /// Get a set of *chaotic* attester duties.
    ///
    /// This function is memoized so that it returns the same result on repeat calls with the same
    /// arguments.
    pub fn get_attester_duties(
        &mut self,
        chain: &BeaconChain<T>,
        epoch: Epoch,
        request_indices: &[usize],
    ) -> Result<(Vec<Option<(AttestationDuty, Fork)>>, Hash256), String> {
        let current_epoch = self.current_epoch;

        if epoch != current_epoch && epoch != current_epoch + 1 {
            return Err(format!(
                "not ready for epoch {epoch}, still at {current_epoch}"
            ));
        }

        let duties = request_indices
            .iter()
            .map(|validator_index| self.get_attester_duty(chain, epoch, *validator_index))
            .collect::<Result<Vec<_>, _>>()?;

        // Use current epoch as dependent root: any queries made in the same epoch should result in
        // the same duties. Queries of the *next epoch* from the *current epoch* are liable to
        // change.
        let dependent_root = Hash256::from_low_u64_be(current_epoch.as_u64());

        Ok((duties, dependent_root))
    }

    pub fn get_attester_duty(
        &mut self,
        chain: &BeaconChain<T>,
        epoch: Epoch,
        validator_index: usize,
    ) -> Result<Option<(AttestationDuty, Fork)>, String> {
        // Check for an existing decision.
        let existing_block_root = self.validator_to_block_root.get(&(validator_index, epoch));

        let (relative_epoch, head_block_root, state) = if let Some(block_root) = existing_block_root
        {
            let state = &mut self
                .states
                .get_mut(block_root)
                .ok_or_else(|| format!("missing state for {block_root:?}"))?
                .advanced;
            let relative_epoch = RelativeEpoch::from_epoch(state.current_epoch(), epoch)
                .map_err(|e| format!("bad relative epoch {block_root:?}: {e:?}"))?;
            (relative_epoch, *block_root, state)
        } else {
            // Select a random head to base the duties on.
            let viable_states = self
                .states
                .iter()
                .filter_map(|(block_root, state)| {
                    let relative_epoch =
                        RelativeEpoch::from_epoch(state.advanced.current_epoch(), epoch).ok()?;
                    Some((relative_epoch, *block_root))
                })
                .collect::<Vec<_>>();
            self.rng
                .choose_slice(&viable_states)
                .copied()
                .map(|(epoch, block_root)| {
                    let state = self.states.get_mut(&block_root).expect("state exists");
                    (epoch, block_root, &mut state.advanced)
                })
                .ok_or("no suitable heads")?
        };

        state
            .build_committee_cache(relative_epoch, &chain.spec)
            .map_err(|e| format!("error computing committee: {e:?}"))?;

        let mut opt_duty = state
            .get_attestation_duties(validator_index, relative_epoch)
            .map_err(|e| format!("no duties for {validator_index}: {e:?}"))?;

        // Update caches.
        if let Some(duty) = opt_duty {
            // Check for collision by (slot, committee index). This would prevent us from
            // forming an attestation with a state that's consistent with the duties, so in this
            // case we return a null duty. The validator client will retry and we'll hopefully
            // pick a different random head that does work.
            if self
                .committee_index_to_block_root
                .get(&(duty.slot, duty.index))
                .map_or(false, |cached_block_root| {
                    *cached_block_root != head_block_root
                })
            {
                warn!(
                    chain.log,
                    "Duties collision";
                    "validator_index" => validator_index,
                    "slot" => duty.slot,
                    "committee_index" => duty.index
                );
                opt_duty = None;
            } else {
                self.committee_index_to_block_root
                    .insert((duty.slot, duty.index), head_block_root);
                self.validator_to_block_root
                    .insert((validator_index, epoch), head_block_root);
            }
        }

        // Update shuffling cache used for attestation verification.
        let shuffling_id = AttestationShufflingId::new(head_block_root, state, relative_epoch)
            .map_err(|_| "cannot compute shuffling id")?;
        let cache = state
            .committee_cache(relative_epoch)
            .map_err(|_| "cache unbuilt")?;
        chain
            .shuffling_cache
            .try_write_for(std::time::Duration::from_secs(2))
            .ok_or("cache timeout")?
            .insert_committee_cache(shuffling_id, cache);

        Ok(opt_duty.map(|duty| (duty, state.fork())))
    }

    pub fn produce_attestation_data(
        &self,
        slot: Slot,
        committee_index: u64,
    ) -> Result<AttestationData, String> {
        let beacon_block_root = *self
            .committee_index_to_block_root
            .get(&(slot, committee_index))
            .ok_or_else(|| format!("no committee {committee_index} cached for {slot}"))?;
        let state = &self
            .states
            .get(&beacon_block_root)
            .ok_or("missing state")?
            .advanced;

        let slots_per_epoch = T::EthSpec::slots_per_epoch();
        let epoch = slot.epoch(slots_per_epoch);
        let epoch_start_slot = epoch.start_slot(slots_per_epoch);
        let block_slot = state.latest_block_header().slot;

        // If head block is prior to target slot, then it is the target.
        let target_root = if block_slot <= epoch_start_slot {
            beacon_block_root
        } else {
            // Otherwise the epoch boundary block is certainly in the past and can be looked up
            // in `block_roots`.
            *state
                .get_block_root(epoch_start_slot)
                .map_err(|_| "out of bounds")?
        };
        let target = Checkpoint {
            epoch,
            root: target_root,
        };
        let source = state.current_justified_checkpoint();

        Ok(AttestationData {
            slot,
            index: committee_index,
            source,
            target,
            beacon_block_root,
        })
    }

    pub fn get_proposer_duties(
        &mut self,
        chain: &BeaconChain<T>,
        epoch: Epoch,
        validator_indices: &HashSet<u64>,
    ) -> Result<(Vec<ProposerData>, Hash256), String> {
        let current_epoch = self.current_epoch;
        if epoch != current_epoch {
            return Err(format!(
                "not ready for epoch {epoch}, still at {current_epoch}"
            ));
        }
        let dependent_root = Hash256::from_low_u64_be(current_epoch.as_u64());

        // Some garbage proposer data for slots we don't care about.
        let dummy_proposer_data = |slot| ProposerData {
            pubkey: PublicKeyBytes::empty(),
            validator_index: u64::MAX,
            slot,
        };

        // Check for cached duties.
        let mut duties = vec![];
        let mut cache_hit = false;
        let slots_per_epoch = T::EthSpec::slots_per_epoch();
        for slot in epoch.slot_iter(slots_per_epoch) {
            if let Some((proposer_data, _)) = self.proposers.get(&slot) {
                cache_hit = true;
                duties.push(proposer_data.clone());
            } else {
                duties.push(dummy_proposer_data(slot));
            }
        }

        if cache_hit {
            return Ok((duties, dependent_root));
        }

        // Iterate all heads, looking for heads that award proposal duties to our validators.
        let mut slot_candidates: BTreeMap<Slot, Vec<(u64, Hash256)>> = BTreeMap::new();
        for (block_root, hydra_state) in &self.states {
            let proposers = hydra_state
                .advanced
                .get_beacon_proposer_indices(&chain.spec)
                .map_err(|e| format!("error computing proposers: {e:?}"))?;

            for (i, slot) in epoch.slot_iter(slots_per_epoch).enumerate() {
                let proposer = proposers[i] as u64;

                if validator_indices.contains(&proposer) {
                    slot_candidates
                        .entry(slot)
                        .or_default()
                        .push((proposer, *block_root));
                }
            }
        }

        for (slot, candidates) in slot_candidates {
            // Choose one proposer for each slot.
            if let Some((proposer, block_root)) = self.rng.choose_slice(&candidates).copied() {
                let proposer_data = ProposerData {
                    pubkey: chain
                        .validator_pubkey_bytes(proposer as usize)
                        .unwrap()
                        .unwrap(),
                    validator_index: proposer,
                    slot,
                };
                let offset = slot.as_u64() % T::EthSpec::slots_per_epoch();
                duties[offset as usize] = proposer_data.clone();
                self.proposers.insert(slot, (proposer_data, block_root));
            }
        }

        Ok((duties, dependent_root))
    }

    pub fn state_for_proposal(&self, slot: Slot) -> Option<BeaconState<T::EthSpec>> {
        let (_, block_root) = self.proposers.get(&slot)?;
        let state = self.states.get(block_root)?;
        Some(state.advanced.clone())
    }

    #[allow(clippy::type_complexity)]
    pub fn proposer_heads_at_slot(
        &self,
        slot: Slot,
        validator_indices: &[usize],
        spec: &ChainSpec,
    ) -> BTreeMap<usize, Vec<(Hash256, &HydraState<T::EthSpec>)>> {
        let mut proposer_heads = BTreeMap::new();

        for (block_root, state) in &self.states {
            let proposer = state
                .advanced
                .get_beacon_proposer_index(slot, spec)
                .unwrap();
            if validator_indices.contains(&proposer) {
                proposer_heads
                    .entry(proposer)
                    .or_insert_with(Vec::new)
                    .push((*block_root, state));
            }
        }

        // Sort vecs to establish deterministic ordering.
        for proposal_opps in proposer_heads.values_mut() {
            proposal_opps.sort_by_key(|(block_root, _)| *block_root);
        }

        proposer_heads
    }
}
