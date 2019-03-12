use super::{generate_deterministic_keypairs, KeypairsFile};
use crate::beacon_state::BeaconStateBuilder;
use crate::*;
use bls::get_withdrawal_credentials;
use dirs;
use log::debug;
use rayon::prelude::*;
use std::path::{Path, PathBuf};

pub const KEYPAIRS_FILE: &str = "keypairs.raw_keypairs";

/// Returns the directory where the generated keypairs should be stored.
///
/// It is either `$HOME/.lighthouse/keypairs.raw_keypairs` or, if `$HOME` is not available,
/// `./keypairs.raw_keypairs`.
pub fn keypairs_path() -> PathBuf {
    let dir = dirs::home_dir()
        .and_then(|home| Some(home.join(".lighthouse")))
        .unwrap_or_else(|| PathBuf::from(""));
    dir.join(KEYPAIRS_FILE)
}

/// Builds a beacon state to be used for testing purposes.
///
/// This struct should **never be used for production purposes.**
pub struct TestingBeaconStateBuilder {
    state: BeaconState,
    keypairs: Vec<Keypair>,
}

impl TestingBeaconStateBuilder {
    /// Attempts to load validators from a file in `$HOME/.lighthouse/keypairs.raw_keypairs`. If
    /// the file is unavailable, it generates the keys at runtime.
    ///
    /// If the `$HOME` environment variable is not set, the local directory is used.
    ///
    /// See the `Self::from_keypairs_file` method for more info.
    ///
    /// # Panics
    ///
    /// If the file does not contain enough keypairs or is invalid.
    pub fn from_default_keypairs_file_if_exists(validator_count: usize, spec: &ChainSpec) -> Self {
        let dir = dirs::home_dir()
            .and_then(|home| Some(home.join(".lighthouse")))
            .unwrap_or_else(|| PathBuf::from(""));
        let file = dir.join(KEYPAIRS_FILE);

        if file.exists() {
            TestingBeaconStateBuilder::from_keypairs_file(validator_count, &file, spec)
        } else {
            TestingBeaconStateBuilder::from_deterministic_keypairs(validator_count, spec)
        }
    }

    /// Loads the initial validator keypairs from a file on disk.
    ///
    /// Loading keypairs from file is ~10x faster than generating them. Use the `gen_keys` command
    /// on the  `test_harness` binary to generate the keys. In the `test_harness` dir, run `cargo
    /// run -- gen_keys -h` for help.
    ///
    /// # Panics
    ///
    /// If the file does not exist, is invalid or does not contain enough keypairs.
    pub fn from_keypairs_file(validator_count: usize, path: &Path, spec: &ChainSpec) -> Self {
        debug!("Loading {} keypairs from file...", validator_count);
        let keypairs = Vec::from_raw_file(path, validator_count).unwrap();
        TestingBeaconStateBuilder::from_keypairs(keypairs, spec)
    }

    /// Generates the validator keypairs deterministically.
    pub fn from_deterministic_keypairs(validator_count: usize, spec: &ChainSpec) -> Self {
        debug!("Generating {} deterministic keypairs...", validator_count);
        let keypairs = generate_deterministic_keypairs(validator_count);
        TestingBeaconStateBuilder::from_keypairs(keypairs, spec)
    }

    /// Creates the builder from an existing set of keypairs.
    pub fn from_keypairs(keypairs: Vec<Keypair>, spec: &ChainSpec) -> Self {
        let validator_count = keypairs.len();

        debug!(
            "Building {} Validator objects from keypairs...",
            validator_count
        );
        let validators = keypairs
            .par_iter()
            .map(|keypair| {
                let withdrawal_credentials = Hash256::from_slice(&get_withdrawal_credentials(
                    &keypair.pk,
                    spec.bls_withdrawal_prefix_byte,
                ));

                Validator {
                    pubkey: keypair.pk.clone(),
                    withdrawal_credentials,
                    activation_epoch: spec.far_future_epoch,
                    exit_epoch: spec.far_future_epoch,
                    withdrawable_epoch: spec.far_future_epoch,
                    initiated_exit: false,
                    slashed: false,
                }
            })
            .collect();

        let mut state_builder = BeaconStateBuilder::new(
            0,
            Eth1Data {
                deposit_root: Hash256::zero(),
                block_hash: Hash256::zero(),
            },
            spec,
        );

        let balances = vec![32_000_000_000; validator_count];

        debug!("Importing {} existing validators...", validator_count);
        state_builder.import_existing_validators(
            validators,
            balances,
            validator_count as u64,
            spec,
        );

        let state = state_builder.build(spec).unwrap();

        debug!("BeaconState built.");

        Self { state, keypairs }
    }

    /// Consume the builder and return the `BeaconState` and the keypairs for each validator.
    pub fn build(self) -> (BeaconState, Vec<Keypair>) {
        (self.state, self.keypairs)
    }

    /// Ensures that the state returned from `Self::build(..)` has all caches pre-built.
    ///
    /// Note: this performs the build when called. Ensure that no changes are made that would
    /// invalidate this cache.
    pub fn build_caches(&mut self, spec: &ChainSpec) -> Result<(), BeaconStateError> {
        let state = &mut self.state;

        state.build_epoch_cache(RelativeEpoch::Previous, &spec)?;
        state.build_epoch_cache(RelativeEpoch::Current, &spec)?;
        state.build_epoch_cache(RelativeEpoch::Next, &spec)?;

        Ok(())
    }

    /// Sets the `BeaconState` to be in a slot, calling `teleport_to_epoch` to update the epoch.
    pub fn teleport_to_slot(&mut self, slot: Slot, spec: &ChainSpec) {
        self.teleport_to_epoch(slot.epoch(spec.slots_per_epoch), spec);
        self.state.slot = slot;
    }

    /// Sets the `BeaconState` to be in the first slot of the given epoch.
    ///
    /// Sets all justification/finalization parameters to be be as "perfect" as possible (i.e.,
    /// highest justified and finalized slots, full justification bitfield, etc).
    fn teleport_to_epoch(&mut self, epoch: Epoch, spec: &ChainSpec) {
        let state = &mut self.state;

        let slot = epoch.start_slot(spec.slots_per_epoch);

        state.slot = slot;

        state.previous_shuffling_epoch = epoch - 1;
        state.current_shuffling_epoch = epoch;

        state.previous_shuffling_seed = Hash256::from_low_u64_le(0);
        state.current_shuffling_seed = Hash256::from_low_u64_le(1);

        state.previous_justified_epoch = epoch - 3;
        state.justified_epoch = epoch - 2;
        state.justification_bitfield = u64::max_value();

        state.finalized_epoch = epoch - 3;
        state.validator_registry_update_epoch = epoch - 3;
    }

    /// Creates a full set of attestations for the `BeaconState`. Each attestation has full
    /// participation from its committee and references the expected beacon_block hashes.
    ///
    /// These attestations should be fully conducive to justification and finalization.
    pub fn insert_attestations(&mut self, spec: &ChainSpec) {
        let state = &mut self.state;

        state
            .build_epoch_cache(RelativeEpoch::Previous, spec)
            .unwrap();
        state
            .build_epoch_cache(RelativeEpoch::Current, spec)
            .unwrap();

        let current_epoch = state.current_epoch(spec);
        let previous_epoch = state.previous_epoch(spec);

        let first_slot = previous_epoch.start_slot(spec.slots_per_epoch).as_u64();
        let last_slot = current_epoch.end_slot(spec.slots_per_epoch).as_u64()
            - spec.min_attestation_inclusion_delay;
        let last_slot = std::cmp::min(state.slot.as_u64(), last_slot);

        for slot in first_slot..last_slot + 1 {
            let slot = Slot::from(slot);

            let committees = state
                .get_crosslink_committees_at_slot(slot, spec)
                .unwrap()
                .clone();

            for (committee, shard) in committees {
                state
                    .latest_attestations
                    .push(committee_to_pending_attestation(
                        state, &committee, shard, slot, spec,
                    ))
            }
        }
    }
}

/// Maps a committee to a `PendingAttestation`.
///
/// The committee will be signed by all validators in the committee.
fn committee_to_pending_attestation(
    state: &BeaconState,
    committee: &[usize],
    shard: u64,
    slot: Slot,
    spec: &ChainSpec,
) -> PendingAttestation {
    let current_epoch = state.current_epoch(spec);
    let previous_epoch = state.previous_epoch(spec);

    let mut aggregation_bitfield = Bitfield::new();
    let mut custody_bitfield = Bitfield::new();

    for (i, _) in committee.iter().enumerate() {
        aggregation_bitfield.set(i, true);
        custody_bitfield.set(i, true);
    }

    let is_previous_epoch =
        state.slot.epoch(spec.slots_per_epoch) != slot.epoch(spec.slots_per_epoch);

    let justified_epoch = if is_previous_epoch {
        state.previous_justified_epoch
    } else {
        state.justified_epoch
    };

    let epoch_boundary_root = if is_previous_epoch {
        *state
            .get_block_root(previous_epoch.start_slot(spec.slots_per_epoch), spec)
            .unwrap()
    } else {
        *state
            .get_block_root(current_epoch.start_slot(spec.slots_per_epoch), spec)
            .unwrap()
    };

    let justified_block_root = *state
        .get_block_root(justified_epoch.start_slot(spec.slots_per_epoch), spec)
        .unwrap();

    PendingAttestation {
        aggregation_bitfield,
        data: AttestationData {
            slot,
            shard,
            beacon_block_root: *state.get_block_root(slot, spec).unwrap(),
            epoch_boundary_root,
            crosslink_data_root: Hash256::zero(),
            latest_crosslink: Crosslink {
                epoch: slot.epoch(spec.slots_per_epoch),
                crosslink_data_root: Hash256::zero(),
            },
            justified_epoch,
            justified_block_root,
        },
        custody_bitfield,
        inclusion_slot: slot + spec.min_attestation_inclusion_delay,
    }
}
