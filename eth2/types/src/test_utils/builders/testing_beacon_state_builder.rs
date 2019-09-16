use super::super::{generate_deterministic_keypairs, KeypairsFile};
use crate::test_utils::TestingPendingAttestationBuilder;
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
#[derive(Clone)]
pub struct TestingBeaconStateBuilder<T: EthSpec> {
    state: BeaconState<T>,
    keypairs: Vec<Keypair>,
}

impl<T: EthSpec> TestingBeaconStateBuilder<T> {
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

    /// Uses the given keypair for all validators.
    pub fn from_single_keypair(
        validator_count: usize,
        keypair: &Keypair,
        spec: &ChainSpec,
    ) -> Self {
        debug!("Generating {} cloned keypairs...", validator_count);

        let mut keypairs = Vec::with_capacity(validator_count);
        for _ in 0..validator_count {
            keypairs.push(keypair.clone())
        }

        TestingBeaconStateBuilder::from_keypairs(keypairs, spec)
    }

    /// Creates the builder from an existing set of keypairs.
    pub fn from_keypairs(keypairs: Vec<Keypair>, spec: &ChainSpec) -> Self {
        let validator_count = keypairs.len();
        let starting_balance = spec.max_effective_balance;

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
                    // All validators start active.
                    activation_eligibility_epoch: T::genesis_epoch(),
                    activation_epoch: T::genesis_epoch(),
                    exit_epoch: spec.far_future_epoch,
                    withdrawable_epoch: spec.far_future_epoch,
                    slashed: false,
                    effective_balance: starting_balance,
                }
            })
            .collect::<Vec<_>>()
            .into();

        let genesis_time = 1_567_052_589; // 29 August, 2019;

        let mut state = BeaconState::new(
            genesis_time,
            Eth1Data {
                deposit_root: Hash256::zero(),
                deposit_count: 0,
                block_hash: Hash256::zero(),
            },
            spec,
        );

        state.eth1_data.deposit_count = validator_count as u64;
        state.eth1_deposit_index = validator_count as u64;

        let balances = vec![starting_balance; validator_count].into();

        debug!("Importing {} existing validators...", validator_count);
        state.validators = validators;
        state.balances = balances;

        debug!("BeaconState initialized.");

        Self { state, keypairs }
    }

    /// Consume the builder and return the `BeaconState` and the keypairs for each validator.
    pub fn build(self) -> (BeaconState<T>, Vec<Keypair>) {
        (self.state, self.keypairs)
    }

    /// Ensures that the state returned from `Self::build(..)` has all caches pre-built.
    ///
    /// Note: this performs the build when called. Ensure that no changes are made that would
    /// invalidate this cache.
    pub fn build_caches(&mut self, spec: &ChainSpec) -> Result<(), BeaconStateError> {
        self.state.build_all_caches(spec).unwrap();

        Ok(())
    }

    /// Sets the `BeaconState` to be in a slot, calling `teleport_to_epoch` to update the epoch.
    pub fn teleport_to_slot(&mut self, slot: Slot) {
        self.teleport_to_epoch(slot.epoch(T::slots_per_epoch()));
        self.state.slot = slot;
    }

    /// Sets the `BeaconState` to be in the first slot of the given epoch.
    ///
    /// Sets all justification/finalization parameters to be be as "perfect" as possible (i.e.,
    /// highest justified and finalized slots, full justification bitfield, etc).
    fn teleport_to_epoch(&mut self, epoch: Epoch) {
        let state = &mut self.state;

        let slot = epoch.start_slot(T::slots_per_epoch());

        state.slot = slot;

        // NOTE: we could update the latest start shard here

        state.previous_justified_checkpoint.epoch = epoch - 3;
        state.current_justified_checkpoint.epoch = epoch - 2;
        state.justification_bits = BitVector::from_bytes(vec![0b0000_1111]).unwrap();

        state.finalized_checkpoint.epoch = epoch - 3;
    }

    /// Creates a full set of attestations for the `BeaconState`. Each attestation has full
    /// participation from its committee and references the expected beacon_block hashes.
    ///
    /// These attestations should be fully conducive to justification and finalization.
    pub fn insert_attestations(&mut self, spec: &ChainSpec) {
        let state = &mut self.state;

        state
            .build_committee_cache(RelativeEpoch::Previous, spec)
            .unwrap();
        state
            .build_committee_cache(RelativeEpoch::Current, spec)
            .unwrap();

        let current_epoch = state.current_epoch();
        let previous_epoch = state.previous_epoch();

        let first_slot = previous_epoch.start_slot(T::slots_per_epoch()).as_u64();
        let last_slot = current_epoch.end_slot(T::slots_per_epoch()).as_u64()
            - spec.min_attestation_inclusion_delay;
        let last_slot = std::cmp::min(state.slot.as_u64(), last_slot);

        for slot in first_slot..=last_slot {
            let slot = Slot::from(slot);

            let committees: Vec<OwnedCrosslinkCommittee> = state
                .get_crosslink_committees_at_slot(slot)
                .unwrap()
                .into_iter()
                .map(|c| c.clone().into_owned())
                .collect();

            for crosslink_committee in committees {
                let mut builder = TestingPendingAttestationBuilder::new(
                    state,
                    crosslink_committee.shard,
                    slot,
                    spec,
                );
                // The entire committee should have signed the pending attestation.
                let signers = vec![true; crosslink_committee.committee.len()];
                builder.add_committee_participation(signers);
                let attestation = builder.build();

                if attestation.data.target.epoch < state.current_epoch() {
                    state.previous_epoch_attestations.push(attestation).unwrap()
                } else {
                    state.current_epoch_attestations.push(attestation).unwrap()
                }
            }
        }
    }
}
