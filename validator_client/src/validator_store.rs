use crate::{
    fork_service::ForkService, http_metrics::metrics, initialized_validators::InitializedValidators,
};
use account_utils::{validator_definitions::ValidatorDefinition, ZeroizeString};
use parking_lot::{Mutex, RwLock};
use slashing_protection::{NotSafe, Safe, SlashingDatabase};
use slog::{crit, error, info, warn, Logger};
use slot_clock::SlotClock;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;
use types::{
    Attestation, BeaconBlock, ChainSpec, Domain, Epoch, EthSpec, Fork, Hash256, Keypair, PublicKey,
    SelectionProof, Signature, SignedAggregateAndProof, SignedBeaconBlock, SignedRoot, Slot,
};
use validator_dir::ValidatorDir;

/// Number of epochs of slashing protection history to keep.
///
/// This acts as a maximum safe-guard against clock drift.
const SLASHING_PROTECTION_HISTORY_EPOCHS: u64 = 512;

struct LocalValidator {
    validator_dir: ValidatorDir,
    voting_keypair: Keypair,
}

/// We derive our own `PartialEq` to avoid doing equality checks between secret keys.
///
/// It's nice to avoid secret key comparisons from a security perspective, but it's also a little
/// risky when it comes to `HashMap` integrity (that's why we need `PartialEq`).
///
/// Currently, we obtain keypairs from keystores where we derive the `PublicKey` from a `SecretKey`
/// via a hash function. In order to have two equal `PublicKey` with different `SecretKey` we would
/// need to have either:
///
/// - A serious upstream integrity error.
/// - A hash collision.
///
/// It seems reasonable to make these two assumptions in order to avoid the equality checks.
impl PartialEq for LocalValidator {
    fn eq(&self, other: &Self) -> bool {
        self.validator_dir == other.validator_dir
            && self.voting_keypair.pk == other.voting_keypair.pk
    }
}

#[derive(Clone)]
pub struct ValidatorStore<T, E: EthSpec> {
    validators: Arc<RwLock<InitializedValidators>>,
    slashing_protection: SlashingDatabase,
    slashing_protection_last_prune: Arc<Mutex<Epoch>>,
    genesis_validators_root: Hash256,
    spec: Arc<ChainSpec>,
    log: Logger,
    temp_dir: Option<Arc<TempDir>>,
    fork_service: ForkService<T, E>,
}

impl<T: SlotClock + 'static, E: EthSpec> ValidatorStore<T, E> {
    pub fn new(
        validators: InitializedValidators,
        slashing_protection: SlashingDatabase,
        genesis_validators_root: Hash256,
        spec: ChainSpec,
        fork_service: ForkService<T, E>,
        log: Logger,
    ) -> Self {
        Self {
            validators: Arc::new(RwLock::new(validators)),
            slashing_protection,
            slashing_protection_last_prune: Arc::new(Mutex::new(Epoch::new(0))),
            genesis_validators_root,
            spec: Arc::new(spec),
            log,
            temp_dir: None,
            fork_service,
        }
    }

    pub fn initialized_validators(&self) -> Arc<RwLock<InitializedValidators>> {
        self.validators.clone()
    }

    /// Insert a new validator to `self`, where the validator is represented by an EIP-2335
    /// keystore on the filesystem.
    ///
    /// This function includes:
    ///
    /// - Add the validator definition to the YAML file, saving it to the filesystem.
    /// - Enable validator with the slashing protection database.
    /// - If `enable == true`, start performing duties for the validator.
    pub async fn add_validator_keystore<P: AsRef<Path>>(
        &self,
        voting_keystore_path: P,
        password: ZeroizeString,
        enable: bool,
    ) -> Result<ValidatorDefinition, String> {
        let mut validator_def =
            ValidatorDefinition::new_keystore_with_password(voting_keystore_path, Some(password))
                .map_err(|e| format!("failed to create validator definitions: {:?}", e))?;

        self.slashing_protection
            .register_validator(&validator_def.voting_public_key)
            .map_err(|e| format!("failed to register validator: {:?}", e))?;

        validator_def.enabled = enable;

        self.validators
            .write()
            .add_definition(validator_def.clone())
            .await
            .map_err(|e| format!("Unable to add definition: {:?}", e))?;

        Ok(validator_def)
    }

    pub fn voting_pubkeys(&self) -> Vec<PublicKey> {
        self.validators
            .read()
            .iter_voting_pubkeys()
            .cloned()
            .collect()
    }

    pub fn num_voting_validators(&self) -> usize {
        self.validators.read().num_enabled()
    }

    fn fork(&self) -> Fork {
        self.fork_service.fork()
    }

    pub fn randao_reveal(&self, validator_pubkey: &PublicKey, epoch: Epoch) -> Option<Signature> {
        self.validators
            .read()
            .voting_keypair(validator_pubkey)
            .map(|voting_keypair| {
                let domain = self.spec.get_domain(
                    epoch,
                    Domain::Randao,
                    &self.fork(),
                    self.genesis_validators_root,
                );
                let message = epoch.signing_root(domain);

                voting_keypair.sk.sign(message)
            })
    }

    pub fn sign_block(
        &self,
        validator_pubkey: &PublicKey,
        block: BeaconBlock<E>,
        current_slot: Slot,
    ) -> Option<SignedBeaconBlock<E>> {
        // Make sure the block slot is not higher than the current slot to avoid potential attacks.
        if block.slot > current_slot {
            warn!(
                self.log,
                "Not signing block with slot greater than current slot";
                "block_slot" => block.slot.as_u64(),
                "current_slot" => current_slot.as_u64()
            );
            return None;
        }

        // Check for slashing conditions.
        let fork = self.fork();
        let domain = self.spec.get_domain(
            block.epoch(),
            Domain::BeaconProposer,
            &fork,
            self.genesis_validators_root,
        );

        let slashing_status = self.slashing_protection.check_and_insert_block_proposal(
            validator_pubkey,
            &block.block_header(),
            domain,
        );

        match slashing_status {
            // We can safely sign this block.
            Ok(Safe::Valid) => {
                let validators = self.validators.read();
                let voting_keypair = validators.voting_keypair(validator_pubkey)?;

                metrics::inc_counter_vec(&metrics::SIGNED_BLOCKS_TOTAL, &[metrics::SUCCESS]);

                Some(block.sign(
                    &voting_keypair.sk,
                    &fork,
                    self.genesis_validators_root,
                    &self.spec,
                ))
            }
            Ok(Safe::SameData) => {
                warn!(
                    self.log,
                    "Skipping signing of previously signed block";
                );
                metrics::inc_counter_vec(&metrics::SIGNED_BLOCKS_TOTAL, &[metrics::SAME_DATA]);
                None
            }
            Err(NotSafe::UnregisteredValidator(pk)) => {
                warn!(
                    self.log,
                    "Not signing block for unregistered validator";
                    "msg" => "Carefully consider running with --init-slashing-protection (see --help)",
                    "public_key" => format!("{:?}", pk)
                );
                metrics::inc_counter_vec(&metrics::SIGNED_BLOCKS_TOTAL, &[metrics::UNREGISTERED]);
                None
            }
            Err(e) => {
                crit!(
                    self.log,
                    "Not signing slashable block";
                    "error" => format!("{:?}", e)
                );
                metrics::inc_counter_vec(&metrics::SIGNED_BLOCKS_TOTAL, &[metrics::SLASHABLE]);
                None
            }
        }
    }

    pub fn sign_attestation(
        &self,
        validator_pubkey: &PublicKey,
        validator_committee_position: usize,
        attestation: &mut Attestation<E>,
        current_epoch: Epoch,
    ) -> Option<()> {
        // Make sure the target epoch is not higher than the current epoch to avoid potential attacks.
        if attestation.data.target.epoch > current_epoch {
            return None;
        }

        // Checking for slashing conditions.
        let fork = self.fork();

        let domain = self.spec.get_domain(
            attestation.data.target.epoch,
            Domain::BeaconAttester,
            &fork,
            self.genesis_validators_root,
        );
        let slashing_status = self.slashing_protection.check_and_insert_attestation(
            validator_pubkey,
            &attestation.data,
            domain,
        );

        match slashing_status {
            // We can safely sign this attestation.
            Ok(Safe::Valid) => {
                let validators = self.validators.read();
                let voting_keypair = validators.voting_keypair(validator_pubkey)?;

                attestation
                    .sign(
                        &voting_keypair.sk,
                        validator_committee_position,
                        &fork,
                        self.genesis_validators_root,
                        &self.spec,
                    )
                    .map_err(|e| {
                        error!(
                            self.log,
                            "Error whilst signing attestation";
                            "error" => format!("{:?}", e)
                        )
                    })
                    .ok()?;

                metrics::inc_counter_vec(&metrics::SIGNED_ATTESTATIONS_TOTAL, &[metrics::SUCCESS]);

                Some(())
            }
            Ok(Safe::SameData) => {
                warn!(
                    self.log,
                    "Skipping signing of previously signed attestation"
                );
                metrics::inc_counter_vec(
                    &metrics::SIGNED_ATTESTATIONS_TOTAL,
                    &[metrics::SAME_DATA],
                );
                None
            }
            Err(NotSafe::UnregisteredValidator(pk)) => {
                warn!(
                    self.log,
                    "Not signing attestation for unregistered validator";
                    "msg" => "Carefully consider running with --init-slashing-protection (see --help)",
                    "public_key" => format!("{:?}", pk)
                );
                metrics::inc_counter_vec(
                    &metrics::SIGNED_ATTESTATIONS_TOTAL,
                    &[metrics::UNREGISTERED],
                );
                None
            }
            Err(e) => {
                crit!(
                    self.log,
                    "Not signing slashable attestation";
                    "attestation" => format!("{:?}", attestation.data),
                    "error" => format!("{:?}", e)
                );
                metrics::inc_counter_vec(
                    &metrics::SIGNED_ATTESTATIONS_TOTAL,
                    &[metrics::SLASHABLE],
                );
                None
            }
        }
    }

    /// Signs an `AggregateAndProof` for a given validator.
    ///
    /// The resulting `SignedAggregateAndProof` is sent on the aggregation channel and cannot be
    /// modified by actors other than the signing validator.
    pub fn produce_signed_aggregate_and_proof(
        &self,
        validator_pubkey: &PublicKey,
        validator_index: u64,
        aggregate: Attestation<E>,
        selection_proof: SelectionProof,
    ) -> Option<SignedAggregateAndProof<E>> {
        let validators = self.validators.read();
        let voting_keypair = &validators.voting_keypair(validator_pubkey)?;

        metrics::inc_counter_vec(&metrics::SIGNED_AGGREGATES_TOTAL, &[metrics::SUCCESS]);

        Some(SignedAggregateAndProof::from_aggregate(
            validator_index,
            aggregate,
            Some(selection_proof),
            &voting_keypair.sk,
            &self.fork(),
            self.genesis_validators_root,
            &self.spec,
        ))
    }

    /// Produces a `SelectionProof` for the `slot`, signed by with corresponding secret key to
    /// `validator_pubkey`.
    pub fn produce_selection_proof(
        &self,
        validator_pubkey: &PublicKey,
        slot: Slot,
    ) -> Option<SelectionProof> {
        let validators = self.validators.read();
        let voting_keypair = &validators.voting_keypair(validator_pubkey)?;

        metrics::inc_counter_vec(&metrics::SIGNED_SELECTION_PROOFS_TOTAL, &[metrics::SUCCESS]);

        Some(SelectionProof::new::<E>(
            slot,
            &voting_keypair.sk,
            &self.fork(),
            self.genesis_validators_root,
            &self.spec,
        ))
    }

    /// Prune the slashing protection database so that it remains performant.
    ///
    /// This function will only do actual pruning periodically, so it should usually be
    /// cheap to call. The `first_run` flag can be used to print a more verbose message when pruning
    /// runs.
    pub fn prune_slashing_protection_db(&self, current_epoch: Epoch, first_run: bool) {
        // Attempt to prune every SLASHING_PROTECTION_HISTORY_EPOCHs, with a tolerance for
        // missing the epoch that aligns exactly.
        let mut last_prune = self.slashing_protection_last_prune.lock();
        if current_epoch / SLASHING_PROTECTION_HISTORY_EPOCHS
            <= *last_prune / SLASHING_PROTECTION_HISTORY_EPOCHS
        {
            return;
        }

        if first_run {
            info!(
                self.log,
                "Pruning slashing protection DB";
                "epoch" => current_epoch,
                "msg" => "pruning may take several minutes the first time it runs"
            );
        } else {
            info!(self.log, "Pruning slashing protection DB"; "epoch" => current_epoch);
        }

        let _timer = metrics::start_timer(&metrics::SLASHING_PROTECTION_PRUNE_TIMES);

        let new_min_target_epoch = current_epoch.saturating_sub(SLASHING_PROTECTION_HISTORY_EPOCHS);
        let new_min_slot = new_min_target_epoch.start_slot(E::slots_per_epoch());

        let validators = self.validators.read();
        if let Err(e) = self
            .slashing_protection
            .prune_all_signed_attestations(validators.iter_voting_pubkeys(), new_min_target_epoch)
        {
            error!(
                self.log,
                "Error during pruning of signed attestations";
                "error" => ?e,
            );
            return;
        }

        if let Err(e) = self
            .slashing_protection
            .prune_all_signed_blocks(validators.iter_voting_pubkeys(), new_min_slot)
        {
            error!(
                self.log,
                "Error during pruning of signed blocks";
                "error" => ?e,
            );
            return;
        }

        *last_prune = current_epoch;

        info!(self.log, "Completed pruning of slashing protection DB");
    }
}
