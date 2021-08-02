use crate::{
    doppelganger_service::DoppelgangerService, http_metrics::metrics,
    initialized_validators::InitializedValidators,
};
use account_utils::{validator_definitions::ValidatorDefinition, ZeroizeString};
use parking_lot::{Mutex, RwLock};
use slashing_protection::{NotSafe, Safe, SlashingDatabase};
use slog::{crit, error, info, warn, Logger};
use slot_clock::SlotClock;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;
use types::{
    attestation::Error as AttestationError, graffiti::GraffitiString, Attestation, BeaconBlock,
    ChainSpec, Domain, Epoch, EthSpec, Fork, Graffiti, Hash256, Keypair, PublicKeyBytes,
    SelectionProof, Signature, SignedAggregateAndProof, SignedBeaconBlock,
    SignedContributionAndProof, SignedRoot, Slot, SyncCommitteeContribution, SyncCommitteeMessage,
    SyncSelectionProof, SyncSubnetId,
};
use validator_dir::ValidatorDir;

pub use crate::doppelganger_service::DoppelgangerStatus;

#[derive(Debug, PartialEq)]
pub enum Error {
    DoppelgangerProtected(PublicKeyBytes),
    UnknownToDoppelgangerService(PublicKeyBytes),
    UnknownPubkey(PublicKeyBytes),
    Slashable(NotSafe),
    SameData,
    GreaterThanCurrentSlot { slot: Slot, current_slot: Slot },
    GreaterThanCurrentEpoch { epoch: Epoch, current_epoch: Epoch },
    UnableToSignAttestation(AttestationError),
}

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

pub struct ValidatorStore<T, E: EthSpec> {
    validators: Arc<RwLock<InitializedValidators>>,
    slashing_protection: SlashingDatabase,
    slashing_protection_last_prune: Arc<Mutex<Epoch>>,
    genesis_validators_root: Hash256,
    spec: Arc<ChainSpec>,
    log: Logger,
    doppelganger_service: Option<Arc<DoppelgangerService>>,
    slot_clock: T,
    _phantom: PhantomData<E>,
}

impl<T: SlotClock + 'static, E: EthSpec> ValidatorStore<T, E> {
    pub fn new(
        validators: InitializedValidators,
        slashing_protection: SlashingDatabase,
        genesis_validators_root: Hash256,
        spec: ChainSpec,
        doppelganger_service: Option<Arc<DoppelgangerService>>,
        slot_clock: T,
        log: Logger,
    ) -> Self {
        Self {
            validators: Arc::new(RwLock::new(validators)),
            slashing_protection,
            slashing_protection_last_prune: Arc::new(Mutex::new(Epoch::new(0))),
            genesis_validators_root,
            spec: Arc::new(spec),
            log,
            doppelganger_service,
            slot_clock,
            _phantom: PhantomData,
        }
    }

    /// Register all local validators in doppelganger protection to try and prevent instances of
    /// duplicate validators operating on the network at the same time.
    ///
    /// This function has no effect if doppelganger protection is disabled.
    pub fn register_all_in_doppelganger_protection_if_enabled(&self) -> Result<(), String> {
        if let Some(doppelganger_service) = &self.doppelganger_service {
            for pubkey in self.validators.read().iter_voting_pubkeys() {
                doppelganger_service.register_new_validator::<E, _>(*pubkey, &self.slot_clock)?
            }
        }

        Ok(())
    }

    /// Returns `true` if doppelganger protection is enabled, or else `false`.
    pub fn doppelganger_protection_enabled(&self) -> bool {
        self.doppelganger_service.is_some()
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
        graffiti: Option<GraffitiString>,
    ) -> Result<ValidatorDefinition, String> {
        let mut validator_def = ValidatorDefinition::new_keystore_with_password(
            voting_keystore_path,
            Some(password),
            graffiti.map(Into::into),
        )
        .map_err(|e| format!("failed to create validator definitions: {:?}", e))?;

        let validator_pubkey = validator_def.voting_public_key.compress();

        self.slashing_protection
            .register_validator(validator_pubkey)
            .map_err(|e| format!("failed to register validator: {:?}", e))?;

        validator_def.enabled = enable;

        if let Some(doppelganger_service) = &self.doppelganger_service {
            doppelganger_service
                .register_new_validator::<E, _>(validator_pubkey, &self.slot_clock)?;
        }

        self.validators
            .write()
            .add_definition(validator_def.clone())
            .await
            .map_err(|e| format!("Unable to add definition: {:?}", e))?;

        Ok(validator_def)
    }

    /// Attempts to resolve the pubkey to a validator index.
    ///
    /// It may return `None` if the `pubkey` is:
    ///
    /// - Unknown.
    /// - Known, but with an unknown index.
    pub fn validator_index(&self, pubkey: &PublicKeyBytes) -> Option<u64> {
        self.validators.read().get_index(pubkey)
    }

    /// Returns all voting pubkeys for all enabled validators.
    ///
    /// The `filter_func` allows for filtering pubkeys based upon their `DoppelgangerStatus`. There
    /// are two primary functions used here:
    ///
    /// - `DoppelgangerStatus::only_safe`: only returns pubkeys which have passed doppelganger
    ///     protection and are safe-enough to sign messages.
    /// - `DoppelgangerStatus::ignored`: returns all the pubkeys from `only_safe` *plus* those still
    ///     undergoing protection. This is useful for collecting duties or other non-signing tasks.
    #[allow(clippy::needless_collect)] // Collect is required to avoid holding a lock.
    pub fn voting_pubkeys<I, F>(&self, filter_func: F) -> I
    where
        I: FromIterator<PublicKeyBytes>,
        F: Fn(DoppelgangerStatus) -> Option<PublicKeyBytes>,
    {
        // Collect all the pubkeys first to avoid interleaving locks on `self.validators` and
        // `self.doppelganger_service()`.
        let pubkeys = self
            .validators
            .read()
            .iter_voting_pubkeys()
            .cloned()
            .collect::<Vec<_>>();

        pubkeys
            .into_iter()
            .map(|pubkey| {
                self.doppelganger_service
                    .as_ref()
                    .map(|doppelganger_service| doppelganger_service.validator_status(pubkey))
                    // Allow signing on all pubkeys if doppelganger protection is disabled.
                    .unwrap_or_else(|| DoppelgangerStatus::SigningEnabled(pubkey))
            })
            .filter_map(filter_func)
            .collect()
    }

    /// Returns doppelganger statuses for all enabled validators.
    #[allow(clippy::needless_collect)] // Collect is required to avoid holding a lock.
    pub fn doppelganger_statuses(&self) -> Vec<DoppelgangerStatus> {
        // Collect all the pubkeys first to avoid interleaving locks on `self.validators` and
        // `self.doppelganger_service`.
        let pubkeys = self
            .validators
            .read()
            .iter_voting_pubkeys()
            .cloned()
            .collect::<Vec<_>>();

        pubkeys
            .into_iter()
            .map(|pubkey| {
                self.doppelganger_service
                    .as_ref()
                    .map(|doppelganger_service| doppelganger_service.validator_status(pubkey))
                    // Allow signing on all pubkeys if doppelganger protection is disabled.
                    .unwrap_or_else(|| DoppelgangerStatus::SigningEnabled(pubkey))
            })
            .collect()
    }

    /// Check if the `validator_pubkey` is permitted by the doppleganger protection to sign
    /// messages.
    pub fn doppelganger_protection_allows_signing(&self, validator_pubkey: PublicKeyBytes) -> bool {
        self.doppelganger_service
            .as_ref()
            // If there's no doppelganger service then we assume it is purposefully disabled and
            // declare that all keys are safe with regard to it.
            .map_or(true, |doppelganger_service| {
                doppelganger_service
                    .validator_status(validator_pubkey)
                    .only_safe()
                    .is_some()
            })
    }

    pub fn num_voting_validators(&self) -> usize {
        self.validators.read().num_enabled()
    }

    fn fork(&self, epoch: Epoch) -> Fork {
        self.spec.fork_at_epoch(epoch)
    }

    /// Runs `func`, providing it access to the `Keypair` corresponding to `validator_pubkey`.
    ///
    /// This forms the canonical point for accessing the secret key of some validator. It is
    /// structured as a `with_...` function since we need to pass-through a read-lock in order to
    /// access the keypair.
    ///
    /// Access to keypairs might be restricted by other internal mechanisms (e.g., doppleganger
    /// protection).
    ///
    /// ## Warning
    ///
    /// This function takes a read-lock on `self.validators`. To prevent deadlocks, it is advised to
    /// never take any sort of concurrency lock inside this function.
    fn with_validator_keypair<F, R>(
        &self,
        validator_pubkey: PublicKeyBytes,
        func: F,
    ) -> Result<R, Error>
    where
        F: FnOnce(&Keypair) -> R,
    {
        // If the doppelganger service is active, check to ensure it explicitly permits signing by
        // this validator.
        if !self.doppelganger_protection_allows_signing(validator_pubkey) {
            return Err(Error::DoppelgangerProtected(validator_pubkey));
        }

        let validators_lock = self.validators.read();

        Ok(func(
            validators_lock
                .voting_keypair(&validator_pubkey)
                .ok_or(Error::UnknownPubkey(validator_pubkey))?,
        ))
    }

    pub fn randao_reveal(
        &self,
        validator_pubkey: PublicKeyBytes,
        epoch: Epoch,
    ) -> Result<Signature, Error> {
        let domain = self.spec.get_domain(
            epoch,
            Domain::Randao,
            &self.fork(epoch),
            self.genesis_validators_root,
        );
        let message = epoch.signing_root(domain);

        self.with_validator_keypair(validator_pubkey, |keypair| keypair.sk.sign(message))
    }

    pub fn graffiti(&self, validator_pubkey: &PublicKeyBytes) -> Option<Graffiti> {
        self.validators.read().graffiti(validator_pubkey)
    }

    pub fn sign_block(
        &self,
        validator_pubkey: PublicKeyBytes,
        block: BeaconBlock<E>,
        current_slot: Slot,
    ) -> Result<SignedBeaconBlock<E>, Error> {
        // Make sure the block slot is not higher than the current slot to avoid potential attacks.
        if block.slot() > current_slot {
            warn!(
                self.log,
                "Not signing block with slot greater than current slot";
                "block_slot" => block.slot().as_u64(),
                "current_slot" => current_slot.as_u64()
            );
            return Err(Error::GreaterThanCurrentSlot {
                slot: block.slot(),
                current_slot,
            });
        }

        // Check for slashing conditions.
        let fork = self.fork(block.epoch());
        let domain = self.spec.get_domain(
            block.epoch(),
            Domain::BeaconProposer,
            &fork,
            self.genesis_validators_root,
        );

        let slashing_status = self.slashing_protection.check_and_insert_block_proposal(
            &validator_pubkey,
            &block.block_header(),
            domain,
        );

        match slashing_status {
            // We can safely sign this block without slashing.
            Ok(Safe::Valid) => {
                metrics::inc_counter_vec(&metrics::SIGNED_BLOCKS_TOTAL, &[metrics::SUCCESS]);

                self.with_validator_keypair(validator_pubkey, move |keypair| {
                    block.sign(&keypair.sk, &fork, self.genesis_validators_root, &self.spec)
                })
            }
            Ok(Safe::SameData) => {
                warn!(
                    self.log,
                    "Skipping signing of previously signed block";
                );
                metrics::inc_counter_vec(&metrics::SIGNED_BLOCKS_TOTAL, &[metrics::SAME_DATA]);
                Err(Error::SameData)
            }
            Err(NotSafe::UnregisteredValidator(pk)) => {
                warn!(
                    self.log,
                    "Not signing block for unregistered validator";
                    "msg" => "Carefully consider running with --init-slashing-protection (see --help)",
                    "public_key" => format!("{:?}", pk)
                );
                metrics::inc_counter_vec(&metrics::SIGNED_BLOCKS_TOTAL, &[metrics::UNREGISTERED]);
                Err(Error::Slashable(NotSafe::UnregisteredValidator(pk)))
            }
            Err(e) => {
                crit!(
                    self.log,
                    "Not signing slashable block";
                    "error" => format!("{:?}", e)
                );
                metrics::inc_counter_vec(&metrics::SIGNED_BLOCKS_TOTAL, &[metrics::SLASHABLE]);
                Err(Error::Slashable(e))
            }
        }
    }

    pub fn sign_attestation(
        &self,
        validator_pubkey: PublicKeyBytes,
        validator_committee_position: usize,
        attestation: &mut Attestation<E>,
        current_epoch: Epoch,
    ) -> Result<(), Error> {
        // Make sure the target epoch is not higher than the current epoch to avoid potential attacks.
        if attestation.data.target.epoch > current_epoch {
            return Err(Error::GreaterThanCurrentEpoch {
                epoch: attestation.data.target.epoch,
                current_epoch,
            });
        }

        // Checking for slashing conditions.
        let fork = self.fork(attestation.data.target.epoch);

        let domain = self.spec.get_domain(
            attestation.data.target.epoch,
            Domain::BeaconAttester,
            &fork,
            self.genesis_validators_root,
        );
        let slashing_status = self.slashing_protection.check_and_insert_attestation(
            &validator_pubkey,
            &attestation.data,
            domain,
        );

        match slashing_status {
            // We can safely sign this attestation.
            Ok(Safe::Valid) => {
                self.with_validator_keypair(validator_pubkey, |keypair| {
                    attestation.sign(
                        &keypair.sk,
                        validator_committee_position,
                        &fork,
                        self.genesis_validators_root,
                        &self.spec,
                    )
                })?
                .map_err(Error::UnableToSignAttestation)?;

                metrics::inc_counter_vec(&metrics::SIGNED_ATTESTATIONS_TOTAL, &[metrics::SUCCESS]);

                Ok(())
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
                Err(Error::SameData)
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
                Err(Error::Slashable(NotSafe::UnregisteredValidator(pk)))
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
                Err(Error::Slashable(e))
            }
        }
    }

    /// Signs an `AggregateAndProof` for a given validator.
    ///
    /// The resulting `SignedAggregateAndProof` is sent on the aggregation channel and cannot be
    /// modified by actors other than the signing validator.
    pub fn produce_signed_aggregate_and_proof(
        &self,
        validator_pubkey: PublicKeyBytes,
        validator_index: u64,
        aggregate: Attestation<E>,
        selection_proof: SelectionProof,
    ) -> Result<SignedAggregateAndProof<E>, Error> {
        let fork = self.fork(aggregate.data.target.epoch);

        let proof = self.with_validator_keypair(validator_pubkey, move |keypair| {
            SignedAggregateAndProof::from_aggregate(
                validator_index,
                aggregate,
                Some(selection_proof),
                &keypair.sk,
                &fork,
                self.genesis_validators_root,
                &self.spec,
            )
        })?;

        metrics::inc_counter_vec(&metrics::SIGNED_AGGREGATES_TOTAL, &[metrics::SUCCESS]);

        Ok(proof)
    }

    /// Produces a `SelectionProof` for the `slot`, signed by with corresponding secret key to
    /// `validator_pubkey`.
    pub fn produce_selection_proof(
        &self,
        validator_pubkey: PublicKeyBytes,
        slot: Slot,
    ) -> Result<SelectionProof, Error> {
        // Bypass the `with_validator_keypair` function.
        //
        // This is because we don't care about doppelganger protection when it comes to selection
        // proofs. They are not slashable and we need them to subscribe to subnets on the BN.
        //
        // As long as we disallow `SignedAggregateAndProof` then these selection proofs will never
        // be published on the network.
        let validators_lock = self.validators.read();
        let keypair = validators_lock
            .voting_keypair(&validator_pubkey)
            .ok_or(Error::UnknownPubkey(validator_pubkey))?;

        let proof = SelectionProof::new::<E>(
            slot,
            &keypair.sk,
            &self.fork(slot.epoch(E::slots_per_epoch())),
            self.genesis_validators_root,
            &self.spec,
        );

        metrics::inc_counter_vec(&metrics::SIGNED_SELECTION_PROOFS_TOTAL, &[metrics::SUCCESS]);

        Ok(proof)
    }

    /// Produce a `SyncSelectionProof` for `slot` signed by the secret key of `validator_pubkey`.
    pub fn produce_sync_selection_proof(
        &self,
        validator_pubkey: &PublicKeyBytes,
        slot: Slot,
        subnet_id: SyncSubnetId,
    ) -> Result<SyncSelectionProof, Error> {
        // Bypass `with_validator_keypair`: sync committee messages are not slashable.
        let validators = self.validators.read();
        let voting_keypair = validators
            .voting_keypair(validator_pubkey)
            .ok_or(Error::UnknownPubkey(*validator_pubkey))?;

        metrics::inc_counter_vec(
            &metrics::SIGNED_SYNC_SELECTION_PROOFS_TOTAL,
            &[metrics::SUCCESS],
        );

        Ok(SyncSelectionProof::new::<E>(
            slot,
            subnet_id.into(),
            &voting_keypair.sk,
            &self.fork(slot.epoch(E::slots_per_epoch())),
            self.genesis_validators_root,
            &self.spec,
        ))
    }

    pub fn produce_sync_committee_signature(
        &self,
        slot: Slot,
        beacon_block_root: Hash256,
        validator_index: u64,
        validator_pubkey: &PublicKeyBytes,
    ) -> Result<SyncCommitteeMessage, Error> {
        // Bypass `with_validator_keypair`: sync committee messages are not slashable.
        let validators = self.validators.read();
        let voting_keypair = validators
            .voting_keypair(validator_pubkey)
            .ok_or(Error::UnknownPubkey(*validator_pubkey))?;

        metrics::inc_counter_vec(
            &metrics::SIGNED_SYNC_COMMITTEE_MESSAGES_TOTAL,
            &[metrics::SUCCESS],
        );

        Ok(SyncCommitteeMessage::new::<E>(
            slot,
            beacon_block_root,
            validator_index,
            &voting_keypair.sk,
            &self.fork(slot.epoch(E::slots_per_epoch())),
            self.genesis_validators_root,
            &self.spec,
        ))
    }

    pub fn produce_signed_contribution_and_proof(
        &self,
        aggregator_index: u64,
        aggregator_pubkey: &PublicKeyBytes,
        contribution: SyncCommitteeContribution<E>,
        selection_proof: SyncSelectionProof,
    ) -> Result<SignedContributionAndProof<E>, Error> {
        // Bypass `with_validator_keypair`: sync committee messages are not slashable.
        let validators = self.validators.read();
        let voting_keypair = validators
            .voting_keypair(aggregator_pubkey)
            .ok_or(Error::UnknownPubkey(*aggregator_pubkey))?;
        let fork = self.fork(contribution.slot.epoch(E::slots_per_epoch()));

        metrics::inc_counter_vec(
            &metrics::SIGNED_SYNC_COMMITTEE_CONTRIBUTIONS_TOTAL,
            &[metrics::SUCCESS],
        );

        Ok(SignedContributionAndProof::from_aggregate(
            aggregator_index,
            contribution,
            Some(selection_proof),
            &voting_keypair.sk,
            &fork,
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

        let all_pubkeys: Vec<_> = self.voting_pubkeys(DoppelgangerStatus::ignored);

        if let Err(e) = self
            .slashing_protection
            .prune_all_signed_attestations(all_pubkeys.iter(), new_min_target_epoch)
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
            .prune_all_signed_blocks(all_pubkeys.iter(), new_min_slot)
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
