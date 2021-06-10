use crate::{
    doppelganger_service::DoppelgangerService, fork_service::ForkService, http_metrics::metrics,
    initialized_validators::InitializedValidators,
};
use account_utils::{validator_definitions::ValidatorDefinition, ZeroizeString};
use parking_lot::{Mutex, RwLock};
use slashing_protection::{NotSafe, Safe, SlashingDatabase};
use slog::{crit, error, info, warn, Logger};
use slot_clock::SlotClock;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;
use types::{
    attestation::Error as AttestationError, graffiti::GraffitiString, Attestation, BeaconBlock,
    ChainSpec, Domain, Epoch, EthSpec, Fork, Graffiti, Hash256, Keypair, PublicKeyBytes,
    SelectionProof, Signature, SignedAggregateAndProof, SignedBeaconBlock, SignedRoot, Slot,
};
use validator_dir::ValidatorDir;

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

#[derive(Clone)]
pub struct ValidatorStore<T, E: EthSpec> {
    validators: Arc<RwLock<InitializedValidators>>,
    slashing_protection: SlashingDatabase,
    slashing_protection_last_prune: Arc<Mutex<Epoch>>,
    genesis_validators_root: Hash256,
    spec: Arc<ChainSpec>,
    log: Logger,
    temp_dir: Option<Arc<TempDir>>,
    doppelganger_service: Option<DoppelgangerService<T, E>>,
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
            doppelganger_service: None,
            fork_service,
        }
    }

    pub fn attach_doppelganger_service(
        &mut self,
        service: DoppelgangerService<T, E>,
    ) -> Result<(), String> {
        if self.doppelganger_service.is_some() {
            return Err("Cannot attach doppelganger service twice".to_string());
        }

        // Ensure all existing validators are registered with the service.
        for pubkey in self.validators.read().iter_voting_pubkeys() {
            service.register_new_validator(*pubkey)?
        }

        self.doppelganger_service = Some(service);

        Ok(())
    }

    pub fn initialized_validators(&self) -> Arc<RwLock<InitializedValidators>> {
        self.validators.clone()
    }

    pub fn slot_clock(&self) -> T {
        self.fork_service.slot_clock()
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

        if let Some(doppelganger_service) = self.doppelganger_service.as_ref() {
            doppelganger_service.register_new_validator(validator_pubkey)?;
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

    /// Returns all public keys that are required for duties collection. This includes all initialized
    /// validators regardless of doppelganger detection status. We want to continue to collect duties
    /// during doppelganger detection periods because we want to continue to subscribe to the correct
    /// subnets.
    pub fn all_pubkeys(&self) -> Vec<PublicKeyBytes> {
        self.validators
            .read()
            .iter_voting_pubkeys()
            .cloned()
            .collect()
    }

    /// Check if the `validator_pubkey` is permitted by the doppleganger protection to sign
    /// messages.
    ///
    /// Returns:
    ///
    /// - Ok(()): if the validator is permitted to sign.
    /// - Err(e): if the validator is not permitted to sign.
    pub fn doppelganger_protection_allows_signing(
        &self,
        validator_pubkey: &PublicKeyBytes,
    ) -> Result<(), Error> {
        if let Some(doppelganger_service) = &self.doppelganger_service {
            match doppelganger_service.validator_should_sign(validator_pubkey) {
                Some(true) => Ok(()),
                Some(false) => Err(Error::DoppelgangerProtected(*validator_pubkey)),
                None => Err(Error::UnknownToDoppelgangerService(*validator_pubkey)),
            }
        } else {
            Ok(())
        }
    }

    /// Returns all the validators permitted to sign attestations, blocks and other consensus
    /// messages.
    ///
    /// Excludes any validators which are undergoing a doppelganger protection period.
    pub fn signing_pubkeys(&self) -> Vec<PublicKeyBytes> {
        let mut pubkeys = self
            .validators
            .read()
            .iter_voting_pubkeys()
            .cloned()
            .collect::<Vec<_>>();

        // Filter out all pubkeys which should not sign because they're undergoing doppelganger
        // protection.
        //
        // This filtering happens in it's own `retain` call to avoid interleaving locks.
        pubkeys.retain(|pubkey| {
            if let Some(doppelganger_service) = self.doppelganger_service.as_ref() {
                if let Some(should_sign) = doppelganger_service.validator_should_sign(pubkey) {
                    // Doppleganger protection is enabled and the validator is known to it.
                    should_sign
                } else {
                    crit!(
                        self.log,
                        "Doppelganger validator missing";
                        "msg" => "internal consistency error, preventing validator from signing",
                        "pubkey" => ?pubkey,
                    );

                    // Do not retain any validator that has not been registered with the validator
                    // service.
                    false
                }
            } else {
                // Retain all pubkeys if there is no doppelganger protection enabled.
                true
            }
        });

        pubkeys
    }

    /// Returns a `HashSet` of all public keys that are required for signing attestations and blocks.
    /// This will exclude initialized validators that are currently in a doppelganger detection period.
    pub fn signing_pubkeys_hashset(&self) -> HashSet<PublicKeyBytes> {
        self.validators.read().voting_pubkeys().cloned().collect()
    }

    pub fn num_voting_validators(&self) -> usize {
        self.validators.read().num_enabled()
    }

    fn fork(&self) -> Fork {
        self.fork_service.fork()
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
        validator_pubkey: &PublicKeyBytes,
        func: F,
    ) -> Result<R, Error>
    where
        F: FnOnce(&Keypair) -> R,
    {
        // If the doppelganger service is active, check to ensure it explicitly permits signing by
        // this validator.
        self.doppelganger_protection_allows_signing(validator_pubkey)?;

        let validators_lock = self.validators.read();

        Ok(func(
            validators_lock
                .voting_keypair(validator_pubkey)
                .ok_or_else(|| Error::UnknownPubkey(*validator_pubkey))?,
        ))
    }

    pub fn randao_reveal(
        &self,
        validator_pubkey: &PublicKeyBytes,
        epoch: Epoch,
    ) -> Result<Signature, Error> {
        let domain = self.spec.get_domain(
            epoch,
            Domain::Randao,
            &self.fork(),
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
        validator_pubkey: &PublicKeyBytes,
        block: BeaconBlock<E>,
        current_slot: Slot,
    ) -> Result<SignedBeaconBlock<E>, Error> {
        // Make sure the block slot is not higher than the current slot to avoid potential attacks.
        if block.slot > current_slot {
            warn!(
                self.log,
                "Not signing block with slot greater than current slot";
                "block_slot" => block.slot.as_u64(),
                "current_slot" => current_slot.as_u64()
            );
            return Err(Error::GreaterThanCurrentSlot {
                slot: block.slot,
                current_slot,
            });
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
        validator_pubkey: &PublicKeyBytes,
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
        validator_pubkey: &PublicKeyBytes,
        validator_index: u64,
        aggregate: Attestation<E>,
        selection_proof: SelectionProof,
    ) -> Result<SignedAggregateAndProof<E>, Error> {
        // Take the fork early to avoid lock interleaving.
        let fork = self.fork();

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
        validator_pubkey: &PublicKeyBytes,
        slot: Slot,
    ) -> Result<SelectionProof, Error> {
        // Take the fork early to avoid lock interleaving.
        let fork = self.fork();

        let proof = self.with_validator_keypair(validator_pubkey, |keypair| {
            SelectionProof::new::<E>(
                slot,
                &keypair.sk,
                &fork,
                self.genesis_validators_root,
                &self.spec,
            )
        })?;

        metrics::inc_counter_vec(&metrics::SIGNED_SELECTION_PROOFS_TOTAL, &[metrics::SUCCESS]);

        Ok(proof)
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

        let all_pubkeys = self.all_pubkeys();
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
