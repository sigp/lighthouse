use crate::config::SLASHING_PROTECTION_FILENAME;
use crate::{config::Config, fork_service::ForkService};
use parking_lot::RwLock;
use slashing_protection::{NotSafe, Safe, SlashingDatabase};
use slog::{crit, error, warn, Logger};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::sync::Arc;
use tempdir::TempDir;
use types::{
    Attestation, BeaconBlock, ChainSpec, Domain, Epoch, EthSpec, Fork, Hash256, Keypair, PublicKey,
    SelectionProof, Signature, SignedAggregateAndProof, SignedBeaconBlock, SignedRoot, Slot,
};
use validator_dir::{Manager as ValidatorManager, ValidatorDir};

#[derive(PartialEq)]
struct LocalValidator {
    validator_dir: ValidatorDir,
    voting_keypair: Keypair,
}

#[derive(Clone)]
pub struct ValidatorStore<T, E: EthSpec> {
    validators: Arc<RwLock<HashMap<PublicKey, LocalValidator>>>,
    slashing_protection: SlashingDatabase,
    genesis_validators_root: Hash256,
    spec: Arc<ChainSpec>,
    log: Logger,
    temp_dir: Option<Arc<TempDir>>,
    fork_service: ForkService<T, E>,
    _phantom: PhantomData<E>,
}

impl<T: SlotClock + 'static, E: EthSpec> ValidatorStore<T, E> {
    pub fn load_from_disk(
        config: &Config,
        genesis_validators_root: Hash256,
        spec: ChainSpec,
        fork_service: ForkService<T, E>,
        log: Logger,
    ) -> Result<Self, String> {
        let slashing_db_path = config.data_dir.join(SLASHING_PROTECTION_FILENAME);
        let slashing_protection =
            SlashingDatabase::open_or_create(&slashing_db_path).map_err(|e| {
                format!(
                    "Failed to open or create slashing protection database: {:?}",
                    e
                )
            })?;

        let validator_key_values = ValidatorManager::open(&config.data_dir)
            .map_err(|e| format!("unable to read data_dir: {:?}", e))?
            .decrypt_all_validators(config.secrets_dir.clone())
            .map_err(|e| format!("unable to decrypt all validator directories: {:?}", e))?
            .into_iter()
            .map(|(kp, dir)| {
                (
                    kp.pk.clone(),
                    LocalValidator {
                        validator_dir: dir,
                        voting_keypair: kp,
                    },
                )
            });

        Ok(Self {
            validators: Arc::new(RwLock::new(HashMap::from_iter(validator_key_values))),
            slashing_protection,
            genesis_validators_root,
            spec: Arc::new(spec),
            log,
            temp_dir: None,
            fork_service,
            _phantom: PhantomData,
        })
    }

    /// Register all known validators with the slashing protection database.
    ///
    /// Registration is required to protect against a lost or missing slashing database,
    /// such as when relocating validator keys to a new machine.
    pub fn register_all_validators_for_slashing_protection(&self) -> Result<(), String> {
        self.slashing_protection
            .register_validators(self.validators.read().keys())
            .map_err(|e| format!("Error while registering validators: {:?}", e))
    }

    pub fn voting_pubkeys(&self) -> Vec<PublicKey> {
        self.validators
            .read()
            .iter()
            .map(|(pubkey, _dir)| pubkey.clone())
            .collect()
    }

    pub fn num_voting_validators(&self) -> usize {
        self.validators.read().len()
    }

    fn fork(&self) -> Option<Fork> {
        if self.fork_service.fork().is_none() {
            error!(
                self.log,
                "Unable to get Fork for signing";
            );
        }
        self.fork_service.fork()
    }

    pub fn randao_reveal(&self, validator_pubkey: &PublicKey, epoch: Epoch) -> Option<Signature> {
        // TODO: check this against the slot clock to make sure it's not an early reveal?
        self.validators
            .read()
            .get(validator_pubkey)
            .and_then(|local_validator| {
                let voting_keypair = &local_validator.voting_keypair;
                let domain = self.spec.get_domain(
                    epoch,
                    Domain::Randao,
                    &self.fork()?,
                    self.genesis_validators_root,
                );
                let message = epoch.signing_root(domain);

                Some(Signature::new(message.as_bytes(), &voting_keypair.sk))
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
        let fork = self.fork()?;
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
                let validator = validators.get(validator_pubkey)?;
                let voting_keypair = &validator.voting_keypair;

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
                None
            }
            Err(NotSafe::UnregisteredValidator(pk)) => {
                warn!(
                    self.log,
                    "Not signing block for unregistered validator";
                    "msg" => "Carefully consider running with --auto-register (see --help)",
                    "public_key" => format!("{:?}", pk)
                );
                None
            }
            Err(e) => {
                crit!(
                    self.log,
                    "Not signing slashable block";
                    "error" => format!("{:?}", e)
                );
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
        let fork = self.fork()?;

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
                let validator = validators.get(validator_pubkey)?;
                let voting_keypair = &validator.voting_keypair;

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

                Some(())
            }
            Ok(Safe::SameData) => {
                warn!(
                    self.log,
                    "Skipping signing of previously signed attestation"
                );
                None
            }
            Err(NotSafe::UnregisteredValidator(pk)) => {
                warn!(
                    self.log,
                    "Not signing attestation for unregistered validator";
                    "msg" => "Carefully consider running with --auto-register (see --help)",
                    "public_key" => format!("{:?}", pk)
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
        let voting_keypair = &validators.get(validator_pubkey)?.voting_keypair;

        Some(SignedAggregateAndProof::from_aggregate(
            validator_index,
            aggregate,
            Some(selection_proof),
            &voting_keypair.sk,
            &self.fork()?,
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
        let voting_keypair = &validators.get(validator_pubkey)?.voting_keypair;

        Some(SelectionProof::new::<E>(
            slot,
            &voting_keypair.sk,
            &self.fork()?,
            self.genesis_validators_root,
            &self.spec,
        ))
    }
}
