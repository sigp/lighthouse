use crate::fork_service::ForkService;
use crate::validator_directory::{ValidatorDirectory, ValidatorDirectoryBuilder};
use parking_lot::{Mutex, RwLock};
use rayon::prelude::*;
use slashing_protection::{
    signed_attestation::SignedAttestation,
    signed_block::SignedBlock,
    validator_history::{SlashingProtection as SlashingProtectionTrait, ValidatorHistory},
};
use slog::{error, warn, Logger};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::read_dir;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Arc;
use tempdir::TempDir;
use types::{
    Attestation, BeaconBlock, ChainSpec, Domain, Epoch, EthSpec, Fork, Hash256, Keypair, PublicKey,
    SelectionProof, Signature, SignedAggregateAndProof, SignedBeaconBlock, SignedRoot, Slot,
};

struct VotingValidator {
    voting_keypair: Keypair,
    attestation_slashing_protection: Option<Arc<Mutex<ValidatorHistory<SignedAttestation>>>>,
    block_slashing_protection: Option<Arc<Mutex<ValidatorHistory<SignedBlock>>>>,
}

impl TryFrom<ValidatorDirectory> for VotingValidator {
    type Error = String;

    fn try_from(dir: ValidatorDirectory) -> Result<Self, Self::Error> {
        let slots_per_epoch = dir.slots_per_epoch;
        let attestation_slashing_protection = dir
            .attestation_slashing_protection
            .map(|path| {
                ValidatorHistory::open(&path, None).map_err(|e| {
                    format!(
                        "Error loading attester slashing protection from {:?}: {:?}",
                        path, e
                    )
                })
            })
            .transpose()?;
        let block_slashing_protection = dir
            .block_slashing_protection
            .map(|path| {
                ValidatorHistory::open(&path, slots_per_epoch).map_err(|e| {
                    format!(
                        "Error loading proposer slashing protection from {:?}: {:?}",
                        path, e
                    )
                })
            })
            .transpose()?;

        if attestation_slashing_protection.is_none() || block_slashing_protection.is_none() {
            return Err(
                "Validator cannot vote without attestation or block slashing protection"
                    .to_string(),
            );
        }

        Ok(Self {
            voting_keypair: dir
                .voting_keypair
                .ok_or_else(|| "Validator without voting keypair cannot vote".to_string())?,
            attestation_slashing_protection: attestation_slashing_protection
                .map(|v| Arc::new(Mutex::new(v))),
            block_slashing_protection: block_slashing_protection.map(|v| Arc::new(Mutex::new(v))),
        })
    }
}

#[derive(Clone)]
pub struct ValidatorStore<T, E: EthSpec> {
    validators: Arc<RwLock<HashMap<PublicKey, VotingValidator>>>,
    genesis_validators_root: Hash256,
    spec: Arc<ChainSpec>,
    log: Logger,
    temp_dir: Option<Arc<TempDir>>,
    fork_service: ForkService<T, E>,
    _phantom: PhantomData<E>,
}

impl<T: SlotClock + 'static, E: EthSpec> ValidatorStore<T, E> {
    pub fn load_from_disk(
        base_dir: PathBuf,
        genesis_validators_root: Hash256,
        spec: ChainSpec,
        fork_service: ForkService<T, E>,
        log: Logger,
    ) -> Result<Self, String> {
        println!("Loading validator store from disk, WTF");
        let validator_key_values = read_dir(&base_dir)
            .map_err(|e| format!("Failed to read base directory {:?}: {:?}", base_dir, e))?
            .collect::<Vec<_>>()
            .into_par_iter()
            .filter_map(|validator_dir| {
                let path = validator_dir.ok()?.path();

                if path.is_dir() {
                    match ValidatorDirectory::load_for_signing(path.clone(), E::slots_per_epoch()) {
                        Ok(validator_directory) => Some(validator_directory),
                        Err(e) => {
                            error!(
                                log,
                                "Failed to load a validator directory";
                                "error" => e,
                                "path" => path.to_str(),
                            );
                            None
                        }
                    }
                } else {
                    None
                }
            })
            .filter_map(|validator_directory| {
                match VotingValidator::try_from(validator_directory.clone()) {
                    Ok(voting_validator) => Some(voting_validator),
                    Err(e) => {
                        error!(

                            log,
                            "Unable to load validator from disk";
                            "error" => e,
                            "path" => format!("{:?}", validator_directory.directory)
                        );
                        None
                    }
                }
            })
            .map(|voting_validator| (voting_validator.voting_keypair.pk.clone(), voting_validator));

        Ok(Self {
            validators: Arc::new(RwLock::new(HashMap::from_par_iter(validator_key_values))),
            genesis_validators_root,
            spec: Arc::new(spec),
            log,
            temp_dir: None,
            fork_service,
            _phantom: PhantomData,
        })
    }

    pub fn insecure_ephemeral_validators(
        validator_indices: &[usize],
        genesis_validators_root: Hash256,
        spec: ChainSpec,
        fork_service: ForkService<T, E>,
        log: Logger,
    ) -> Result<Self, String> {
        println!("Loading vals from insecure keys");
        let temp_dir = TempDir::new("insecure_validator")
            .map_err(|e| format!("Unable to create temp dir: {:?}", e))?;
        let data_dir = PathBuf::from(temp_dir.path());

        let validators = validator_indices
            .par_iter()
            .map(|index| {
                ValidatorDirectoryBuilder::default()
                    .spec(spec.clone())
                    .slots_per_epoch(E::slots_per_epoch())
                    .full_deposit_amount()?
                    .insecure_keypairs(*index)
                    .create_directory(data_dir.clone())?
                    .write_keypair_files()?
                    .write_eth1_data_file()?
                    .create_sqlite_slashing_dbs()?
                    .build()
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter_map(|validator_directory| {
                match VotingValidator::try_from(validator_directory.clone()) {
                    Ok(voting_validator) => Some(voting_validator),
                    Err(e) => {
                        error!(
                            log,
                            "Unable to load insecure validator from disk";
                            "error" => e,
                            "path" => format!("{:?}", validator_directory.directory)
                        );
                        None
                    }
                }
            })
            .map(|voting_validator| (voting_validator.voting_keypair.pk.clone(), voting_validator));

        Ok(Self {
            validators: Arc::new(RwLock::new(HashMap::from_iter(validators))),
            genesis_validators_root,
            spec: Arc::new(spec),
            log,
            temp_dir: Some(Arc::new(temp_dir)),
            fork_service,
            _phantom: PhantomData,
        })
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
            .and_then(|validator_dir| {
                let voting_keypair = &validator_dir.voting_keypair;
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
        let validators = self.validators.read();

        // Retrieving the corresponding ValidatorDir
        let validator = validators.get(validator_pubkey)?;

        if validator.block_slashing_protection.is_none() {
            error!(
                self.log,
                "Validator does not have block slashing protection";
                "action" => "refused to produce block",
                "pubkey" => format!("{:?}", &validator.voting_keypair.pk),
            );
            return None;
        }

        // Making sure the block slot is not higher than the current slot to avoid potential attacks.
        if block.slot > current_slot {
            warn!(
                self.log,
                "Not signing block at slot {} > {}",
                block.slot.as_u64(),
                current_slot.as_u64()
            );
            return None;
        }

        // Checking for slashing conditions
        let slashing_status = validator
            .block_slashing_protection
            .as_ref()?
            .try_lock()?
            .update_if_valid(&block.block_header());

        match slashing_status {
            Ok(_) => {
                // We can safely sign this block
                let voting_keypair = &validator.voting_keypair;
                Some(block.sign(
                    &voting_keypair.sk,
                    &self.fork()?,
                    self.genesis_validators_root,
                    &self.spec,
                ))
            }
            Err(e) => {
                warn!(
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
        let validators = self.validators.read();

        // Retrieving the corresponding ValidatorDir
        let validator = validators.get(validator_pubkey)?;

        if validator.attestation_slashing_protection.is_none() {
            error!(
                self.log,
                "Validator does not have attestation slashing protection";
                "action" => "refused to produce attestation",
                "pubkey" => format!("{:?}", &validator.voting_keypair.pk),
            );
            return None;
        }

        // Making sure the target epoch is not higher than the current epoch to avoid potential attacks.
        if attestation.data.target.epoch > current_epoch {
            return None;
        }

        // Checking for slashing conditions
        let slashing_status = validator
            .attestation_slashing_protection
            .as_ref()?
            .try_lock()?
            .update_if_valid(&attestation.data);

        match slashing_status {
            Ok(_) => {
                // We can safely sign this attestation
                let voting_keypair = &validator.voting_keypair;

                attestation
                    .sign(
                        &voting_keypair.sk,
                        validator_committee_position,
                        &self.fork()?,
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
            Err(e) => {
                warn!(
                    self.log,
                    "Not signing slashable attestation";
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
    ) -> Option<SignedAggregateAndProof<E>> {
        let validators = self.validators.read();
        let voting_keypair = &validators.get(validator_pubkey)?.voting_keypair;

        Some(SignedAggregateAndProof::from_aggregate(
            validator_index,
            aggregate,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fork_service::ForkServiceBuilder;
    use beacon_node::beacon_chain::BeaconChainTypes;
    use beacon_node::{
        Client, ClientConfig, ClientGenesis, ProductionBeaconNode, ProductionClient,
    };
    use environment::{EnvironmentBuilder, RuntimeContext};
    use futures::future::Future;
    use remote_beacon_node::RemoteBeaconNode;
    use sloggers::{null::NullLoggerBuilder, Build};
    use slot_clock::SystemTimeSlotClock;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};
    use types::{
        AggregateSignature, AttestationData, BeaconBlockBody, BitList, Checkpoint, Epoch, Eth1Data,
        EthSpec, Hash256, MinimalEthSpec, Slot, VariableList,
    };

    // Create an attestation that is NOT signed, just for testing purposes.
    fn attestation_builder<T: EthSpec>(
        slot: u64,
        index: u64,
        committe_size: usize,
        source: u64,
        target: u64,
    ) -> Attestation<T> {
        let aggregation_bits = BitList::with_capacity(committe_size).expect("should build bitlist");
        let data = attestation_data_builder(slot, index, source, target);
        Attestation {
            aggregation_bits,
            data,
            signature: AggregateSignature::new(),
        }
    }

    fn checkpoint_builder(epoch: Epoch) -> Checkpoint {
        let root = Hash256::zero();
        Checkpoint { epoch, root }
    }

    fn attestation_data_builder(
        slot: u64,
        index: u64,
        source: u64,
        target: u64,
    ) -> AttestationData {
        let slot = Slot::from(slot);
        let source = Epoch::from(source);
        let target = Epoch::from(target);
        let source = checkpoint_builder(source);
        let target = checkpoint_builder(target);
        let beacon_block_root = Hash256::zero();
        AttestationData {
            slot,
            index,
            source,
            target,
            beacon_block_root,
        }
    }

    fn eth1_data_builder() -> Eth1Data {
        Eth1Data {
            deposit_root: Hash256::zero(),
            deposit_count: 0,
            block_hash: Hash256::zero(),
        }
    }
    fn beacon_block_body_builder<T: EthSpec>() -> BeaconBlockBody<T> {
        BeaconBlockBody {
            randao_reveal: Signature::empty_signature(),
            eth1_data: eth1_data_builder(),
            graffiti: [1; 32],
            proposer_slashings: VariableList::empty(),
            attester_slashings: VariableList::empty(),
            attestations: VariableList::empty(),
            deposits: VariableList::empty(),
            voluntary_exits: VariableList::empty(),
        }
    }

    fn block_builder<T: EthSpec>(slot: u64) -> BeaconBlock<T> {
        BeaconBlock {
            slot: Slot::from(slot),
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body: beacon_block_body_builder(),
        }
    }

    struct LocalBeaconNode<T> {
        pub client: T,
        pub datadir: TempDir,
    }

    impl<E: EthSpec> LocalBeaconNode<ProductionClient<E>> {
        /// Starts a new, production beacon node on the tokio runtime in the given `context`.
        ///
        /// The node created is using the same types as the node we use in production.
        pub fn production(context: RuntimeContext<E>, mut client_config: ClientConfig) -> Self {
            // Creates a temporary directory that will be deleted once this `TempDir` is dropped.
            let datadir = TempDir::new("lighthouse_node_test_rig")
                .expect("should create temp directory for client datadir");

            client_config.data_dir = datadir.path().into();
            client_config.network.network_dir = PathBuf::from(datadir.path()).join("network");

            let client = ProductionBeaconNode::new(context, client_config)
                .wait()
                .expect("should build production client")
                .into_inner();

            LocalBeaconNode { client, datadir }
        }
    }

    impl<T: BeaconChainTypes> LocalBeaconNode<Client<T>> {
        /// Returns a `RemoteBeaconNode` that can connect to `self`. Useful for testing the node as if
        /// it were external this process.
        fn remote_node(&self) -> Result<RemoteBeaconNode<T::EthSpec>, String> {
            let socket_addr = self
                .client
                .http_listen_addr()
                .ok_or_else(|| "A remote beacon node must have a http server".to_string())?;
            Ok(RemoteBeaconNode::new(format!(
                "http://{}:{}",
                socket_addr.ip(),
                socket_addr.port()
            ))?)
        }
    }

    fn testing_client_config() -> ClientConfig {
        let mut client_config = ClientConfig::default();

        // Setting ports to `0` means that the OS will choose some available port.
        client_config.network.libp2p_port = 0;
        client_config.network.discovery_port = 0;
        client_config.rest_api.port = 0;
        client_config.websocket_server.port = 0;

        client_config.dummy_eth1_backend = true;
        client_config.rest_api.enabled = true;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("should get system time")
            .as_secs();

        client_config.genesis = ClientGenesis::Interop {
            validator_count: 8,
            genesis_time: now,
        };

        client_config.dummy_eth1_backend = true;

        client_config
    }

    fn testing_validator_store() -> ValidatorStore<SystemTimeSlotClock, MinimalEthSpec> {
        let indices = [0];
        let spec = ChainSpec::minimal();
        let genesis_time = 12;
        let genesis_validators_root = Hash256::from_low_u64_le(44);
        let slot_clock = SystemTimeSlotClock::new(
            spec.genesis_slot,
            Duration::from_secs(genesis_time),
            Duration::from_millis(spec.milliseconds_per_slot),
        );
        let mut env = EnvironmentBuilder::minimal()
            .null_logger()
            .expect("should have null logger")
            .single_thread_tokio_runtime()
            .expect("should have single threaded runtime")
            .build()
            .expect("should have built environment");
        let beacon_node = LocalBeaconNode::production(env.core_context(), testing_client_config());
        let remote_beacon_node = beacon_node.remote_node().expect("should have remote node");
        let fork_service = ForkServiceBuilder::new()
            .slot_clock(slot_clock)
            .beacon_node(remote_beacon_node)
            .runtime_context(env.core_context().service_context("fork".to_string()))
            .build()
            .expect("should build fork service");
        fork_service
            .start_update_service(&spec)
            .expect("should start service");
        let log_builder = NullLoggerBuilder;
        let log = log_builder.build().expect("failed to start null logger");
        ValidatorStore::insecure_ephemeral_validators(
            &indices,
            genesis_validators_root,
            spec,
            fork_service,
            log,
        )
        .expect("should have built a validator store")
    }

    #[test]
    fn validator_store_attestation_test() {
        let validator_store = testing_validator_store();
        let slots_per_epoch = MinimalEthSpec::slots_per_epoch();
        let pubkeys = validator_store.voting_pubkeys();
        let committee_size = 125;
        let validator_committee_position = 3;

        let spec = ChainSpec::minimal();
        let genesis_time = 12;
        let slot_clock = SystemTimeSlotClock::new(
            spec.genesis_slot,
            Duration::from_secs(genesis_time),
            Duration::from_millis(spec.milliseconds_per_slot),
        );
        let current_epoch = slot_clock
            .now()
            .expect("should return current slot")
            .epoch(slots_per_epoch);

        let index = 2;

        // Perfectly valid attestation: expected to succeed.
        let slot = 0;
        let source = 0;
        let target = 1;
        let mut attestation =
            attestation_builder::<MinimalEthSpec>(slot, index, committee_size, source, target);
        let res = validator_store.sign_attestation(
            &pubkeys[0],
            validator_committee_position,
            &mut attestation,
            current_epoch,
        );
        assert_eq!(res, Some(()));

        // The exact same attestation: expected to succeed.
        let mut attestation =
            attestation_builder::<MinimalEthSpec>(slot, index, committee_size, source, target);
        let res = validator_store.sign_attestation(
            &pubkeys[0],
            validator_committee_position,
            &mut attestation,
            current_epoch,
        );
        assert_eq!(res, Some(()));

        // DoubleVote because the slot is different: expected to fail.
        let slot = slot + 1;
        let mut attestation =
            attestation_builder::<MinimalEthSpec>(slot, index, committee_size, source, target);
        let res = validator_store.sign_attestation(
            &pubkeys[0],
            validator_committee_position,
            &mut attestation,
            current_epoch,
        );
        assert_eq!(res, None);

        // Valid attestation with target higher than the one signed before: expected to succeed.
        let target = target + 1;
        dbg!(target);
        let mut attestation =
            attestation_builder::<MinimalEthSpec>(slot, index, committee_size, source, target);
        let res = validator_store.sign_attestation(
            &pubkeys[0],
            validator_committee_position,
            &mut attestation,
            current_epoch,
        );
        assert_eq!(res, Some(()));

        // Pruning error: target is smaller than the first one in the db: expected to fail.
        let target = 0;
        let mut attestation =
            attestation_builder::<MinimalEthSpec>(slot, index, committee_size, source, target);
        let res = validator_store.sign_attestation(
            &pubkeys[0],
            validator_committee_position,
            &mut attestation,
            current_epoch,
        );
        assert_eq!(res, None);

        // Valid attestation: expected to succeed.
        let source = 2;
        let target = 4;
        let mut attestation =
            attestation_builder::<MinimalEthSpec>(slot, index, committee_size, source, target);
        let res = validator_store.sign_attestation(
            &pubkeys[0],
            validator_committee_position,
            &mut attestation,
            current_epoch,
        );
        assert_eq!(res, Some(()));

        // Valid attestation: expected to succeed.
        let source = 3;
        let target = 5;
        let mut attestation =
            attestation_builder::<MinimalEthSpec>(slot, index, committee_size, source, target);
        let res = validator_store.sign_attestation(
            &pubkeys[0],
            validator_committee_position,
            &mut attestation,
            current_epoch,
        );
        assert_eq!(res, Some(()));

        // Surrounding vote: expected to fail.
        let source = 2;
        let target = 6;
        let mut attestation =
            attestation_builder::<MinimalEthSpec>(slot, index, committee_size, source, target);
        let res = validator_store.sign_attestation(
            &pubkeys[0],
            validator_committee_position,
            &mut attestation,
            current_epoch,
        );
        assert_eq!(res, None);

        // Valid attestation: expected to succeeded.
        let source = 5;
        let target = 10;
        let mut attestation =
            attestation_builder::<MinimalEthSpec>(slot, index, committee_size, source, target);
        let res = validator_store.sign_attestation(
            &pubkeys[0],
            validator_committee_position,
            &mut attestation,
            current_epoch,
        );
        assert_eq!(res, Some(()));

        // Surrounded vote: expected to fail.
        let source = 6;
        let target = 7;
        let mut attestation =
            attestation_builder::<MinimalEthSpec>(slot, index, committee_size, source, target);
        let res = validator_store.sign_attestation(
            &pubkeys[0],
            validator_committee_position,
            &mut attestation,
            current_epoch,
        );
        assert_eq!(res, None);

        // Valid attestation: expected to succeed.
        let source = 3;
        let target = 6;
        let mut attestation =
            attestation_builder::<MinimalEthSpec>(slot, index, committee_size, source, target);
        let res = validator_store.sign_attestation(
            &pubkeys[0],
            validator_committee_position,
            &mut attestation,
            current_epoch,
        );
        assert_eq!(res, Some(()));

        // Random public key: expected to fail.
        let mut attestation =
            attestation_builder::<MinimalEthSpec>(slot, index, committee_size, source, target);
        let res = validator_store.sign_attestation(
            &PublicKey::default(),
            validator_committee_position,
            &mut attestation,
            current_epoch,
        );
        assert_eq!(res, None);

        // Invalid attestation: target == source: expected to fail.
        let source = source + 1;
        let target = source;
        let mut attestation =
            attestation_builder::<MinimalEthSpec>(slot, index, committee_size, source, target);
        let res = validator_store.sign_attestation(
            &pubkeys[0],
            validator_committee_position,
            &mut attestation,
            current_epoch,
        );
        assert_eq!(res, None);

        // Valid attestation: target epoch is the same as the current epoch.
        let source = source + 1;
        let target = current_epoch.into();
        let mut attestation =
            attestation_builder::<MinimalEthSpec>(slot, index, committee_size, source, target);
        let res = validator_store.sign_attestation(
            &pubkeys[0],
            validator_committee_position,
            &mut attestation,
            current_epoch,
        );
        assert_eq!(res, Some(()));

        // Invalid attestation: target epoch is higher than current epoch.
        let source = source + 1;
        let target = target + 1;
        let mut attestation =
            attestation_builder::<MinimalEthSpec>(slot, index, committee_size, source, target);
        let res = validator_store.sign_attestation(
            &pubkeys[0],
            validator_committee_position,
            &mut attestation,
            current_epoch,
        );
        assert_eq!(res, None);
    }

    #[test]
    fn validator_store_block_protection_test() {
        let validator_store = testing_validator_store();
        let slots_per_epoch = MinimalEthSpec::slots_per_epoch();
        let pubkeys = validator_store.voting_pubkeys();

        let spec = ChainSpec::minimal();
        let genesis_time = 12;
        let slot_clock = SystemTimeSlotClock::new(
            spec.genesis_slot,
            Duration::from_secs(genesis_time),
            Duration::from_millis(spec.milliseconds_per_slot),
        );

        // Perfectly valid block: expected to succeed.
        let slot = slots_per_epoch;
        let block = block_builder(slot);

        let res = validator_store
            .sign_block(
                &pubkeys[0],
                block.clone(),
                slot_clock
                    .now()
                    .expect("should have returned the current slot"),
            )
            .expect("signs successfully");
        assert_eq!(res.message, block);

        // Valid block: expected to succeed.
        let slot = 2 * slots_per_epoch;
        let block = block_builder(slot);
        let res = validator_store
            .sign_block(
                &pubkeys[0],
                block.clone(),
                slot_clock
                    .now()
                    .expect("should have returned the current slot"),
            )
            .expect("signed successfully");
        assert_eq!(res.message, block);

        // Re-publishing block: expected to succeed.
        let slot = 2 * slots_per_epoch;
        let block = block_builder(slot);
        let res = validator_store
            .sign_block(
                &pubkeys[0],
                block.clone(),
                slot_clock
                    .now()
                    .expect("should have returned the current slot"),
            )
            .expect("signed successfully");
        assert_eq!(res.message, block);

        // Valid block: expected to succeed.
        let slot = 5 * slots_per_epoch;
        let block = block_builder(slot);
        let res = validator_store
            .sign_block(
                &pubkeys[0],
                block.clone(),
                slot_clock
                    .now()
                    .expect("should have returned the current slot"),
            )
            .expect("signed successfully");
        assert_eq!(res.message, block);

        // Valid block: expected to succeed.
        let slot = 3 * slots_per_epoch;
        let block = block_builder(slot);
        let res = validator_store
            .sign_block(
                &pubkeys[0],
                block.clone(),
                slot_clock
                    .now()
                    .expect("should have returned the current slot"),
            )
            .expect("signed successfully");
        assert_eq!(res.message, block);

        // Block slot earlier than first entry: expected to fail.
        let slot = 0;
        let block = block_builder(slot);
        let res = validator_store.sign_block(
            &pubkeys[0],
            block,
            slot_clock
                .now()
                .expect("should have returned the current slot"),
        );
        assert_eq!(res, None);

        // Conflicting block with slot 3: expected to fail.
        let slot = 3 * slots_per_epoch;
        let mut block = block_builder(slot);
        block.parent_root = Hash256::random();
        let res = validator_store.sign_block(
            &pubkeys[0],
            block,
            slot_clock
                .now()
                .expect("should have returned the current slot"),
        );
        assert_eq!(res, None);

        // Conflicting block with slot 3: expected to fail.
        let slot = 3 * slots_per_epoch;
        let mut block = block_builder(slot);
        block.state_root = Hash256::random();
        let res = validator_store.sign_block(
            &pubkeys[0],
            block,
            slot_clock
                .now()
                .expect("should have returned the current slot"),
        );
        assert_eq!(res, None);

        // Block slot is the current one: expected to succeed.
        let slot = slot_clock
            .now()
            .expect("should have returned the current slot");
        let mut block = block_builder(slot.as_u64());
        block.state_root = Hash256::random();
        let res = validator_store
            .sign_block(&pubkeys[0], block.clone(), slot)
            .expect("signed successfully");
        assert_eq!(res.message, block);

        // Block slot is in the future: expected to fail.
        let slot = slot_clock
            .now()
            .expect("should have returned the current slot");
        let mut block = block_builder(slot.as_u64() + 1);
        block.state_root = Hash256::random();
        let res = validator_store.sign_block(&pubkeys[0], block, slot);
        assert_eq!(res, None);
    }
}
