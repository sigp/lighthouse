use crate::{
    test_utils::DEFAULT_JWT_SECRET, test_utils::MockExecutionConfig, test_utils::MockServer, *,
};
use alloy_primitives::B256 as H256;
use fixed_bytes::FixedBytesExtended;
use kzg::Kzg;
use tempfile::NamedTempFile;
use types::MainnetEthSpec;

pub struct MockExecutionLayer<E: EthSpec> {
    pub server: MockServer<E>,
    pub el: ExecutionLayer<E>,
    pub executor: TaskExecutor,
    pub spec: Arc<ChainSpec>,
}

/// Env var that switches every test-infra `MockExecutionLayer` from JSON-RPC to REST-SSZ.
///
/// Off (unset) by default so the JSON-RPC path is always exercised. Because all mocks — including
/// the `beacon_chain` harness's `mock_execution_layer_from_parts` — funnel through
/// `MockExecutionLayer::new`, setting this flips the transport across the whole test tree with no
/// per-crate Cargo plumbing, e.g. `MOCK_REST_SSZ=1 cargo nextest run`.
pub const MOCK_REST_SSZ_ENV_VAR: &str = "MOCK_REST_SSZ";

pub fn mock_rest_ssz_enabled() -> bool {
    std::env::var(MOCK_REST_SSZ_ENV_VAR)
        .map(|v| !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
}

impl<E: EthSpec> MockExecutionLayer<E> {
    pub fn default_params(executor: TaskExecutor) -> Self {
        let mut spec = MainnetEthSpec::default_spec();
        spec.terminal_block_hash = ExecutionBlockHash::zero();
        spec.terminal_block_hash_activation_epoch = Epoch::new(0);
        Self::new(
            executor,
            None,
            None,
            None,
            None,
            None,
            Some(JwtKey::from_slice(&DEFAULT_JWT_SECRET).unwrap()),
            Arc::new(spec),
            None,
        )
    }

    pub fn fulu_params(executor: TaskExecutor) -> Self {
        let mut spec = MainnetEthSpec::default_spec();
        spec.terminal_block_hash = ExecutionBlockHash::zero();
        spec.terminal_block_hash_activation_epoch = Epoch::new(0);
        Self::new(
            executor,
            Some(0),
            Some(0),
            Some(0),
            Some(0),
            None,
            Some(JwtKey::from_slice(&DEFAULT_JWT_SECRET).unwrap()),
            Arc::new(spec),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        executor: TaskExecutor,
        shanghai_time: Option<u64>,
        cancun_time: Option<u64>,
        prague_time: Option<u64>,
        osaka_time: Option<u64>,
        amsterdam_time: Option<u64>,
        jwt_key: Option<JwtKey>,
        spec: Arc<ChainSpec>,
        kzg: Option<Arc<Kzg>>,
    ) -> Self {
        let handle = executor.handle().unwrap();

        let rest_ssz = mock_rest_ssz_enabled();

        let jwt_key = jwt_key.unwrap_or_else(JwtKey::random);
        let server = MockServer::new_with_config(
            &handle,
            MockExecutionConfig {
                jwt_key,
                shanghai_time,
                cancun_time,
                prague_time,
                osaka_time,
                amsterdam_time,
                serve_rest_ssz: rest_ssz,
                ..Default::default()
            },
            kzg,
        );

        let url = SensitiveUrl::parse(&server.url()).unwrap();
        let file = NamedTempFile::new().unwrap();

        let path = file.path().into();
        std::fs::write(&path, hex::encode(DEFAULT_JWT_SECRET)).unwrap();

        let config = Config {
            execution_endpoint: Some(url),
            secret_file: Some(path),
            suggested_fee_recipient: Some(Address::repeat_byte(42)),
            engine_api_rest_ssz: rest_ssz,
            ..Default::default()
        };
        let el = ExecutionLayer::from_config(config, executor.clone()).unwrap();

        Self {
            server,
            el,
            executor,
            spec,
        }
    }

    /// Resolve the engine transport with an **awaited** upcheck, then assert it matches the mode
    /// selected by `MOCK_REST_SSZ` (`Rest` when set, `JsonRpcOnly` otherwise).
    pub async fn resolve_and_assert_transport(self) -> Self {
        self.el.upcheck().await;
        let expected = if mock_rest_ssz_enabled() {
            Transport::Rest
        } else {
            Transport::JsonRpcOnly
        };
        assert_eq!(self.el.resolved_transport(), Some(expected));
        self
    }

    pub async fn produce_valid_execution_payload_on_head(self) -> Self {
        let latest_execution_block = {
            let block_gen = self.server.execution_block_generator();
            block_gen.latest_block().unwrap()
        };

        let parent_hash = latest_execution_block.block_hash();
        let parent_gas_limit = latest_execution_block.gas_limit();
        let block_number = latest_execution_block.block_number() + 1;
        let timestamp = block_number;
        let prev_randao = Hash256::from_low_u64_be(block_number);
        let head_block_root = Hash256::repeat_byte(42);
        // TODO(gloas): allow statuses other than Pending?
        let head_payload_status = fork_choice::PayloadStatus::Pending;
        let forkchoice_update_params = ForkchoiceUpdateParameters {
            head_root: head_block_root,
            head_hash: Some(parent_hash),
            justified_hash: None,
            finalized_hash: None,
        };
        let payload_attributes = PayloadAttributes::new(
            timestamp,
            prev_randao,
            Address::repeat_byte(42),
            None,
            None,
            None,
            None,
        );

        // Insert a proposer to ensure the fork choice updated command works.
        let slot = Slot::new(0);
        let validator_index = 0;
        self.el
            .insert_proposer(
                slot,
                head_block_root,
                head_payload_status,
                validator_index,
                payload_attributes,
            )
            .await;

        self.el
            .notify_forkchoice_updated(
                parent_hash,
                ExecutionBlockHash::zero(),
                ExecutionBlockHash::zero(),
                slot,
                head_block_root,
                head_payload_status,
                ForkName::Bellatrix,
            )
            .await
            .unwrap();

        let validator_index = 0;
        let builder_params = BuilderParams {
            pubkey: PublicKeyBytes::empty(),
            slot,
            chain_health: ChainHealth::Healthy,
        };
        let suggested_fee_recipient = self.el.get_suggested_fee_recipient(validator_index).await;
        let payload_attributes = PayloadAttributes::new(
            timestamp,
            prev_randao,
            suggested_fee_recipient,
            None,
            None,
            None,
            None,
        );

        let payload_parameters = PayloadParameters {
            parent_hash,
            parent_gas_limit: Some(parent_gas_limit),
            proposer_gas_limit: None,
            payload_attributes: &payload_attributes,
            forkchoice_update_params: &forkchoice_update_params,
            current_fork: ForkName::Bellatrix,
        };

        let block_proposal_content_type = self
            .el
            .get_payload(
                payload_parameters,
                builder_params,
                &self.spec,
                None,
                BlockProductionVersion::FullV2,
            )
            .await
            .unwrap();

        let payload: ExecutionPayload<E> = match block_proposal_content_type {
            BlockProposalContentsType::Full(block) => block.to_payload().into(),
            BlockProposalContentsType::Blinded(_) => panic!("Should always be a full payload"),
        };

        let block_hash = payload.block_hash();
        assert_eq!(payload.parent_hash(), parent_hash);
        assert_eq!(payload.block_number(), block_number);
        assert_eq!(payload.timestamp(), timestamp);
        assert_eq!(payload.prev_randao(), prev_randao);

        // Ensure the payload cache is empty.
        assert!(
            self.el
                .get_payload_by_root(&payload.tree_hash_root())
                .is_none()
        );
        let builder_params = BuilderParams {
            pubkey: PublicKeyBytes::empty(),
            slot,
            chain_health: ChainHealth::Healthy,
        };
        let suggested_fee_recipient = self.el.get_suggested_fee_recipient(validator_index).await;
        let payload_attributes = PayloadAttributes::new(
            timestamp,
            prev_randao,
            suggested_fee_recipient,
            None,
            None,
            None,
            None,
        );

        let payload_parameters = PayloadParameters {
            parent_hash,
            parent_gas_limit: Some(parent_gas_limit),
            proposer_gas_limit: None,
            payload_attributes: &payload_attributes,
            forkchoice_update_params: &forkchoice_update_params,
            current_fork: ForkName::Bellatrix,
        };

        let block_proposal_content_type = self
            .el
            .get_payload(
                payload_parameters,
                builder_params,
                &self.spec,
                None,
                BlockProductionVersion::BlindedV2,
            )
            .await
            .unwrap();

        match block_proposal_content_type {
            BlockProposalContentsType::Full(block) => {
                let payload_header = block.to_payload();
                self.assert_valid_execution_payload_on_head(
                    payload,
                    payload_header,
                    block_hash,
                    parent_hash,
                    block_number,
                    timestamp,
                    prev_randao,
                    ForkName::Bellatrix,
                )
                .await;
            }
            BlockProposalContentsType::Blinded(block) => {
                let payload_header = block.to_payload();
                self.assert_valid_execution_payload_on_head(
                    payload,
                    payload_header,
                    block_hash,
                    parent_hash,
                    block_number,
                    timestamp,
                    prev_randao,
                    ForkName::Bellatrix,
                )
                .await;
            }
        };

        self
    }

    pub async fn reconcile_unknown_payload_on_head(self) -> Self {
        let latest_execution_block = {
            let block_gen = self.server.execution_block_generator();
            block_gen.latest_block().unwrap()
        };

        let parent_hash = latest_execution_block.block_hash();
        let parent_gas_limit = latest_execution_block.gas_limit();
        let block_number = latest_execution_block.block_number() + 1;
        let timestamp = block_number;
        let prev_randao = Hash256::from_low_u64_be(block_number);
        let head_block_root = Hash256::repeat_byte(42);
        let slot = Slot::new(0);
        let validator_index = 0;

        let current_fork = self
            .server
            .execution_block_generator()
            .get_fork_at_timestamp(timestamp);

        let forkchoice_update_params = ForkchoiceUpdateParameters {
            head_root: head_block_root,
            head_hash: Some(parent_hash),
            justified_hash: None,
            finalized_hash: None,
        };
        let suggested_fee_recipient = self.el.get_suggested_fee_recipient(validator_index).await;
        let payload_attributes = PayloadAttributes::new(
            timestamp,
            prev_randao,
            suggested_fee_recipient,
            current_fork.capella_enabled().then(Vec::new),
            current_fork.deneb_enabled().then(Hash256::zero),
            None,
            None,
        );

        let build_params = || PayloadParameters {
            parent_hash,
            parent_gas_limit: Some(parent_gas_limit),
            proposer_gas_limit: None,
            payload_attributes: &payload_attributes,
            forkchoice_update_params: &forkchoice_update_params,
            current_fork,
        };
        let builder_params = || BuilderParams {
            pubkey: PublicKeyBytes::empty(),
            slot,
            chain_health: ChainHealth::Healthy,
        };

        self.el
            .get_payload(
                build_params(),
                builder_params(),
                &self.spec,
                None,
                BlockProductionVersion::FullV2,
            )
            .await
            .unwrap();

        let expired_before = crate::metrics::get_int_counter(
            &crate::metrics::EXECUTION_LAYER_PRE_PREPARED_PAYLOAD_ID,
            &[crate::metrics::EXPIRED],
        )
        .map(|counter| counter.get())
        .unwrap_or(0);

        // Make the cached id unknown to the EL so the next `get_payload` reconciles.
        self.server.expire_all_payload_ids();

        // Same `(parent_hash, attrs)`: cache HIT the stale id -> unknown-payload -> re-fcU -> retry once.
        self.el
            .get_payload(
                build_params(),
                builder_params(),
                &self.spec,
                None,
                BlockProductionVersion::FullV2,
            )
            .await
            .unwrap();

        let expired_after = crate::metrics::get_int_counter(
            &crate::metrics::EXECUTION_LAYER_PRE_PREPARED_PAYLOAD_ID,
            &[crate::metrics::EXPIRED],
        )
        .map(|counter| counter.get())
        .unwrap_or(0);
        assert_eq!(
            expired_after,
            expired_before + 1,
            "reconcile did not fire: cached id was not observed as unknown-payload"
        );

        self
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn assert_valid_execution_payload_on_head<Payload: AbstractExecPayload<E>>(
        &self,
        payload: ExecutionPayload<E>,
        payload_header: Payload,
        block_hash: ExecutionBlockHash,
        parent_hash: ExecutionBlockHash,
        block_number: u64,
        timestamp: u64,
        prev_randao: H256,
        fork: ForkName,
    ) {
        assert_eq!(payload_header.block_hash(), block_hash);
        assert_eq!(payload_header.parent_hash(), parent_hash);
        assert_eq!(payload_header.block_number(), block_number);
        assert_eq!(payload_header.timestamp(), timestamp);
        assert_eq!(payload_header.prev_randao(), prev_randao);

        // Ensure the payload cache has the correct payload.
        assert_eq!(
            self.el
                .get_payload_by_root(&payload_header.tree_hash_root()),
            Some(FullPayloadContents::Payload(payload.clone()))
        );

        // TODO: again consider forks
        let status = self
            .el
            .notify_new_payload(payload.to_ref().try_into().unwrap())
            .await
            .unwrap();
        assert_eq!(status, PayloadStatus::Valid);

        // Use junk values for slot/head-root to ensure there is no payload supplied.
        let slot = Slot::new(0);
        let head_block_root = Hash256::repeat_byte(13);
        // TODO(gloas): reconsider the state_payload_status
        self.el
            .notify_forkchoice_updated(
                block_hash,
                ExecutionBlockHash::zero(),
                ExecutionBlockHash::zero(),
                slot,
                head_block_root,
                fork_choice::PayloadStatus::Pending,
                fork,
            )
            .await
            .unwrap();

        let head_execution_block = {
            let block_gen = self.server.execution_block_generator();
            block_gen.latest_block().unwrap()
        };

        assert_eq!(head_execution_block.block_number(), block_number);
        assert_eq!(head_execution_block.block_hash(), block_hash);
        assert_eq!(head_execution_block.parent_hash(), parent_hash);
    }
}
