use crate::{
    test_utils::{
        MockServer, DEFAULT_BUILDER_THRESHOLD_WEI, DEFAULT_JWT_SECRET, DEFAULT_TERMINAL_BLOCK,
        DEFAULT_TERMINAL_DIFFICULTY,
    },
    Config, *,
};
use sensitive_url::SensitiveUrl;
use task_executor::TaskExecutor;
use tempfile::NamedTempFile;
use tree_hash::TreeHash;
use types::{Address, ChainSpec, Epoch, EthSpec, FullPayload, Hash256, MainnetEthSpec};

pub struct MockExecutionLayer<T: EthSpec> {
    pub server: MockServer<T>,
    pub el: ExecutionLayer<T>,
    pub executor: TaskExecutor,
    pub spec: ChainSpec,
}

impl<T: EthSpec> MockExecutionLayer<T> {
    pub fn default_params(executor: TaskExecutor) -> Self {
        let mut spec = MainnetEthSpec::default_spec();
        spec.terminal_total_difficulty = DEFAULT_TERMINAL_DIFFICULTY.into();
        spec.terminal_block_hash = ExecutionBlockHash::zero();
        spec.terminal_block_hash_activation_epoch = Epoch::new(0);
        Self::new(
            executor,
            DEFAULT_TERMINAL_BLOCK,
            None,
            None,
            Some(JwtKey::from_slice(&DEFAULT_JWT_SECRET).unwrap()),
            spec,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        executor: TaskExecutor,
        terminal_block: u64,
        shanghai_time: Option<u64>,
        builder_threshold: Option<u128>,
        jwt_key: Option<JwtKey>,
        spec: ChainSpec,
        builder_url: Option<SensitiveUrl>,
    ) -> Self {
        let handle = executor.handle().unwrap();

        let jwt_key = jwt_key.unwrap_or_else(JwtKey::random);
        let server = MockServer::new(
            &handle,
            jwt_key,
            spec.terminal_total_difficulty,
            terminal_block,
            spec.terminal_block_hash,
            shanghai_time,
        );

        let url = SensitiveUrl::parse(&server.url()).unwrap();
        let file = NamedTempFile::new().unwrap();

        let path = file.path().into();
        std::fs::write(&path, hex::encode(DEFAULT_JWT_SECRET)).unwrap();

        let config = Config {
            execution_endpoints: vec![url],
            builder_url,
            secret_files: vec![path],
            suggested_fee_recipient: Some(Address::repeat_byte(42)),
            builder_profit_threshold: builder_threshold.unwrap_or(DEFAULT_BUILDER_THRESHOLD_WEI),
            ..Default::default()
        };
        let el =
            ExecutionLayer::from_config(config, executor.clone(), executor.log().clone()).unwrap();

        Self {
            server,
            el,
            executor,
            spec,
        }
    }

    pub async fn produce_valid_execution_payload_on_head(self) -> Self {
        let latest_execution_block = {
            let block_gen = self.server.execution_block_generator();
            block_gen.latest_block().unwrap()
        };

        let parent_hash = latest_execution_block.block_hash();
        let block_number = latest_execution_block.block_number() + 1;
        let timestamp = block_number;
        let prev_randao = Hash256::from_low_u64_be(block_number);
        let head_block_root = Hash256::repeat_byte(42);
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
            // FIXME: think about how to handle different forks / withdrawals here..
            None,
        );

        // Insert a proposer to ensure the fork choice updated command works.
        let slot = Slot::new(0);
        let validator_index = 0;
        self.el
            .insert_proposer(slot, head_block_root, validator_index, payload_attributes)
            .await;

        self.el
            .notify_forkchoice_updated(
                parent_hash,
                ExecutionBlockHash::zero(),
                ExecutionBlockHash::zero(),
                slot,
                head_block_root,
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
        let payload_attributes =
            PayloadAttributes::new(timestamp, prev_randao, suggested_fee_recipient, None);
        let payload: ExecutionPayload<T> = self
            .el
            .get_payload::<FullPayload<T>>(
                parent_hash,
                &payload_attributes,
                forkchoice_update_params,
                builder_params,
                // FIXME: do we need to consider other forks somehow? What about withdrawals?
                ForkName::Merge,
                &self.spec,
            )
            .await
            .unwrap()
            .to_payload()
            .into();

        let block_hash = payload.block_hash();
        assert_eq!(payload.parent_hash(), parent_hash);
        assert_eq!(payload.block_number(), block_number);
        assert_eq!(payload.timestamp(), timestamp);
        assert_eq!(payload.prev_randao(), prev_randao);

        // Ensure the payload cache is empty.
        assert!(self
            .el
            .get_payload_by_root(&payload.tree_hash_root())
            .is_none());
        let builder_params = BuilderParams {
            pubkey: PublicKeyBytes::empty(),
            slot,
            chain_health: ChainHealth::Healthy,
        };
        let suggested_fee_recipient = self.el.get_suggested_fee_recipient(validator_index).await;
        let payload_attributes =
            PayloadAttributes::new(timestamp, prev_randao, suggested_fee_recipient, None);
        let payload_header = self
            .el
            .get_payload::<BlindedPayload<T>>(
                parent_hash,
                &payload_attributes,
                forkchoice_update_params,
                builder_params,
                // FIXME: do we need to consider other forks somehow? What about withdrawals?
                ForkName::Merge,
                &self.spec,
            )
            .await
            .unwrap()
            .to_payload();

        assert_eq!(payload_header.block_hash(), block_hash);
        assert_eq!(payload_header.parent_hash(), parent_hash);
        assert_eq!(payload_header.block_number(), block_number);
        assert_eq!(payload_header.timestamp(), timestamp);
        assert_eq!(payload_header.prev_randao(), prev_randao);

        // Ensure the payload cache has the correct payload.
        assert_eq!(
            self.el
                .get_payload_by_root(&payload_header.tree_hash_root()),
            Some(payload.clone())
        );

        let status = self.el.notify_new_payload(&payload).await.unwrap();
        assert_eq!(status, PayloadStatus::Valid);

        // Use junk values for slot/head-root to ensure there is no payload supplied.
        let slot = Slot::new(0);
        let head_block_root = Hash256::repeat_byte(13);
        self.el
            .notify_forkchoice_updated(
                block_hash,
                ExecutionBlockHash::zero(),
                ExecutionBlockHash::zero(),
                slot,
                head_block_root,
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

        self
    }

    pub fn move_to_block_prior_to_terminal_block(self) -> Self {
        self.server
            .execution_block_generator()
            .move_to_block_prior_to_terminal_block()
            .unwrap();
        self
    }

    pub fn move_to_terminal_block(self) -> Self {
        self.server
            .execution_block_generator()
            .move_to_terminal_block()
            .unwrap();
        self
    }

    pub fn produce_forked_pow_block(self) -> (Self, ExecutionBlockHash) {
        let head_block = self
            .server
            .execution_block_generator()
            .latest_block()
            .unwrap();

        let block_hash = self
            .server
            .execution_block_generator()
            .insert_pow_block_by_hash(head_block.parent_hash(), 1)
            .unwrap();
        (self, block_hash)
    }

    pub async fn with_terminal_block<'a, U, V>(self, func: U) -> Self
    where
        U: Fn(ChainSpec, ExecutionLayer<T>, Option<ExecutionBlock>) -> V,
        V: Future<Output = ()>,
    {
        let terminal_block_number = self
            .server
            .execution_block_generator()
            .terminal_block_number;
        let terminal_block = self
            .server
            .execution_block_generator()
            .execution_block_by_number(terminal_block_number);

        func(self.spec.clone(), self.el.clone(), terminal_block).await;
        self
    }
}
