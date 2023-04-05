use super::*;
use crate::decode::{ssz_decode_file, ssz_decode_file_with, ssz_decode_state, yaml_decode_file};
use ::fork_choice::PayloadVerificationStatus;
use beacon_chain::slot_clock::SlotClock;
use beacon_chain::{
    attestation_verification::{
        obtain_indexed_attestation_and_committees_per_slot, VerifiedAttestation,
    },
    test_utils::{BeaconChainHarness, EphemeralHarnessType},
    BeaconChainTypes, CachedHead, CountUnrealized, NotifyExecutionLayer,
};
use execution_layer::{json_structures::JsonPayloadStatusV1Status, PayloadStatusV1};
use serde::Deserialize;
use ssz_derive::Decode;
use state_processing::state_advance::complete_state_advance;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use types::{
    Attestation, AttesterSlashing, BeaconBlock, BeaconState, Checkpoint, EthSpec,
    ExecutionBlockHash, ForkName, Hash256, IndexedAttestation, SignedBeaconBlock, Slot, Uint256,
};

#[derive(Default, Debug, PartialEq, Clone, Deserialize, Decode)]
#[serde(deny_unknown_fields)]
pub struct PowBlock {
    pub block_hash: ExecutionBlockHash,
    pub parent_hash: ExecutionBlockHash,
    pub total_difficulty: Uint256,
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    slot: Slot,
    root: Hash256,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checks {
    head: Option<Head>,
    time: Option<u64>,
    genesis_time: Option<u64>,
    justified_checkpoint: Option<Checkpoint>,
    justified_checkpoint_root: Option<Hash256>,
    finalized_checkpoint: Option<Checkpoint>,
    u_justified_checkpoint: Option<Checkpoint>,
    u_finalized_checkpoint: Option<Checkpoint>,
    proposer_boost_root: Option<Hash256>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadStatus {
    status: JsonPayloadStatusV1Status,
    latest_valid_hash: Option<ExecutionBlockHash>,
    validation_error: Option<String>,
}

impl From<PayloadStatus> for PayloadStatusV1 {
    fn from(status: PayloadStatus) -> Self {
        PayloadStatusV1 {
            status: status.status.into(),
            latest_valid_hash: status.latest_valid_hash,
            validation_error: status.validation_error,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Step<B, A, AS, P> {
    Tick {
        tick: u64,
    },
    ValidBlock {
        block: B,
    },
    MaybeValidBlock {
        block: B,
        valid: bool,
    },
    Attestation {
        attestation: A,
    },
    AttesterSlashing {
        attester_slashing: AS,
    },
    PowBlock {
        pow_block: P,
    },
    OnPayloadInfo {
        block_hash: ExecutionBlockHash,
        payload_status: PayloadStatus,
    },
    Checks {
        checks: Box<Checks>,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    #[serde(rename(deserialize = "description"))]
    _description: String,
}

#[derive(Debug)]
pub struct ForkChoiceTest<E: EthSpec> {
    pub description: String,
    pub anchor_state: BeaconState<E>,
    pub anchor_block: BeaconBlock<E>,
    #[allow(clippy::type_complexity)]
    pub steps: Vec<Step<SignedBeaconBlock<E>, Attestation<E>, AttesterSlashing<E>, PowBlock>>,
}

impl<E: EthSpec> LoadCase for ForkChoiceTest<E> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let description = path
            .iter()
            .last()
            .expect("path must be non-empty")
            .to_str()
            .expect("path must be valid OsStr")
            .to_string();
        let spec = &testing_spec::<E>(fork_name);
        let steps: Vec<Step<String, String, String, String>> =
            yaml_decode_file(&path.join("steps.yaml"))?;
        // Resolve the object names in `steps.yaml` into actual decoded block/attestation objects.
        let steps = steps
            .into_iter()
            .map(|step| match step {
                Step::Tick { tick } => Ok(Step::Tick { tick }),
                Step::ValidBlock { block } => {
                    ssz_decode_file_with(&path.join(format!("{}.ssz_snappy", block)), |bytes| {
                        SignedBeaconBlock::from_ssz_bytes(bytes, spec)
                    })
                    .map(|block| Step::ValidBlock { block })
                }
                Step::MaybeValidBlock { block, valid } => {
                    ssz_decode_file_with(&path.join(format!("{}.ssz_snappy", block)), |bytes| {
                        SignedBeaconBlock::from_ssz_bytes(bytes, spec)
                    })
                    .map(|block| Step::MaybeValidBlock { block, valid })
                }
                Step::Attestation { attestation } => {
                    ssz_decode_file(&path.join(format!("{}.ssz_snappy", attestation)))
                        .map(|attestation| Step::Attestation { attestation })
                }
                Step::AttesterSlashing { attester_slashing } => {
                    ssz_decode_file(&path.join(format!("{}.ssz_snappy", attester_slashing)))
                        .map(|attester_slashing| Step::AttesterSlashing { attester_slashing })
                }
                Step::PowBlock { pow_block } => {
                    ssz_decode_file(&path.join(format!("{}.ssz_snappy", pow_block)))
                        .map(|pow_block| Step::PowBlock { pow_block })
                }
                Step::OnPayloadInfo {
                    block_hash,
                    payload_status,
                } => Ok(Step::OnPayloadInfo {
                    block_hash,
                    payload_status,
                }),
                Step::Checks { checks } => Ok(Step::Checks { checks }),
            })
            .collect::<Result<_, _>>()?;
        let anchor_state = ssz_decode_state(&path.join("anchor_state.ssz_snappy"), spec)?;
        let anchor_block = ssz_decode_file_with(&path.join("anchor_block.ssz_snappy"), |bytes| {
            BeaconBlock::from_ssz_bytes(bytes, spec)
        })?;

        // None of the tests have a `meta.yaml` file, except the altair/genesis tests. For those
        // tests, the meta file has an irrelevant comment as the `description` field. If the meta
        // file is present, we parse it for two reasons:
        //
        // - To satisfy the `check_all_files_accessed.py` check.
        // - To ensure that the `meta.yaml` only contains a description field and nothing else that
        //   might be useful.
        let meta_path = path.join("meta.yaml");
        if meta_path.exists() {
            let _meta: Meta = yaml_decode_file(&meta_path)?;
        }

        Ok(Self {
            description,
            anchor_state,
            anchor_block,
            steps,
        })
    }
}

impl<E: EthSpec> Case for ForkChoiceTest<E> {
    fn description(&self) -> String {
        self.description.clone()
    }

    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let tester = Tester::new(self, testing_spec::<E>(fork_name))?;

        for step in &self.steps {
            match step {
                Step::Tick { tick } => tester.set_tick(*tick),
                Step::ValidBlock { block } => tester.process_block(block.clone(), true)?,
                Step::MaybeValidBlock { block, valid } => {
                    tester.process_block(block.clone(), *valid)?
                }
                Step::Attestation { attestation } => tester.process_attestation(attestation)?,
                Step::AttesterSlashing { attester_slashing } => {
                    tester.process_attester_slashing(attester_slashing)
                }
                Step::PowBlock { pow_block } => tester.process_pow_block(pow_block),
                Step::OnPayloadInfo {
                    block_hash,
                    payload_status,
                } => {
                    let el = tester.harness.mock_execution_layer.as_ref().unwrap();
                    el.server
                        .set_payload_statuses(*block_hash, payload_status.clone().into());
                }
                Step::Checks { checks } => {
                    let Checks {
                        head,
                        time,
                        genesis_time,
                        justified_checkpoint,
                        justified_checkpoint_root,
                        finalized_checkpoint,
                        u_justified_checkpoint,
                        u_finalized_checkpoint,
                        proposer_boost_root,
                    } = checks.as_ref();

                    if let Some(expected_head) = head {
                        tester.check_head(*expected_head)?;
                    }

                    if let Some(expected_time) = time {
                        tester.check_time(*expected_time)?;
                    }

                    if let Some(expected_genesis_time) = genesis_time {
                        tester.check_genesis_time(*expected_genesis_time)?;
                    }

                    if let Some(expected_justified_checkpoint) = justified_checkpoint {
                        tester.check_justified_checkpoint(*expected_justified_checkpoint)?;
                    }

                    if let Some(expected_justified_checkpoint_root) = justified_checkpoint_root {
                        tester
                            .check_justified_checkpoint_root(*expected_justified_checkpoint_root)?;
                    }

                    if let Some(expected_finalized_checkpoint) = finalized_checkpoint {
                        tester.check_finalized_checkpoint(*expected_finalized_checkpoint)?;
                    }

                    if let Some(expected_u_justified_checkpoint) = u_justified_checkpoint {
                        tester.check_u_justified_checkpoint(*expected_u_justified_checkpoint)?;
                    }

                    if let Some(expected_u_finalized_checkpoint) = u_finalized_checkpoint {
                        tester.check_u_finalized_checkpoint(*expected_u_finalized_checkpoint)?;
                    }

                    if let Some(expected_proposer_boost_root) = proposer_boost_root {
                        tester.check_expected_proposer_boost_root(*expected_proposer_boost_root)?;
                    }
                }
            }
        }

        Ok(())
    }
}

/// A testing rig used to execute a test case.
struct Tester<E: EthSpec> {
    harness: BeaconChainHarness<EphemeralHarnessType<E>>,
    spec: ChainSpec,
}

impl<E: EthSpec> Tester<E> {
    pub fn new(case: &ForkChoiceTest<E>, spec: ChainSpec) -> Result<Self, Error> {
        let genesis_time = case.anchor_state.genesis_time();

        if case.anchor_state.slot() != spec.genesis_slot {
            // I would hope that future fork-choice tests would start from a non-genesis anchors,
            // however at the time of writing, none do. I think it would be quite easy to do
            // non-genesis anchors via a weak-subjectivity/checkpoint start.
            //
            // Whilst those tests don't exist, we'll avoid adding checkpoint start complexity to the
            // `BeaconChainHarness` and create a hard failure so we can deal with it then.
            return Err(Error::FailedToParseTest(
                "anchor state is not a genesis state".into(),
            ));
        }

        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .spec(spec.clone())
            .keypairs(vec![])
            .genesis_state_ephemeral_store(case.anchor_state.clone())
            .mock_execution_layer()
            .recalculate_fork_times_with_genesis(0)
            .mock_execution_layer_all_payloads_valid()
            .build();

        if harness.chain.genesis_block_root != case.anchor_block.canonical_root() {
            // This check will need to be removed if/when the fork-choice tests use a non-genesis
            // anchor state.
            return Err(Error::FailedToParseTest(
                "anchor block differs from locally-generated genesis block".into(),
            ));
        }

        // Drop any blocks that might be loaded in the mock execution layer. Some of these tests
        // will provide their own blocks and we want to start from a clean state.
        harness
            .mock_execution_layer
            .as_ref()
            .unwrap()
            .server
            .drop_all_blocks();

        assert_eq!(
            harness.chain.slot_clock.genesis_duration().as_secs(),
            genesis_time
        );

        Ok(Self { harness, spec })
    }

    fn tick_to_slot(&self, tick: u64) -> Result<Slot, Error> {
        let genesis_time = self.harness.chain.slot_clock.genesis_duration().as_secs();
        let since_genesis = tick
            .checked_sub(genesis_time)
            .ok_or_else(|| Error::FailedToParseTest("tick is prior to genesis".into()))?;
        let slots_since_genesis = since_genesis / self.spec.seconds_per_slot;
        Ok(self.spec.genesis_slot + slots_since_genesis)
    }

    fn block_on_dangerous<F: Future>(&self, future: F) -> Result<F::Output, Error> {
        self.harness
            .chain
            .task_executor
            .clone()
            .block_on_dangerous(future, "ef_tests_block_on")
            .ok_or_else(|| Error::InternalError("runtime shutdown".into()))
    }

    fn find_head(&self) -> Result<CachedHead<E>, Error> {
        let chain = self.harness.chain.clone();
        self.block_on_dangerous(chain.recompute_head_at_current_slot())?;
        Ok(self.harness.chain.canonical_head.cached_head())
    }

    pub fn set_tick(&self, tick: u64) {
        self.harness
            .chain
            .slot_clock
            .set_current_time(Duration::from_secs(tick));

        // Compute the slot time manually to ensure the slot clock is correct.
        let slot = self.tick_to_slot(tick).unwrap();
        assert_eq!(slot, self.harness.chain.slot().unwrap());

        self.harness
            .chain
            .canonical_head
            .fork_choice_write_lock()
            .update_time(slot)
            .unwrap();
    }

    pub fn process_block(&self, block: SignedBeaconBlock<E>, valid: bool) -> Result<(), Error> {
        let block_root = block.canonical_root();
        let block = Arc::new(block);
        let result = self.block_on_dangerous(self.harness.chain.process_block(
            block_root,
            block.clone(),
            CountUnrealized::True,
            NotifyExecutionLayer::Yes,
        ))?;
        if result.is_ok() != valid {
            return Err(Error::DidntFail(format!(
                "block with root {} was valid={} whilst test expects valid={}. result: {:?}",
                block_root,
                result.is_ok(),
                valid,
                result
            )));
        }

        // Apply invalid blocks directly against the fork choice `on_block` function. This ensures
        // that the block is being rejected by `on_block`, not just some upstream block processing
        // function.
        if !valid {
            // A missing parent block whilst `valid == false` means the test should pass.
            if let Some(parent_block) = self
                .harness
                .chain
                .get_blinded_block(&block.parent_root())
                .unwrap()
            {
                let parent_state_root = parent_block.state_root();
                let mut state = self
                    .harness
                    .chain
                    .get_state(&parent_state_root, Some(parent_block.slot()))
                    .unwrap()
                    .unwrap();

                complete_state_advance(
                    &mut state,
                    Some(parent_state_root),
                    block.slot(),
                    &self.harness.chain.spec,
                )
                .unwrap();

                let block_delay = self
                    .harness
                    .chain
                    .slot_clock
                    .seconds_from_current_slot_start()
                    .unwrap();

                let result = self
                    .harness
                    .chain
                    .canonical_head
                    .fork_choice_write_lock()
                    .on_block(
                        self.harness.chain.slot().unwrap(),
                        block.message(),
                        block_root,
                        block_delay,
                        &state,
                        PayloadVerificationStatus::Irrelevant,
                        &self.harness.chain.spec,
                        CountUnrealized::True,
                    );

                if result.is_ok() {
                    return Err(Error::DidntFail(format!(
                        "block with root {} should fail on_block",
                        block_root,
                    )));
                }
            }
        }

        Ok(())
    }

    pub fn process_attestation(&self, attestation: &Attestation<E>) -> Result<(), Error> {
        let (indexed_attestation, _) =
            obtain_indexed_attestation_and_committees_per_slot(&self.harness.chain, attestation)
                .map_err(|e| {
                    Error::InternalError(format!("attestation indexing failed with {:?}", e))
                })?;
        let verified_attestation: ManuallyVerifiedAttestation<EphemeralHarnessType<E>> =
            ManuallyVerifiedAttestation {
                attestation,
                indexed_attestation,
            };

        self.harness
            .chain
            .apply_attestation_to_fork_choice(&verified_attestation)
            .map_err(|e| Error::InternalError(format!("attestation import failed with {:?}", e)))
    }

    pub fn process_attester_slashing(&self, attester_slashing: &AttesterSlashing<E>) {
        self.harness
            .chain
            .canonical_head
            .fork_choice_write_lock()
            .on_attester_slashing(attester_slashing)
    }

    pub fn process_pow_block(&self, pow_block: &PowBlock) {
        let el = self.harness.mock_execution_layer.as_ref().unwrap();

        // The EF tests don't supply a block number. Our mock execution layer is fine with duplicate
        // block numbers for the purposes of this test.
        let block_number = 0;

        el.server.insert_pow_block(
            block_number,
            pow_block.block_hash,
            pow_block.parent_hash,
            pow_block.total_difficulty,
        );
    }

    pub fn check_head(&self, expected_head: Head) -> Result<(), Error> {
        let head = self.find_head()?;
        let chain_head = Head {
            slot: head.head_slot(),
            root: head.head_block_root(),
        };

        check_equal("head", chain_head, expected_head)
    }

    pub fn check_time(&self, expected_time: u64) -> Result<(), Error> {
        let slot = self.harness.chain.slot().map_err(|e| {
            Error::InternalError(format!("reading current slot failed with {:?}", e))
        })?;
        let expected_slot = self.tick_to_slot(expected_time)?;
        check_equal("time", slot, expected_slot)
    }

    pub fn check_genesis_time(&self, expected_genesis_time: u64) -> Result<(), Error> {
        let genesis_time = self.harness.chain.slot_clock.genesis_duration().as_secs();
        check_equal("genesis_time", genesis_time, expected_genesis_time)
    }

    pub fn check_justified_checkpoint(&self, expected_checkpoint: Checkpoint) -> Result<(), Error> {
        let head_checkpoint = self.find_head()?.justified_checkpoint();
        let fc_checkpoint = self
            .harness
            .chain
            .canonical_head
            .fork_choice_read_lock()
            .justified_checkpoint();

        assert_checkpoints_eq("justified_checkpoint", head_checkpoint, fc_checkpoint);

        check_equal("justified_checkpoint", fc_checkpoint, expected_checkpoint)
    }

    pub fn check_justified_checkpoint_root(
        &self,
        expected_checkpoint_root: Hash256,
    ) -> Result<(), Error> {
        let head_checkpoint = self.find_head()?.justified_checkpoint();
        let fc_checkpoint = self
            .harness
            .chain
            .canonical_head
            .fork_choice_read_lock()
            .justified_checkpoint();

        assert_checkpoints_eq("justified_checkpoint_root", head_checkpoint, fc_checkpoint);

        check_equal(
            "justified_checkpoint_root",
            fc_checkpoint.root,
            expected_checkpoint_root,
        )
    }

    pub fn check_finalized_checkpoint(&self, expected_checkpoint: Checkpoint) -> Result<(), Error> {
        let head_checkpoint = self.find_head()?.finalized_checkpoint();
        let fc_checkpoint = self
            .harness
            .chain
            .canonical_head
            .fork_choice_read_lock()
            .finalized_checkpoint();

        assert_checkpoints_eq("finalized_checkpoint", head_checkpoint, fc_checkpoint);

        check_equal("finalized_checkpoint", fc_checkpoint, expected_checkpoint)
    }

    pub fn check_u_justified_checkpoint(
        &self,
        expected_checkpoint: Checkpoint,
    ) -> Result<(), Error> {
        let u_justified_checkpoint = self
            .harness
            .chain
            .canonical_head
            .fork_choice_read_lock()
            .unrealized_justified_checkpoint();
        check_equal(
            "u_justified_checkpoint",
            u_justified_checkpoint,
            expected_checkpoint,
        )
    }

    pub fn check_u_finalized_checkpoint(
        &self,
        expected_checkpoint: Checkpoint,
    ) -> Result<(), Error> {
        let u_finalized_checkpoint = self
            .harness
            .chain
            .canonical_head
            .fork_choice_read_lock()
            .unrealized_finalized_checkpoint();
        check_equal(
            "u_finalized_checkpoint",
            u_finalized_checkpoint,
            expected_checkpoint,
        )
    }

    pub fn check_expected_proposer_boost_root(
        &self,
        expected_proposer_boost_root: Hash256,
    ) -> Result<(), Error> {
        let proposer_boost_root = self
            .harness
            .chain
            .canonical_head
            .fork_choice_read_lock()
            .proposer_boost_root();
        check_equal(
            "proposer_boost_root",
            proposer_boost_root,
            expected_proposer_boost_root,
        )
    }
}

/// Checks that the `head` checkpoint from the beacon chain head matches the `fc` checkpoint gleaned
/// directly from fork choice.
///
/// This function is necessary due to a quirk documented in this issue:
///
/// https://github.com/ethereum/consensus-specs/issues/2566
fn assert_checkpoints_eq(name: &str, head: Checkpoint, fc: Checkpoint) {
    assert_eq!(head, fc, "{}", name)
}

/// Convenience function to create `Error` messages.
fn check_equal<T: Debug + PartialEq>(check: &str, result: T, expected: T) -> Result<(), Error> {
    if result == expected {
        Ok(())
    } else {
        Err(Error::NotEqual(format!(
            "{} check failed: Got {:?} | Expected {:?}",
            check, result, expected
        )))
    }
}

/// An attestation that is not verified in the `BeaconChain` sense, but verified-enough for these
/// tests.
///
/// The `BeaconChain` verification is not appropriate since these tests use `Attestation`s with
/// multiple participating validators. Therefore, they are neither aggregated or unaggregated
/// attestations.
pub struct ManuallyVerifiedAttestation<'a, T: BeaconChainTypes> {
    #[allow(dead_code)]
    attestation: &'a Attestation<T::EthSpec>,
    indexed_attestation: IndexedAttestation<T::EthSpec>,
}

impl<'a, T: BeaconChainTypes> VerifiedAttestation<T> for ManuallyVerifiedAttestation<'a, T> {
    fn attestation(&self) -> &Attestation<T::EthSpec> {
        self.attestation
    }

    fn indexed_attestation(&self) -> &IndexedAttestation<T::EthSpec> {
        &self.indexed_attestation
    }
}
