use super::*;
use crate::decode::{ssz_decode_file, ssz_decode_file_with, ssz_decode_state, yaml_decode_file};
use beacon_chain::{
    attestation_verification::{
        obtain_indexed_attestation_and_committees_per_slot, VerifiedAttestation,
    },
    test_utils::{BeaconChainHarness, EphemeralHarnessType},
    BeaconChainTypes, HeadInfo,
};
use serde_derive::Deserialize;
use types::{
    Attestation, BeaconBlock, BeaconState, Checkpoint, Epoch, EthSpec, ForkName, Hash256,
    IndexedAttestation, SignedBeaconBlock, Slot,
};

#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
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
    best_justified_checkpoint: Option<Checkpoint>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Step<B, A> {
    Tick { tick: u64 },
    ValidBlock { block: B },
    MaybeValidBlock { block: B, valid: bool },
    Attestation { attestation: A },
    Checks { checks: Checks },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct ForkChoiceTest<E: EthSpec> {
    pub description: String,
    pub anchor_state: BeaconState<E>,
    pub anchor_block: BeaconBlock<E>,
    pub steps: Vec<Step<SignedBeaconBlock<E>, Attestation<E>>>,
}

impl<E: EthSpec> LoadCase for ForkChoiceTest<E> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let description = format!("{:?}", path);
        let spec = &testing_spec::<E>(fork_name);
        let steps: Vec<Step<String, String>> = yaml_decode_file(&path.join("steps.yaml"))?;
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
                Step::Checks { checks } => Ok(Step::Checks { checks }),
            })
            .collect::<Result<_, _>>()?;
        let anchor_state = ssz_decode_state(&path.join("anchor_state.ssz_snappy"), spec)?;
        let anchor_block = ssz_decode_file_with(&path.join("anchor_block.ssz_snappy"), |bytes| {
            BeaconBlock::from_ssz_bytes(bytes, spec)
        })?;

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
                Step::Checks { checks } => {
                    let Checks {
                        head,
                        time,
                        genesis_time,
                        justified_checkpoint,
                        justified_checkpoint_root,
                        finalized_checkpoint,
                        best_justified_checkpoint,
                    } = checks;

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

                    if let Some(expected_best_justified_checkpoint) = best_justified_checkpoint {
                        tester
                            .check_best_justified_checkpoint(*expected_best_justified_checkpoint)?;
                    }
                }
            }
        }

        Ok(())
    }
}

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

        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec.clone())
            .keypairs(vec![])
            .genesis_state_ephemeral_store(case.anchor_state.clone())
            .build();

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

    fn find_head(&self) -> Result<HeadInfo, Error> {
        self.harness
            .chain
            .fork_choice()
            .map_err(|e| Error::InternalError(format!("failed to find head with {:?}", e)))?;
        self.harness
            .chain
            .head_info()
            .map_err(|e| Error::InternalError(format!("failed to read head with {:?}", e)))
    }

    fn genesis_epoch(&self) -> Epoch {
        self.spec.genesis_slot.epoch(E::slots_per_epoch())
    }

    pub fn set_tick(&self, tick: u64) {
        let slot = self.tick_to_slot(tick).unwrap();
        self.harness.set_current_slot(slot);
        self.harness
            .chain
            .fork_choice
            .write()
            .update_time(slot)
            .unwrap();
    }

    pub fn process_block(&self, block: SignedBeaconBlock<E>, valid: bool) -> Result<(), Error> {
        let result = self.harness.chain.process_block(block.clone());
        // TODO(paul) try apply directly to fork choice?
        if result.is_ok() != valid {
            return Err(Error::DidntFail(format!(
                "block with root {} should be invalid",
                block.canonical_root(),
            )));
        } else {
            Ok(())
        }
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

    pub fn check_head(&self, expected_head: Head) -> Result<(), Error> {
        let chain_head = self.find_head().map(|head| Head {
            slot: head.slot,
            root: head.block_root,
        })?;

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
        let head_checkpoint = self.find_head()?.current_justified_checkpoint;
        let fc_checkpoint = self.harness.chain.fork_choice.read().justified_checkpoint();

        assert_checkpoints_eq(
            "justified_checkpoint",
            self.genesis_epoch(),
            head_checkpoint,
            fc_checkpoint,
        );

        check_equal("justified_checkpoint", fc_checkpoint, expected_checkpoint)
    }

    pub fn check_justified_checkpoint_root(
        &self,
        expected_checkpoint_root: Hash256,
    ) -> Result<(), Error> {
        let head_checkpoint = self.find_head()?.current_justified_checkpoint;
        let fc_checkpoint = self.harness.chain.fork_choice.read().justified_checkpoint();

        assert_checkpoints_eq(
            "justified_checkpoint_root",
            self.genesis_epoch(),
            head_checkpoint,
            fc_checkpoint,
        );

        check_equal(
            "justified_checkpoint_root",
            fc_checkpoint.root,
            expected_checkpoint_root,
        )
    }

    pub fn check_finalized_checkpoint(&self, expected_checkpoint: Checkpoint) -> Result<(), Error> {
        let head_checkpoint = self.find_head()?.finalized_checkpoint;
        let fc_checkpoint = self.harness.chain.fork_choice.read().finalized_checkpoint();

        assert_checkpoints_eq(
            "finalized_checkpoint",
            self.genesis_epoch(),
            head_checkpoint,
            fc_checkpoint,
        );

        check_equal("finalized_checkpoint", fc_checkpoint, expected_checkpoint)
    }

    pub fn check_best_justified_checkpoint(
        &self,
        expected_checkpoint: Checkpoint,
    ) -> Result<(), Error> {
        let best_justified_checkpoint = self
            .harness
            .chain
            .fork_choice
            .read()
            .best_justified_checkpoint();
        check_equal(
            "best_justified_checkpoint",
            best_justified_checkpoint,
            expected_checkpoint,
        )
    }
}

/// Checks that the `head` checkpoint from the beacon chain head matches the `fc` checkpoint gleaned
/// directly from fork choice.
///
/// This function is necessary due to a quirk documented in this issue:
///
/// https://github.com/ethereum/consensus-specs/issues/2566
fn assert_checkpoints_eq(name: &str, genesis_epoch: Epoch, head: Checkpoint, fc: Checkpoint) {
    if fc.epoch == genesis_epoch {
        assert_eq!(
            head,
            Checkpoint {
                epoch: genesis_epoch,
                root: Hash256::zero()
            },
            "{} (genesis)",
            name
        )
    } else {
        assert_eq!(head, fc, "{} (non-genesis)", name)
    }
}

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
