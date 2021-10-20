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
    Attestation, BeaconBlock, BeaconState, Checkpoint, EthSpec, ForkName, Hash256,
    IndexedAttestation, Signature, SignedBeaconBlock, Slot,
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
        let genesis_time = self.anchor_state.genesis_time();
        let spec = testing_spec::<E>(fork_name);

        assert_eq!(self.anchor_state.slot(), spec.genesis_slot);

        let genesis_state = {
            let mut state = self.anchor_state.clone();
            *state.slot_mut() = spec.genesis_slot;
            state
        };

        let genesis_block_root = if self.anchor_block.slot() == spec.genesis_slot {
            self.anchor_block.canonical_root()
        } else if let Ok(root) = self.anchor_state.get_block_root(spec.genesis_slot) {
            *root
        } else {
            Hash256::zero()
        };

        let signed_anchor_block =
            SignedBeaconBlock::from_block(self.anchor_block.clone(), Signature::empty());
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec.clone())
            .keypairs(vec![])
            .checkpoint_sync_ephemeral_store(
                self.anchor_state.clone(),
                signed_anchor_block,
                genesis_state,
            )
            .build();

        let tick_to_slot = |tick: u64| {
            let since_genesis = tick
                .checked_sub(genesis_time)
                .ok_or_else(|| Error::FailedToParseTest("tick is prior to genesis".into()))?;
            let slots_since_genesis = since_genesis / spec.seconds_per_slot;
            Ok(spec.genesis_slot + slots_since_genesis)
        };

        let find_head = || -> Result<HeadInfo, Error> {
            harness
                .chain
                .fork_choice()
                .map_err(|e| Error::InternalError(format!("failed to find head with {:?}", e)))?;
            harness
                .chain
                .head_info()
                .map_err(|e| Error::InternalError(format!("failed to read head with {:?}", e)))
        };

        for step in &self.steps {
            match step {
                Step::Tick { tick } => {
                    let slot = tick_to_slot(*tick)?;
                    harness.set_current_slot(slot);
                    harness
                        .chain
                        .fork_choice
                        .write()
                        .update_time(slot)
                        .map_err(|e| {
                            Error::InternalError(format!(
                                "setting tick to {} failed with {:?}",
                                tick, e
                            ))
                        })?;
                }
                Step::ValidBlock { block } => {
                    harness.chain.process_block(block.clone()).map_err(|e| {
                        Error::InternalError(format!(
                            "valid block {} failed import with {:?}",
                            block.canonical_root(),
                            e
                        ))
                    })?;
                }
                Step::MaybeValidBlock { block, valid } => {
                    let result = harness.chain.process_block(block.clone());
                    if result.is_ok() != *valid {
                        return Err(Error::DidntFail(format!(
                            "block with root {} should be invalid",
                            block.canonical_root(),
                        )));
                    }
                    // TODO(paul) try apply directly to fork choice?
                }
                Step::Attestation { attestation } => {
                    let (indexed_attestation, _) =
                        obtain_indexed_attestation_and_committees_per_slot(
                            &harness.chain,
                            attestation,
                        )
                        .map_err(|e| {
                            Error::InternalError(format!(
                                "attestation indexing failed with {:?}",
                                e
                            ))
                        })?;
                    let verified_attestation: ManuallyVerifiedAttestation<EphemeralHarnessType<E>> =
                        ManuallyVerifiedAttestation {
                            attestation,
                            indexed_attestation,
                        };

                    harness
                        .chain
                        .apply_attestation_to_fork_choice(&verified_attestation)
                        .map_err(|e| {
                            Error::InternalError(format!("attestation import failed with {:?}", e))
                        })?;
                }
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
                        let chain_head = find_head().map(|head| Head {
                            slot: head.slot,
                            root: head.block_root,
                        })?;

                        check_equal("head", chain_head, *expected_head)?;
                    }

                    if let Some(expected_time) = time {
                        let slot = harness.chain.slot().map_err(|e| {
                            Error::InternalError(format!(
                                "reading current slot failed with {:?}",
                                e
                            ))
                        })?;
                        let expected_slot = tick_to_slot(*expected_time)?;
                        check_equal("time", slot, expected_slot)?;
                    }

                    if let Some(expected_genesis_time) = genesis_time {
                        let genesis_time = harness.chain.slot_clock.genesis_duration().as_secs();
                        check_equal("genesis_time", genesis_time, *expected_genesis_time)?;
                    }

                    if let Some(expected_justified_checkpoint) = justified_checkpoint {
                        let mut current_justified_checkpoint =
                            find_head()?.current_justified_checkpoint;

                        if current_justified_checkpoint == Checkpoint::default() {
                            current_justified_checkpoint.root = genesis_block_root;
                        }

                        check_equal(
                            "justified_checkpoint",
                            current_justified_checkpoint,
                            *expected_justified_checkpoint,
                        )?;
                    }

                    if let Some(expected_justified_checkpoint_root) = justified_checkpoint_root {
                        let chain_head = find_head()?;
                        check_equal(
                            "justified_checkpoint_root",
                            chain_head.current_justified_checkpoint.root,
                            *expected_justified_checkpoint_root,
                        )?;
                    }

                    if let Some(expected_finalized_checkpoint) = finalized_checkpoint {
                        let mut finalized_checkpoint = find_head()?.finalized_checkpoint;

                        if finalized_checkpoint == Checkpoint::default() {
                            finalized_checkpoint.root = genesis_block_root;
                        }

                        check_equal(
                            "finalized_checkpoint",
                            finalized_checkpoint,
                            *expected_finalized_checkpoint,
                        )?;
                    }

                    if let Some(expected_best_justified_checkpoint) = best_justified_checkpoint {
                        let best_justified_checkpoint =
                            harness.chain.fork_choice.read().best_justified_checkpoint();
                        check_equal(
                            "best_justified_checkpoint",
                            best_justified_checkpoint,
                            *expected_best_justified_checkpoint,
                        )?;
                    }
                }
            }
        }

        Ok(())
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
