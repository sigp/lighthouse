use super::*;
use crate::decode::{ssz_decode_file, ssz_decode_file_with, ssz_decode_state, yaml_decode_file};
use serde_derive::Deserialize;
use types::{
    Attestation, BeaconBlock, BeaconState, Checkpoint, EthSpec, ForkName, Hash256,
    SignedBeaconBlock, Slot,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Head {
    slot: Slot,
    root: Hash256,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Checks {
    head: Option<Head>,
    time: Option<u64>,
    genesis_time: Option<u64>,
    justified_checkpoint: Option<Checkpoint>,
    finalized_checkpoint: Option<Checkpoint>,
    best_justified_checkpoint: Option<Checkpoint>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged, rename_all = "snake_case")]
pub enum Step<B, A> {
    Tick { tick: u64 },
    ValidBlock { block: B },
    MaybeValidBlock { block: B, valid: bool },
    Attestation { attestation: A },
    Checks(Checks),
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
        // This somewhat awkward step resolves the object names in `steps.yaml` into actual decoded
        // block/attestation objects.
        let steps = steps
            .into_iter()
            .map(|step| match step {
                Step::Tick { tick } => Ok(Step::Tick { tick }),
                Step::ValidBlock { block } => {
                    let block = ssz_decode_file_with(
                        &path.join(format!("{}.ssz_snappy", block)),
                        |bytes| SignedBeaconBlock::from_ssz_bytes(bytes, spec),
                    )?;
                    Ok(Step::ValidBlock { block })
                }
                Step::MaybeValidBlock { block, valid } => {
                    let block = ssz_decode_file_with(
                        &path.join(format!("{}.ssz_snappy", block)),
                        |bytes| SignedBeaconBlock::from_ssz_bytes(bytes, spec),
                    )?;
                    Ok(Step::MaybeValidBlock { block, valid })
                }
                Step::Attestation { attestation } => {
                    let attestation =
                        ssz_decode_file(&path.join(format!("{}.ssz_snappy", attestation)))?;
                    Ok(Step::Attestation { attestation })
                }
                Step::Checks(checks) => Ok(Step::Checks(checks)),
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

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        // TODO(paul): run tests
        Ok(())
    }
}
