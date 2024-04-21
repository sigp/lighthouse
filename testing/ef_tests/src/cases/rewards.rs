use super::*;
use crate::case_result::compare_result_detailed;
use crate::decode::{ssz_decode_file, ssz_decode_state, yaml_decode_file};
use compare_fields_derive::CompareFields;
use serde::Deserialize;
use ssz::four_byte_option_impl;
use ssz_derive::{Decode, Encode};
use state_processing::{
    per_epoch_processing::{
        altair,
        base::{self, rewards_and_penalties::AttestationDelta, ValidatorStatuses},
        Delta,
    },
    EpochProcessingError,
};
use types::BeaconState;

#[derive(Debug, Clone, PartialEq, Decode, Encode, CompareFields)]
pub struct Deltas {
    #[compare_fields(as_slice)]
    rewards: Vec<u64>,
    #[compare_fields(as_slice)]
    penalties: Vec<u64>,
}

// Define "legacy" implementations of `Option<Epoch>`, `Option<NonZeroUsize>` which use four bytes
// for encoding the union selector.
four_byte_option_impl!(four_byte_option_deltas, Deltas);

#[derive(Debug, Clone, PartialEq, Decode, Encode, CompareFields)]
pub struct AllDeltas {
    source_deltas: Deltas,
    target_deltas: Deltas,
    head_deltas: Deltas,
    #[ssz(with = "four_byte_option_deltas")]
    inclusion_delay_deltas: Option<Deltas>,
    inactivity_penalty_deltas: Deltas,
}

#[derive(Debug, Clone, PartialEq, CompareFields)]
pub struct TotalDeltas {
    deltas: Vec<i64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Metadata {
    pub description: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RewardsTest<E: EthSpec> {
    pub path: PathBuf,
    pub metadata: Metadata,
    pub pre: BeaconState<E>,
    pub deltas: AllDeltas,
}

/// Function that extracts a delta for a single component from an `AttestationDelta`.
type Accessor = fn(&AttestationDelta) -> &Delta;

fn load_optional_deltas_file(path: &Path) -> Result<Option<Deltas>, Error> {
    let deltas = if path.is_file() {
        Some(ssz_decode_file(path)?)
    } else {
        None
    };
    Ok(deltas)
}

impl<E: EthSpec> LoadCase for RewardsTest<E> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let spec = &testing_spec::<E>(fork_name);
        let metadata_path = path.join("meta.yaml");
        let metadata: Metadata = if metadata_path.is_file() {
            yaml_decode_file(&metadata_path)?
        } else {
            Metadata::default()
        };
        let pre = ssz_decode_state(&path.join("pre.ssz_snappy"), spec)?;
        let source_deltas = ssz_decode_file(&path.join("source_deltas.ssz_snappy"))?;
        let target_deltas = ssz_decode_file(&path.join("target_deltas.ssz_snappy"))?;
        let head_deltas = ssz_decode_file(&path.join("head_deltas.ssz_snappy"))?;
        let inclusion_delay_deltas =
            load_optional_deltas_file(&path.join("inclusion_delay_deltas.ssz_snappy"))?;
        let inactivity_penalty_deltas =
            ssz_decode_file(&path.join("inactivity_penalty_deltas.ssz_snappy"))?;

        let deltas = AllDeltas {
            source_deltas,
            target_deltas,
            head_deltas,
            inclusion_delay_deltas,
            inactivity_penalty_deltas,
        };

        Ok(Self {
            path: path.into(),
            metadata,
            pre,
            deltas,
        })
    }
}

impl<E: EthSpec> Case for RewardsTest<E> {
    fn description(&self) -> String {
        self.metadata.description.clone().unwrap_or_default()
    }

    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let mut state = self.pre.clone();
        let spec = &testing_spec::<E>(fork_name);

        // Single-pass epoch processing doesn't compute rewards in the genesis epoch because that's
        // what the spec for `process_rewards_and_penalties` says to do. We skip these tests for now.
        //
        // See: https://github.com/ethereum/consensus-specs/issues/3593
        if fork_name != ForkName::Base && state.current_epoch() == 0 {
            return Err(Error::SkippedKnownFailure);
        }

        if let BeaconState::Base(_) = state {
            let deltas: Result<AllDeltas, EpochProcessingError> = (|| {
                // Processing requires the committee caches.
                state.build_all_committee_caches(spec)?;

                let mut validator_statuses = ValidatorStatuses::new(&state, spec)?;
                validator_statuses.process_attestations(&state)?;

                let deltas = base::rewards_and_penalties::get_attestation_deltas_all(
                    &state,
                    &validator_statuses,
                    spec,
                )?;

                Ok(convert_all_base_deltas(&deltas))
            })();
            compare_result_detailed(&deltas, &Some(self.deltas.clone()))?;
        } else {
            let deltas: Result<TotalDeltas, EpochProcessingError> = (|| {
                // Processing requires the committee caches.
                state.build_all_committee_caches(spec)?;
                compute_altair_deltas(&mut state, spec)
            })();

            let expected = all_deltas_to_total_deltas(&self.deltas);

            compare_result_detailed(&deltas, &Some(expected))?;
        };

        Ok(())
    }
}

fn convert_all_base_deltas(ad: &[AttestationDelta]) -> AllDeltas {
    AllDeltas {
        source_deltas: convert_base_deltas(ad, |d| &d.source_delta),
        target_deltas: convert_base_deltas(ad, |d| &d.target_delta),
        head_deltas: convert_base_deltas(ad, |d| &d.head_delta),
        inclusion_delay_deltas: Some(convert_base_deltas(ad, |d| &d.inclusion_delay_delta)),
        inactivity_penalty_deltas: convert_base_deltas(ad, |d| &d.inactivity_penalty_delta),
    }
}

fn convert_base_deltas(attestation_deltas: &[AttestationDelta], accessor: Accessor) -> Deltas {
    let (rewards, penalties) = attestation_deltas
        .iter()
        .map(accessor)
        .map(|delta| (delta.rewards, delta.penalties))
        .unzip();
    Deltas { rewards, penalties }
}

fn deltas_to_total_deltas(d: &Deltas) -> impl Iterator<Item = i64> + '_ {
    d.rewards
        .iter()
        .zip(&d.penalties)
        .map(|(&reward, &penalty)| reward as i64 - penalty as i64)
}

fn optional_deltas_to_total_deltas(d: &Option<Deltas>, len: usize) -> TotalDeltas {
    let deltas = if let Some(d) = d {
        deltas_to_total_deltas(d).collect()
    } else {
        vec![0i64; len]
    };
    TotalDeltas { deltas }
}

fn all_deltas_to_total_deltas(d: &AllDeltas) -> TotalDeltas {
    let len = d.source_deltas.rewards.len();
    let deltas = deltas_to_total_deltas(&d.source_deltas)
        .zip(deltas_to_total_deltas(&d.target_deltas))
        .zip(deltas_to_total_deltas(&d.head_deltas))
        .zip(optional_deltas_to_total_deltas(&d.inclusion_delay_deltas, len).deltas)
        .zip(deltas_to_total_deltas(&d.inactivity_penalty_deltas))
        .map(
            |((((source, target), head), inclusion_delay), inactivity_penalty)| {
                source + target + head + inclusion_delay + inactivity_penalty
            },
        )
        .collect::<Vec<i64>>();
    TotalDeltas { deltas }
}

fn compute_altair_deltas<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<TotalDeltas, EpochProcessingError> {
    // Initialise deltas to pre-state balances.
    let mut deltas = state
        .balances()
        .iter()
        .map(|x| *x as i64)
        .collect::<Vec<_>>();
    altair::process_rewards_and_penalties_slow(state, spec)?;

    for (delta, new_balance) in deltas.iter_mut().zip(state.balances()) {
        let old_balance = *delta;
        *delta = *new_balance as i64 - old_balance;
    }

    Ok(TotalDeltas { deltas })
}
