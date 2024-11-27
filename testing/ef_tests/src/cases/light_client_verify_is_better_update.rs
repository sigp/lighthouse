use super::*;
use decode::ssz_decode_light_client_update;
use serde::Deserialize;
use types::{LightClientUpdate, Slot};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LightClientVerifyIsBetterUpdate<E: EthSpec> {
    light_client_updates: Vec<LightClientUpdate<E>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Metadata {
    updates_count: u64,
}

impl<E: EthSpec> LoadCase for LightClientVerifyIsBetterUpdate<E> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let mut light_client_updates = vec![];
        let metadata: Metadata = decode::yaml_decode_file(path.join("meta.yaml").as_path())?;
        for index in 0..metadata.updates_count {
            let light_client_update = ssz_decode_light_client_update(
                &path.join(format!("updates_{}.ssz_snappy", index)),
                &fork_name,
            )?;
            light_client_updates.push(light_client_update);
        }

        Ok(Self {
            light_client_updates,
        })
    }
}

impl<E: EthSpec> Case for LightClientVerifyIsBetterUpdate<E> {
    // Light client updates in `self.light_client_updates` are ordered in descending precedence
    // where the update at index = 0 is considered the best update. This test iterates through
    // all light client updates in a nested loop to make all possible comparisons. If a light client update
    // at index `i`` is considered 'better' than a light client update at index `j`` when `i > j`, this test fails.
    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let spec = fork_name.make_genesis_spec(E::default_spec());
        for (i, ith_light_client_update) in self.light_client_updates.iter().enumerate() {
            for (j, jth_light_client_update) in self.light_client_updates.iter().enumerate() {
                eprintln!("{i} {j}");
                if i == j {
                    continue;
                }

                let is_better_update = ith_light_client_update
                    .is_better_light_client_update(jth_light_client_update, &spec)
                    .unwrap();

                let ith_summary =
                    LightClientUpdateSummary::from_update(ith_light_client_update, &spec);
                let jth_summary =
                    LightClientUpdateSummary::from_update(jth_light_client_update, &spec);

                let (best_index, other_index, best_update, other_update, failed) = if i < j {
                    // i is better, so is_better_update must return false
                    (i, j, ith_summary, jth_summary, is_better_update)
                } else {
                    // j is better, so is_better must return true
                    (j, i, jth_summary, ith_summary, !is_better_update)
                };

                if failed {
                    eprintln!("is_better_update: {is_better_update}");
                    eprintln!("index {best_index} update {best_update:?}");
                    eprintln!("index {other_index} update {other_update:?}");
                    eprintln!(
                        "update at index {best_index} must be considered better than update at index {other_index}"
                    );
                    return Err(Error::FailedComparison(format!(
                        "update at index {best_index} must be considered better than update at index {other_index}"
                    )));
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct LightClientUpdateSummary {
    participants: usize,
    supermajority: bool,
    relevant_sync_committee: bool,
    has_finality: bool,
    has_sync_committee_finality: bool,
    header_slot: Slot,
    signature_slot: Slot,
}

impl LightClientUpdateSummary {
    fn from_update<E: EthSpec>(update: &LightClientUpdate<E>, spec: &ChainSpec) -> Self {
        let max_participants = update.sync_aggregate().sync_committee_bits.len();
        let participants = update.sync_aggregate().sync_committee_bits.num_set_bits();
        Self {
            participants,
            supermajority: participants * 3 > max_participants * 2,
            relevant_sync_committee: update.is_sync_committee_update(spec).unwrap(),
            has_finality: !update.is_finality_branch_empty(),
            has_sync_committee_finality: update.has_sync_committee_finality(spec).unwrap(),
            header_slot: update.attested_header_slot(),
            signature_slot: *update.signature_slot(),
        }
    }
}
