use super::*;
use decode::ssz_decode_light_client_update;
use serde::Deserialize;
use types::LightClientUpdate;

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
                if i == j {
                    continue;
                }

                let is_better_update = ith_light_client_update
                    .is_better_light_client_update(jth_light_client_update, &spec)
                    .unwrap();

                if (is_better_update && (i < j)) || (!is_better_update && (i > j)) {
                    return Err(Error::FailedComparison(
                        format!("Light client update at index {} should not be considered a better update than the light client update at index {}", i, j)
                    ));
                }
            }
        }

        Ok(())
    }
}
