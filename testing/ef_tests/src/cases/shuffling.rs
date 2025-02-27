use super::*;
use crate::case_result::compare_result;
use crate::decode::yaml_decode_file;
use serde::Deserialize;
use std::marker::PhantomData;
use swap_or_not_shuffle::{compute_shuffled_index, shuffle_list};

#[derive(Debug, Clone, Deserialize)]
pub struct Shuffling<E> {
    pub seed: String,
    pub count: usize,
    pub mapping: Vec<usize>,
    #[serde(skip)]
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> LoadCase for Shuffling<E> {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        yaml_decode_file(&path.join("mapping.yaml"))
    }
}

impl<E: EthSpec> Case for Shuffling<E> {
    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        if self.count == 0 {
            compare_result::<_, Error>(&Ok(vec![]), &Some(self.mapping.clone()))?;
        } else {
            let spec = E::default_spec();
            let seed = hex::decode(&self.seed[2..])
                .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

            // Test compute_shuffled_index
            let shuffling = (0..self.count)
                .map(|i| {
                    compute_shuffled_index(i, self.count, &seed, spec.shuffle_round_count).unwrap()
                })
                .collect();
            compare_result::<_, Error>(&Ok(shuffling), &Some(self.mapping.clone()))?;

            // Test "shuffle_list"
            let input: Vec<usize> = (0..self.count).collect();
            let shuffling = shuffle_list(input, spec.shuffle_round_count, &seed, false).unwrap();
            compare_result::<_, Error>(&Ok(shuffling), &Some(self.mapping.clone()))?;
        }

        Ok(())
    }
}
