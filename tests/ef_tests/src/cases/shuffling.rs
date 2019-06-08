use super::*;
use crate::case_result::compare_result;
use serde_derive::Deserialize;
use std::marker::PhantomData;
use swap_or_not_shuffle::{get_permutated_index, shuffle_list};

#[derive(Debug, Clone, Deserialize)]
pub struct Shuffling<T> {
    pub seed: String,
    pub count: usize,
    pub shuffled: Vec<usize>,
    #[serde(skip)]
    _phantom: PhantomData<T>,
}

impl<T> YamlDecode for Shuffling<T> {
    fn yaml_decode(yaml: &String) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(&yaml.as_str()).unwrap())
    }
}

impl<T: EthSpec> Case for Shuffling<T> {
    fn result(&self, _case_index: usize) -> Result<(), Error> {
        if self.count == 0 {
            compare_result::<_, Error>(&Ok(vec![]), &Some(self.shuffled.clone()))?;
        } else {
            let spec = T::default_spec();
            let seed = hex::decode(&self.seed[2..])
                .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

            // Test get_permuted_index
            let shuffling = (0..self.count)
                .into_iter()
                .map(|i| {
                    get_permutated_index(i, self.count, &seed, spec.shuffle_round_count).unwrap()
                })
                .collect();
            compare_result::<_, Error>(&Ok(shuffling), &Some(self.shuffled.clone()))?;

            // Test "shuffle_list"
            let input: Vec<usize> = (0..self.count).collect();
            let shuffling = shuffle_list(input, spec.shuffle_round_count, &seed, false).unwrap();
            compare_result::<_, Error>(&Ok(shuffling), &Some(self.shuffled.clone()))?;
        }

        Ok(())
    }
}
