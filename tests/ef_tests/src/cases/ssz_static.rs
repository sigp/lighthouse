use super::*;
use crate::case_result::compare_result;
use cached_tree_hash::{CachedTreeHash, TreeHashCache};
use rayon::prelude::*;
use serde_derive::Deserialize;
use ssz::Decode;
use std::fmt::Debug;
use tree_hash::TreeHash;
use types::{
    test_utils::{SeedableRng, TestRandom, XorShiftRng},
    Attestation, AttestationData, AttestationDataAndCustodyBit, AttesterSlashing, BeaconBlock,
    BeaconBlockBody, BeaconBlockHeader, BeaconState, Crosslink, Deposit, DepositData, Eth1Data,
    EthSpec, Fork, Hash256, HistoricalBatch, IndexedAttestation, PendingAttestation,
    ProposerSlashing, Transfer, Validator, VoluntaryExit,
};

#[derive(Debug, Clone, Deserialize)]
pub struct SszStatic {
    pub type_name: String,
    pub serialized: String,
    pub root: String,
    #[serde(skip)]
    pub raw_yaml: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Value<T> {
    value: T,
}

impl YamlDecode for SszStatic {
    fn yaml_decode(yaml: &String) -> Result<Self, Error> {
        let mut ssz_static: SszStatic = serde_yaml::from_str(&yaml.as_str()).unwrap();

        ssz_static.raw_yaml = yaml.clone();

        Ok(ssz_static)
    }
}

impl SszStatic {
    fn value<T: serde::de::DeserializeOwned>(&self) -> Result<T, Error> {
        let wrapper: Value<T> = serde_yaml::from_str(&self.raw_yaml.as_str()).map_err(|e| {
            Error::FailedToParseTest(format!("Unable to parse {} YAML: {:?}", self.type_name, e))
        })?;

        Ok(wrapper.value)
    }
}

impl EfTest for Cases<SszStatic> {
    fn test_results<E: EthSpec>(&self) -> Vec<CaseResult> {
        self.test_cases
            .par_iter()
            .enumerate()
            .map(|(i, tc)| {
                let result = match tc.type_name.as_ref() {
                    "Fork" => ssz_static_test::<Fork>(tc),
                    "Crosslink" => ssz_static_test::<Crosslink>(tc),
                    "Eth1Data" => ssz_static_test::<Eth1Data>(tc),
                    "AttestationData" => ssz_static_test::<AttestationData>(tc),
                    "AttestationDataAndCustodyBit" => {
                        ssz_static_test::<AttestationDataAndCustodyBit>(tc)
                    }
                    "IndexedAttestation" => ssz_static_test::<IndexedAttestation>(tc),
                    "DepositData" => ssz_static_test::<DepositData>(tc),
                    "BeaconBlockHeader" => ssz_static_test::<BeaconBlockHeader>(tc),
                    "Validator" => ssz_static_test::<Validator>(tc),
                    "PendingAttestation" => ssz_static_test::<PendingAttestation>(tc),
                    "HistoricalBatch" => ssz_static_test::<HistoricalBatch<E>>(tc),
                    "ProposerSlashing" => ssz_static_test::<ProposerSlashing>(tc),
                    "AttesterSlashing" => ssz_static_test::<AttesterSlashing>(tc),
                    "Attestation" => ssz_static_test::<Attestation>(tc),
                    "Deposit" => ssz_static_test::<Deposit>(tc),
                    "VoluntaryExit" => ssz_static_test::<VoluntaryExit>(tc),
                    "Transfer" => ssz_static_test::<Transfer>(tc),
                    "BeaconBlockBody" => ssz_static_test::<BeaconBlockBody>(tc),
                    "BeaconBlock" => ssz_static_test::<BeaconBlock>(tc),
                    "BeaconState" => ssz_static_test::<BeaconState<E>>(tc),
                    _ => Err(Error::FailedToParseTest(format!(
                        "Unknown type: {}",
                        tc.type_name
                    ))),
                };

                CaseResult::new(i, tc, result)
            })
            .collect()
    }
}

fn ssz_static_test<T>(tc: &SszStatic) -> Result<(), Error>
where
    T: Decode
        + Debug
        + PartialEq<T>
        + serde::de::DeserializeOwned
        + TreeHash
        + CachedTreeHash
        + TestRandom,
{
    // Verify we can decode SSZ in the same way we can decode YAML.
    let ssz = hex::decode(&tc.serialized[2..])
        .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
    let expected = tc.value::<T>()?;
    let decode_result = T::from_ssz_bytes(&ssz);
    compare_result(&decode_result, &Some(expected))?;

    // Verify the TreeHash root of the decoded struct matches the test.
    let decoded = decode_result.unwrap();
    let expected_root =
        &hex::decode(&tc.root[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
    let expected_root = Hash256::from_slice(&expected_root);
    let tree_hash_root = Hash256::from_slice(&decoded.tree_hash_root());
    compare_result::<Hash256, Error>(&Ok(tree_hash_root), &Some(expected_root))?;

    // Verify a _new_ CachedTreeHash root of the decoded struct matches the test.
    let cache = TreeHashCache::new(&decoded).unwrap();
    let cached_tree_hash_root = Hash256::from_slice(cache.tree_hash_root().unwrap());
    compare_result::<Hash256, Error>(&Ok(cached_tree_hash_root), &Some(expected_root))?;

    // Verify the root after an update from a random CachedTreeHash to the decoded struct.
    let mut rng = XorShiftRng::from_seed([42; 16]);
    let random_instance = T::random_for_test(&mut rng);
    let mut cache = TreeHashCache::new(&random_instance).unwrap();
    cache.update(&decoded).unwrap();
    let updated_root = Hash256::from_slice(cache.tree_hash_root().unwrap());
    compare_result::<Hash256, Error>(&Ok(updated_root), &Some(expected_root))?;

    Ok(())
}
