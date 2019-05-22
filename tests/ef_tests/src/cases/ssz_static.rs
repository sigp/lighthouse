use super::*;
use crate::case_result::compare_result;
use cached_tree_hash::{CachedTreeHash, TreeHashCache};
use serde_derive::Deserialize;
use ssz::{Decode, Encode};
use std::fmt::Debug;
use std::marker::PhantomData;
use tree_hash::TreeHash;
use types::{
    test_utils::{SeedableRng, TestRandom, XorShiftRng},
    Attestation, AttestationData, AttestationDataAndCustodyBit, AttesterSlashing, BeaconBlock,
    BeaconBlockBody, BeaconBlockHeader, BeaconState, Crosslink, Deposit, DepositData, Eth1Data,
    EthSpec, Fork, Hash256, HistoricalBatch, IndexedAttestation, PendingAttestation,
    ProposerSlashing, Transfer, Validator, VoluntaryExit,
};

#[derive(Debug, Clone, Deserialize)]
pub struct SszStatic<E> {
    pub type_name: String,
    pub serialized: String,
    pub root: String,
    #[serde(skip)]
    pub raw_yaml: String,
    #[serde(skip, default)]
    _phantom: PhantomData<E>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Value<T> {
    value: T,
}

impl<E> YamlDecode for SszStatic<E> {
    fn yaml_decode(yaml: &String) -> Result<Self, Error> {
        let mut ssz_static: SszStatic<E> = serde_yaml::from_str(&yaml.as_str()).unwrap();

        ssz_static.raw_yaml = yaml.clone();

        Ok(ssz_static)
    }
}

impl<E> SszStatic<E> {
    fn value<T: serde::de::DeserializeOwned>(&self) -> Result<T, Error> {
        let wrapper: Value<T> = serde_yaml::from_str(&self.raw_yaml.as_str()).map_err(|e| {
            Error::FailedToParseTest(format!("Unable to parse {} YAML: {:?}", self.type_name, e))
        })?;

        Ok(wrapper.value)
    }
}

impl<E: EthSpec> Case for SszStatic<E> {
    fn result(&self, _case_index: usize) -> Result<(), Error> {
        match self.type_name.as_ref() {
            "Fork" => ssz_static_test::<Fork, E>(self),
            "Crosslink" => ssz_static_test::<Crosslink, E>(self),
            "Eth1Data" => ssz_static_test::<Eth1Data, E>(self),
            "AttestationData" => ssz_static_test::<AttestationData, E>(self),
            "AttestationDataAndCustodyBit" => {
                ssz_static_test::<AttestationDataAndCustodyBit, E>(self)
            }
            "IndexedAttestation" => ssz_static_test::<IndexedAttestation, E>(self),
            "DepositData" => ssz_static_test::<DepositData, E>(self),
            "BeaconBlockHeader" => ssz_static_test::<BeaconBlockHeader, E>(self),
            "Validator" => ssz_static_test::<Validator, E>(self),
            "PendingAttestation" => ssz_static_test::<PendingAttestation, E>(self),
            "HistoricalBatch" => ssz_static_test::<HistoricalBatch<E>, E>(self),
            "ProposerSlashing" => ssz_static_test::<ProposerSlashing, E>(self),
            "AttesterSlashing" => ssz_static_test::<AttesterSlashing, E>(self),
            "Attestation" => ssz_static_test::<Attestation, E>(self),
            "Deposit" => ssz_static_test::<Deposit, E>(self),
            "VoluntaryExit" => ssz_static_test::<VoluntaryExit, E>(self),
            "Transfer" => ssz_static_test::<Transfer, E>(self),
            "BeaconBlockBody" => ssz_static_test::<BeaconBlockBody, E>(self),
            "BeaconBlock" => ssz_static_test::<BeaconBlock, E>(self),
            "BeaconState" => ssz_static_test::<BeaconState<E>, E>(self),
            _ => Err(Error::FailedToParseTest(format!(
                "Unknown type: {}",
                self.type_name
            ))),
        }
    }
}

fn ssz_static_test<T, E: EthSpec>(tc: &SszStatic<E>) -> Result<(), Error>
where
    T: Clone
        + Decode
        + Debug
        + Encode
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

    // Verify we can encode the result back into original ssz bytes
    let decoded = decode_result.unwrap();
    let encoded_result = decoded.as_ssz_bytes();
    compare_result::<Vec<u8>, Error>(&Ok(encoded_result), &Some(ssz))?;

    // Verify the TreeHash root of the decoded struct matches the test.
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
