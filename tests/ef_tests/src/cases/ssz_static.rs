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

// Enum variant names are used by Serde when deserializing the test YAML
#[derive(Debug, Clone, Deserialize)]
pub enum SszStatic<E>
where
    E: EthSpec,
{
    Fork(SszStaticInner<Fork, E>),
    Crosslink(SszStaticInner<Crosslink, E>),
    Eth1Data(SszStaticInner<Eth1Data, E>),
    AttestationData(SszStaticInner<AttestationData, E>),
    AttestationDataAndCustodyBit(SszStaticInner<AttestationDataAndCustodyBit, E>),
    IndexedAttestation(SszStaticInner<IndexedAttestation, E>),
    DepositData(SszStaticInner<DepositData, E>),
    BeaconBlockHeader(SszStaticInner<BeaconBlockHeader, E>),
    Validator(SszStaticInner<Validator, E>),
    PendingAttestation(SszStaticInner<PendingAttestation, E>),
    HistoricalBatch(SszStaticInner<HistoricalBatch<E>, E>),
    ProposerSlashing(SszStaticInner<ProposerSlashing, E>),
    AttesterSlashing(SszStaticInner<AttesterSlashing, E>),
    Attestation(SszStaticInner<Attestation, E>),
    Deposit(SszStaticInner<Deposit, E>),
    VoluntaryExit(SszStaticInner<VoluntaryExit, E>),
    Transfer(SszStaticInner<Transfer, E>),
    BeaconBlockBody(SszStaticInner<BeaconBlockBody, E>),
    BeaconBlock(SszStaticInner<BeaconBlock, E>),
    BeaconState(SszStaticInner<BeaconState<E>, E>),
}

#[derive(Debug, Clone, Deserialize)]
pub struct SszStaticInner<T, E>
where
    E: EthSpec,
{
    pub value: T,
    pub serialized: String,
    pub root: String,
    #[serde(skip, default)]
    _phantom: PhantomData<E>,
}

impl<E: EthSpec + serde::de::DeserializeOwned> YamlDecode for SszStatic<E> {
    fn yaml_decode(yaml: &str) -> Result<Self, Error> {
        serde_yaml::from_str(yaml).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))
    }
}

impl<E: EthSpec> Case for SszStatic<E> {
    fn result(&self, _case_index: usize) -> Result<(), Error> {
        use self::SszStatic::*;

        match *self {
            Fork(ref val) => ssz_static_test(val),
            Crosslink(ref val) => ssz_static_test(val),
            Eth1Data(ref val) => ssz_static_test(val),
            AttestationData(ref val) => ssz_static_test(val),
            AttestationDataAndCustodyBit(ref val) => ssz_static_test(val),
            IndexedAttestation(ref val) => ssz_static_test(val),
            DepositData(ref val) => ssz_static_test(val),
            BeaconBlockHeader(ref val) => ssz_static_test(val),
            Validator(ref val) => ssz_static_test(val),
            PendingAttestation(ref val) => ssz_static_test(val),
            HistoricalBatch(ref val) => ssz_static_test(val),
            ProposerSlashing(ref val) => ssz_static_test(val),
            AttesterSlashing(ref val) => ssz_static_test(val),
            Attestation(ref val) => ssz_static_test(val),
            Deposit(ref val) => ssz_static_test(val),
            VoluntaryExit(ref val) => ssz_static_test(val),
            Transfer(ref val) => ssz_static_test(val),
            BeaconBlockBody(ref val) => ssz_static_test(val),
            BeaconBlock(ref val) => ssz_static_test(val),
            BeaconState(ref val) => ssz_static_test(val),
        }
    }
}

fn ssz_static_test<T, E: EthSpec>(tc: &SszStaticInner<T, E>) -> Result<(), Error>
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
    let expected = tc.value.clone();
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
