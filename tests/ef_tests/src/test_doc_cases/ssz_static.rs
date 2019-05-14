use super::*;
use tree_hash::TreeHash;
use types::{
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

impl TestDecode for SszStatic {
    fn test_decode(yaml: &String) -> Result<Self, Error> {
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

impl Test for TestDocCases<SszStatic> {
    fn test<E: EthSpec>(&self) -> Vec<TestCaseResult> {
        self.test_cases
            .iter()
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

                TestCaseResult::new(i, tc, result)
            })
            .collect()
    }
}

fn ssz_static_test<T>(tc: &SszStatic) -> Result<(), Error>
where
    T: Decode + Debug + PartialEq<T> + serde::de::DeserializeOwned + TreeHash,
{
    // Verify we can decode SSZ in the same way we can decode YAML.
    let ssz = hex::decode(&tc.serialized[2..])
        .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
    let expected = tc.value::<T>()?;
    let decode_result = T::from_ssz_bytes(&ssz);
    compare_result(&decode_result, &Some(expected))?;

    // Verify the tree hash root is identical to the decoded struct.
    let root_bytes =
        &hex::decode(&tc.root[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
    let expected_root = Hash256::from_slice(&root_bytes);
    let root = Hash256::from_slice(&decode_result.unwrap().tree_hash_root());
    compare_result::<Hash256, Error>(&Ok(root), &Some(expected_root))?;

    Ok(())
}
