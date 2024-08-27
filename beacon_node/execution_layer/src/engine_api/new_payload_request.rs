use crate::{block_hash::calculate_execution_block_hash, metrics, Error};

use crate::versioned_hashes::verify_versioned_hashes;
use state_processing::per_block_processing::deneb::kzg_commitment_to_versioned_hash;
use superstruct::superstruct;
use types::{
    BeaconBlockRef, BeaconStateError, EthSpec, ExecutionBlockHash, ExecutionPayload,
    ExecutionPayloadRef, Hash256, VersionedHash,
};
use types::{
    ExecutionPayloadBellatrix, ExecutionPayloadCapella, ExecutionPayloadDeneb,
    ExecutionPayloadElectra, ExecutionRequests,
};

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra),
    variant_attributes(derive(Clone, Debug, PartialEq),),
    map_into(ExecutionPayload),
    map_ref_into(ExecutionPayloadRef),
    cast_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    )
)]
#[derive(Clone, Debug, PartialEq)]
pub struct NewPayloadRequest<'block, E: EthSpec> {
    #[superstruct(
        only(Bellatrix),
        partial_getter(rename = "execution_payload_bellatrix")
    )]
    pub execution_payload: &'block ExecutionPayloadBellatrix<E>,
    #[superstruct(only(Capella), partial_getter(rename = "execution_payload_capella"))]
    pub execution_payload: &'block ExecutionPayloadCapella<E>,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_deneb"))]
    pub execution_payload: &'block ExecutionPayloadDeneb<E>,
    #[superstruct(only(Electra), partial_getter(rename = "execution_payload_electra"))]
    pub execution_payload: &'block ExecutionPayloadElectra<E>,
    #[superstruct(only(Deneb, Electra))]
    pub versioned_hashes: Vec<VersionedHash>,
    #[superstruct(only(Deneb, Electra))]
    pub parent_beacon_block_root: Hash256,
    #[superstruct(only(Electra))]
    pub execution_requests_list: &'block ExecutionRequests<E>,
}

impl<'block, E: EthSpec> NewPayloadRequest<'block, E> {
    pub fn parent_hash(&self) -> ExecutionBlockHash {
        match self {
            Self::Bellatrix(payload) => payload.execution_payload.parent_hash,
            Self::Capella(payload) => payload.execution_payload.parent_hash,
            Self::Deneb(payload) => payload.execution_payload.parent_hash,
            Self::Electra(payload) => payload.execution_payload.parent_hash,
        }
    }

    pub fn block_hash(&self) -> ExecutionBlockHash {
        match self {
            Self::Bellatrix(payload) => payload.execution_payload.block_hash,
            Self::Capella(payload) => payload.execution_payload.block_hash,
            Self::Deneb(payload) => payload.execution_payload.block_hash,
            Self::Electra(payload) => payload.execution_payload.block_hash,
        }
    }

    pub fn block_number(&self) -> u64 {
        match self {
            Self::Bellatrix(payload) => payload.execution_payload.block_number,
            Self::Capella(payload) => payload.execution_payload.block_number,
            Self::Deneb(payload) => payload.execution_payload.block_number,
            Self::Electra(payload) => payload.execution_payload.block_number,
        }
    }

    pub fn execution_payload_ref(&self) -> ExecutionPayloadRef<'block, E> {
        match self {
            Self::Bellatrix(request) => ExecutionPayloadRef::Bellatrix(request.execution_payload),
            Self::Capella(request) => ExecutionPayloadRef::Capella(request.execution_payload),
            Self::Deneb(request) => ExecutionPayloadRef::Deneb(request.execution_payload),
            Self::Electra(request) => ExecutionPayloadRef::Electra(request.execution_payload),
        }
    }

    pub fn into_execution_payload(self) -> ExecutionPayload<E> {
        match self {
            Self::Bellatrix(request) => {
                ExecutionPayload::Bellatrix(request.execution_payload.clone())
            }
            Self::Capella(request) => ExecutionPayload::Capella(request.execution_payload.clone()),
            Self::Deneb(request) => ExecutionPayload::Deneb(request.execution_payload.clone()),
            Self::Electra(request) => ExecutionPayload::Electra(request.execution_payload.clone()),
        }
    }

    /// Performs the required verifications of the payload when the chain is optimistically syncing.
    ///
    /// ## Specification
    ///
    /// Performs the verifications in the `verify_and_notify_new_payload` function:
    ///
    /// https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.2/specs/deneb/beacon-chain.md#modified-verify_and_notify_new_payload
    pub fn perform_optimistic_sync_verifications(&self) -> Result<(), Error> {
        self.verify_payload_block_hash()?;
        self.verify_versioned_hashes()?;

        Ok(())
    }

    /// Verify the block hash is consistent locally within Lighthouse.
    ///
    /// ## Specification
    ///
    /// Equivalent to `is_valid_block_hash` in the spec:
    /// https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.2/specs/deneb/beacon-chain.md#is_valid_block_hash
    pub fn verify_payload_block_hash(&self) -> Result<(), Error> {
        let payload = self.execution_payload_ref();
        let parent_beacon_block_root = self.parent_beacon_block_root().ok().cloned();

        let _timer = metrics::start_timer(&metrics::EXECUTION_LAYER_VERIFY_BLOCK_HASH);

        let (header_hash, rlp_transactions_root) =
            calculate_execution_block_hash(payload, parent_beacon_block_root);

        if header_hash != self.block_hash() {
            return Err(Error::BlockHashMismatch {
                computed: header_hash,
                payload: payload.block_hash(),
                transactions_root: rlp_transactions_root,
            });
        }

        Ok(())
    }

    /// Verify the versioned hashes computed by the blob transactions match the versioned hashes computed from the commitments.
    ///
    /// ## Specification
    ///
    /// Equivalent to `is_valid_versioned_hashes` in the spec:
    /// https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.2/specs/deneb/beacon-chain.md#is_valid_versioned_hashes
    pub fn verify_versioned_hashes(&self) -> Result<(), Error> {
        if let Ok(versioned_hashes) = self.versioned_hashes() {
            verify_versioned_hashes(self.execution_payload_ref(), versioned_hashes)
                .map_err(Error::VerifyingVersionedHashes)?;
        }
        Ok(())
    }
}

impl<'a, E: EthSpec> TryFrom<BeaconBlockRef<'a, E>> for NewPayloadRequest<'a, E> {
    type Error = BeaconStateError;

    fn try_from(block: BeaconBlockRef<'a, E>) -> Result<Self, Self::Error> {
        match block {
            BeaconBlockRef::Base(_) | BeaconBlockRef::Altair(_) => {
                Err(Self::Error::IncorrectStateVariant)
            }
            BeaconBlockRef::Bellatrix(block_ref) => {
                Ok(Self::Bellatrix(NewPayloadRequestBellatrix {
                    execution_payload: &block_ref.body.execution_payload.execution_payload,
                }))
            }
            BeaconBlockRef::Capella(block_ref) => Ok(Self::Capella(NewPayloadRequestCapella {
                execution_payload: &block_ref.body.execution_payload.execution_payload,
            })),
            BeaconBlockRef::Deneb(block_ref) => Ok(Self::Deneb(NewPayloadRequestDeneb {
                execution_payload: &block_ref.body.execution_payload.execution_payload,
                versioned_hashes: block_ref
                    .body
                    .blob_kzg_commitments
                    .iter()
                    .map(kzg_commitment_to_versioned_hash)
                    .collect(),
                parent_beacon_block_root: block_ref.parent_root,
            })),
            BeaconBlockRef::Electra(block_ref) => Ok(Self::Electra(NewPayloadRequestElectra {
                execution_payload: &block_ref.body.execution_payload.execution_payload,
                versioned_hashes: block_ref
                    .body
                    .blob_kzg_commitments
                    .iter()
                    .map(kzg_commitment_to_versioned_hash)
                    .collect(),
                parent_beacon_block_root: block_ref.parent_root,
                execution_requests_list: &block_ref.body.execution_requests,
            })),
            //TODO(EIP7732): Need new method of constructing NewPayloadRequest
            BeaconBlockRef::EIP7732(_) => Err(Self::Error::IncorrectStateVariant),
        }
    }
}

impl<'a, E: EthSpec> TryFrom<ExecutionPayloadRef<'a, E>> for NewPayloadRequest<'a, E> {
    type Error = BeaconStateError;

    fn try_from(payload: ExecutionPayloadRef<'a, E>) -> Result<Self, Self::Error> {
        match payload {
            ExecutionPayloadRef::Bellatrix(payload) => {
                Ok(Self::Bellatrix(NewPayloadRequestBellatrix {
                    execution_payload: payload,
                }))
            }
            ExecutionPayloadRef::Capella(payload) => Ok(Self::Capella(NewPayloadRequestCapella {
                execution_payload: payload,
            })),
            ExecutionPayloadRef::Deneb(_) => Err(Self::Error::IncorrectStateVariant),
            ExecutionPayloadRef::Electra(_) => Err(Self::Error::IncorrectStateVariant),
            //TODO(EIP7732): Probably time to just get rid of this
            ExecutionPayloadRef::EIP7732(_) => Err(Self::Error::IncorrectStateVariant),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::versioned_hashes::Error as VersionedHashError;
    use crate::{Error, NewPayloadRequest};
    use state_processing::per_block_processing::deneb::kzg_commitment_to_versioned_hash;
    use types::{BeaconBlock, ExecPayload, ExecutionBlockHash, Hash256, MainnetEthSpec};

    #[test]
    fn test_optimistic_sync_verifications_valid_block() {
        let beacon_block = get_valid_beacon_block();
        let new_payload_request = NewPayloadRequest::try_from(beacon_block.to_ref())
            .expect("should create new payload request");

        assert!(
            new_payload_request
                .perform_optimistic_sync_verifications()
                .is_ok(),
            "validations should pass"
        );
    }

    #[test]
    fn test_optimistic_sync_verifications_bad_block_hash() {
        let mut beacon_block = get_valid_beacon_block();
        let correct_block_hash = beacon_block
            .body()
            .execution_payload()
            .expect("should get payload")
            .block_hash();
        let invalid_block_hash = ExecutionBlockHash(Hash256::repeat_byte(0x42));

        // now mutate the block hash
        beacon_block
            .body_mut()
            .execution_payload_deneb_mut()
            .expect("should get payload")
            .execution_payload
            .block_hash = invalid_block_hash;

        let new_payload_request = NewPayloadRequest::try_from(beacon_block.to_ref())
            .expect("should create new payload request");
        let verification_result = new_payload_request.perform_optimistic_sync_verifications();
        println!("verification_result: {:?}", verification_result);
        let got_expected_result = match verification_result {
            Err(Error::BlockHashMismatch {
                computed, payload, ..
            }) => computed == correct_block_hash && payload == invalid_block_hash,
            _ => false,
        };
        assert!(got_expected_result, "should return expected error");
    }

    #[test]
    fn test_optimistic_sync_verifications_bad_versioned_hashes() {
        let mut beacon_block = get_valid_beacon_block();

        let mut commitments: Vec<_> = beacon_block
            .body()
            .blob_kzg_commitments()
            .expect("should get commitments")
            .clone()
            .into();

        let correct_versioned_hash = kzg_commitment_to_versioned_hash(
            commitments.last().expect("should get last commitment"),
        );

        // mutate the last commitment
        commitments
            .last_mut()
            .expect("should get last commitment")
            .0[0] = 0x42;

        // calculate versioned hash from mutated commitment
        let bad_versioned_hash = kzg_commitment_to_versioned_hash(
            commitments.last().expect("should get last commitment"),
        );

        *beacon_block
            .body_mut()
            .blob_kzg_commitments_mut()
            .expect("should get commitments") = commitments.into();

        let new_payload_request = NewPayloadRequest::try_from(beacon_block.to_ref())
            .expect("should create new payload request");
        let verification_result = new_payload_request.perform_optimistic_sync_verifications();
        println!("verification_result: {:?}", verification_result);

        let got_expected_result = match verification_result {
            Err(Error::VerifyingVersionedHashes(VersionedHashError::VersionHashMismatch {
                expected,
                found,
            })) => expected == bad_versioned_hash && found == correct_versioned_hash,
            _ => false,
        };
        assert!(got_expected_result, "should return expected error");
    }

    fn get_valid_beacon_block() -> BeaconBlock<MainnetEthSpec> {
        BeaconBlock::Deneb(serde_json::from_str(r#"{
          "slot": "88160",
          "proposer_index": "583",
          "parent_root": "0x60770cd86a497ca3aa2e91f1687aa3ebafac87af52c30a920b5f40bd9e930eb6",
          "state_root": "0x4a0e0abbcbcf576f2cb7387c4289ab13b8a128e32127642f056143d6164941a6",
          "body": {
            "randao_reveal": "0xb5253d5739496abc4f67c7c92e39e46cca452c2fdfc5275e3e0426a012aa62df82f47f7dece348e28db4bb212f0e793d187120bbd47b8031ed79344116eb4128f0ce0b05ba18cd615bb13966c1bd7d89e23cc769c8e4d8e4a63755f623ac3bed",
            "eth1_data": {
              "deposit_root": "0xe4785ac914d8673797f886e3151ce2647f81ae070c7ddb6845e65fd1c47d1222",
              "deposit_count": "1181",
              "block_hash": "0x010671bdfbfce6b0071984a06a7ded6deef13b4f8fdbae402c606a7a0c8780d1"
            },
            "graffiti": "0x6c6f6465737461722f6765746800000000000000000000000000000000000000",
            "proposer_slashings": [],
            "attester_slashings": [],
            "attestations": [],
            "deposits": [],
            "voluntary_exits": [],
            "sync_aggregate": {
              "sync_committee_bits": "0xfebffffffebfff7fff7f7fffbbefffff6affffffffbfffffefffebfffdbf77fff7fd77ffffefffdff7ffffeffffffe7e5ffffffdefffff7ffbffff7fffffffff",
              "sync_committee_signature": "0x91939b5baf2a6f52d405b6dd396f5346ec435eca7d25912c91cc6a2f7030d870d68bebe4f2b21872a06929ff4cf3e5e9191053cb43eb24ebe34b9a75fb88a3acd06baf329c87f68bd664b49891260c698d7bca0f5365870b5b2b3a76f582156c"
            },
            "execution_payload": {
              "parent_hash": "0xa6f3ed782a992f79ad38da2af91b3e8923c71b801c50bc9033bb35a2e1da885f",
              "fee_recipient": "0xf97e180c050e5ab072211ad2c213eb5aee4df134",
              "state_root": "0x3bfd1a7f309ed35048c349a8daf01815bdc09a6d5df86ea77d1056f248ba2017",
              "receipts_root": "0xcb5b8ffea57cd0fa87194d49bc8bb7fad08c93c9934b886489503c328d15fd36",
              "logs_bloom": "0x002000000000000000000000800000000000000000001040000000000000000000000001000000000000000000000000000000000000100000000020000c0800000000000000008000000008000000200000800000000000000000000000000000000000000000008000000000008000000000000000000002000010000000000000000000000000000000000000000000000000000000080000004000000000800000000000000000000100000000000000000000000000000000000800000000000102000000000000000000000000000000080000001000000000000000000000000000000000000000000000000000000000000000000000000000000000",
              "prev_randao": "0xb2693020177d99ffbd4c267023be172d759e7306ff51b0e7d677d3148fbd7f1d",
              "block_number": "74807",
              "gas_limit": "30000000",
              "gas_used": "128393",
              "timestamp": "1697039520",
              "extra_data": "0xd883010d03846765746888676f312e32312e31856c696e7578",
              "base_fee_per_gas": "7",
              "block_hash": "0xc64f3a43c64aeb98518a237f6279fa03095b9f95ca673c860ad7f16fb9340062",
              "transactions": [
                "0x02f9017a8501a1f0ff4382317585012a05f2008512a05f2000830249f094c1b0bc605e2c808aa0867bfc98e51a1fe3e9867f80b901040cc7326300000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000036e534e16b8920d000000000000000000000000fb3e9c7cb92443931ee6b5b9728598d4eb9618c1000000000000000000000000fc7360b3b28cf4204268a8354dbec60720d155d2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000009a054a063f0fe7b9c68de8df91aaa5e96c15ab540000000000000000000000000c8d41b8fcc066cdabaf074d78e5153e8ce018a9c080a07dd9be0d014ffcd5b6883d0917c66b74ba51f0d976c8fc5674af192af6fa9450a02dad2c660974c125f5f22b1e6e8862a292e08cc2b4cafda35af650ee62868a43",
                "0x03f8db8501a1f0ff430d84773594008504a817c8008252089454e594b6de0aa4b0188cd1549dd7ba715a455d078080c08504a817c800f863a001253ce00f525e3495cffa0b865eadb90a4c5ee812185cc796af74b6ec0a5dd7a0010720372a4d7dcab84413ed0cfc164fb91fb6ef1562ec2f7a82e912a1d9e129a0015a73e97950397896ed2c47dcab7c0360220bcfb413a8f210a7b6e6264e698880a04402cb0f13c17ef41dca106b1e1520c7aadcbe62984d81171e29914f587d67c1a02db62a8edb581917958e4a3884e7eececbaec114c5ee496e238033e896f997ac"
              ],
              "withdrawals": [],
              "blob_gas_used": "393216",
              "excess_blob_gas": "58720256"
            },
            "bls_to_execution_changes": [],
            "blob_kzg_commitments": [
              "0xa7accb7a25224a8c2e0cee9cd569fc1798665bfbfe780e08945fa9098ec61da4061f5b04e750a88d3340a801850a54fa",
              "0xac7b47f99836510ae9076dc5f5da1f370679dea1d47073307a14cbb125cdc7822ae619637135777cb40e13d897fd00a7",
              "0x997794110b9655833a88ad5a4ec40a3dc7964877bfbeb04ca1abe1d51bdc43e20e4c5757028896d298d7da954a6f14a1"
            ]
          }
        }"#).expect("should decode"))
    }
}
