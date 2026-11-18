use serde::Deserialize;
use ssz::{Decode, Encode};
use std::collections::BTreeMap;
use tree_hash::TreeHash;
use types::*;

#[derive(Deserialize)]
struct Fixture {
    ssz: String,
    root: Hash256,
    #[serde(default)]
    execution_requests: Vec<String>,
}

type Fixtures = BTreeMap<String, Vec<Fixture>>;

fn check<T: Decode + Encode + TreeHash>(fixtures: &Fixtures, name: &str) {
    for (index, fixture) in fixtures[name].iter().enumerate() {
        let bytes = hex::decode(&fixture.ssz).unwrap();
        let value = T::from_ssz_bytes(&bytes)
            .unwrap_or_else(|error| panic!("{name} fixture {index}: {error:?}"));
        assert_eq!(value.as_ssz_bytes(), bytes, "{name} fixture {index}");
        assert_eq!(
            value.tree_hash_root(),
            fixture.root,
            "{name} fixture {index}"
        );
    }
}

fn check_fixtures<E: EthSpec>(fixture_data: &str) {
    let fixtures: Fixtures = serde_json::from_str(fixture_data).unwrap();

    check::<XmssPublicKey>(&fixtures, "XMSSPubkey");
    check::<XmssSignature>(&fixtures, "XMSSSignature");
    check::<VrfProof>(&fixtures, "VRFProof");
    check::<AttestationProof<E>>(&fixtures, "AttestationProof");
    check::<AttestationPq<E>>(&fixtures, "Attestation");
    check::<IndexedAttestationPq<E>>(&fixtures, "IndexedAttestation");
    check::<AttesterSlashingPq<E>>(&fixtures, "AttesterSlashing");
    check::<AggregateAndProofPq<E>>(&fixtures, "AggregateAndProof");
    check::<SignedAggregateAndProofPq<E>>(&fixtures, "SignedAggregateAndProof");
    check::<SingleAttestationPq>(&fixtures, "SingleAttestation");
    check::<SignedBeaconBlockHeaderPq>(&fixtures, "SignedBeaconBlockHeader");
    check::<ProposerSlashingPq>(&fixtures, "ProposerSlashing");
    check::<ValidatorPreregistrationRequest>(&fixtures, "ValidatorPreregistrationRequest");
    check::<BuilderPreregistrationRequest>(&fixtures, "BuilderPreregistrationRequest");
    check::<ValidatorPreregistration>(&fixtures, "ValidatorPreregistration");
    check::<BuilderPreregistration>(&fixtures, "BuilderPreregistration");
    check::<VoluntaryExitRequest>(&fixtures, "VoluntaryExitRequest");
    check::<DepositRequest>(&fixtures, "DepositRequest");
    check::<ExecutionRequestsPq<E>>(&fixtures, "ExecutionRequests");
    check::<SignedExecutionPayloadBidPq<E>>(&fixtures, "SignedExecutionPayloadBid");
    check::<ExecutionPayloadEnvelopePq<E>>(&fixtures, "ExecutionPayloadEnvelope");
    check::<SignedExecutionPayloadEnvelopePq<E>>(&fixtures, "SignedExecutionPayloadEnvelope");
    check::<PayloadAttestationMessagePq>(&fixtures, "PayloadAttestationMessage");
    check::<SignedProposerPreferencesPq>(&fixtures, "SignedProposerPreferences");
    check::<BeaconBlockBodyPq<E>>(&fixtures, "BeaconBlockBody");
    check::<BeaconBlockPq<E>>(&fixtures, "BeaconBlock");
    check::<SignedBeaconBlockPq<E>>(&fixtures, "SignedBeaconBlock");
    check::<AggregationCommittee>(&fixtures, "AggregationCommittee");
    check::<AggregationCommittees>(&fixtures, "AggregationCommittees");
    check::<AggregationCommitteeWindow<E>>(&fixtures, "AggregationCommitteeWindow");

    for fixture in &fixtures["ExecutionRequests"] {
        let bytes = hex::decode(&fixture.ssz).unwrap();
        let requests =
            ExecutionRequests::<E>::from_ssz_bytes_by_fork(&bytes, ForkName::Pq).unwrap();
        let ExecutionRequests::Pq(requests) = requests else {
            panic!("wrong execution requests variant");
        };
        let encoded = requests
            .get_execution_requests_list()
            .iter()
            .map(|request| format!("0x{}", hex::encode(request)))
            .collect::<Vec<_>>();
        assert_eq!(encoded, fixture.execution_requests);
    }

    let spec = ForkName::Pq.make_genesis_spec(E::default_spec());
    for fixture in &fixtures["SignedBeaconBlock"] {
        let bytes = hex::decode(&fixture.ssz).unwrap();
        let block = SignedBeaconBlock::<E>::from_ssz_bytes_by_fork(&bytes, ForkName::Pq).unwrap();
        assert!(matches!(block, SignedBeaconBlock::Pq(_)));
        assert_eq!(block.tree_hash_root(), fixture.root);
        assert_eq!(block.as_ssz_bytes(), bytes);
        assert_eq!(
            SignedBeaconBlock::from_ssz_bytes(&bytes, &spec).unwrap(),
            block
        );
        assert_eq!(
            SignedBeaconBlock::any_from_ssz_bytes(&bytes).unwrap(),
            block
        );
        assert!(SignedBeaconBlock::<E>::from_ssz_bytes_by_fork(&bytes, ForkName::Gloas).is_err());
        assert!(matches!(
            block.signed_block_header(),
            SignedBeaconBlockHeader::Pq(_)
        ));
        assert_eq!(block.clone_as_blinded().tree_hash_root(), fixture.root);
    }
}

#[test]
fn mainnet_pyspec_fixtures() {
    check_fixtures::<MainnetEthSpec>(include_str!("fixtures/pq/mainnet.json"));
}

#[test]
fn minimal_pyspec_fixtures() {
    check_fixtures::<MinimalEthSpec>(include_str!("fixtures/pq/minimal.json"));
}

fn hash_pair(left: Hash256, right: Hash256) -> Hash256 {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(left.as_slice());
    bytes[32..].copy_from_slice(right.as_slice());
    ethereum_hashing::hash_fixed(&bytes).into()
}

fn binary_merkle_root(leaves: &[Hash256]) -> Hash256 {
    if let [leaf] = leaves {
        return *leaf;
    }
    let (left, right) = leaves.split_at(leaves.len() / 2);
    hash_pair(binary_merkle_root(left), binary_merkle_root(right))
}

#[test]
fn gapped_progressive_roots() {
    let fixtures: Fixtures =
        serde_json::from_str(include_str!("fixtures/pq/mainnet.json")).unwrap();
    let bytes = hex::decode(&fixtures["Attestation"][1].ssz).unwrap();
    let attestation = AttestationPq::<MainnetEthSpec>::from_ssz_bytes(&bytes).unwrap();

    let zero = Hash256::ZERO;
    let aggregation_bits = attestation.aggregation_bits.tree_hash_root();
    let data = attestation.data.tree_hash_root();
    let committee_bits = attestation.committee_bits.tree_hash_root();
    let rest = binary_merkle_root(&[data, zero, committee_bits, zero]);
    let mut mask = [0; 32];
    mask[0] = 0b1011;
    let expected = hash_pair(
        hash_pair(aggregation_bits, hash_pair(rest, zero)),
        mask.into(),
    );
    assert_eq!(attestation.tree_hash_root(), expected);

    let bytes = hex::decode(&fixtures["ExecutionRequests"][1].ssz).unwrap();
    let requests = ExecutionRequestsPq::<MainnetEthSpec>::from_ssz_bytes(&bytes).unwrap();
    let first = requests.deposits.tree_hash_root();
    let second = binary_merkle_root(&[
        requests.withdrawals.tree_hash_root(),
        requests.consolidations.tree_hash_root(),
        requests.builder_deposits.tree_hash_root(),
        requests.builder_exits.tree_hash_root(),
    ]);
    let mut last = [zero; 16];
    last[2] = requests.validator_preregistrations.tree_hash_root();
    last[3] = requests.builder_preregistrations.tree_hash_root();
    last[4] = requests.voluntary_exits.tree_hash_root();
    let last = hash_pair(binary_merkle_root(&last), zero);
    let mut mask = [0; 32];
    mask[..2].copy_from_slice(&[0b1001_1111, 0b11]);
    let expected = hash_pair(hash_pair(first, hash_pair(second, last)), mask.into());
    assert_eq!(requests.tree_hash_root(), expected);
}
