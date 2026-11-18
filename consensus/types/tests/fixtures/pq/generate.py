"""Generate M1b SSZ fixtures using the built consensus-specs pyspec.

Run with the Python environment from consensus-specs at
a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c after running its make build target.
"""

import json
from pathlib import Path

from eth_consensus_specs.pq import mainnet, minimal


def generate(spec):
    def byte_pattern(length, seed):
        return bytes((seed + 13 * i) % 256 for i in range(length))

    def root(seed):
        return spec.Root(byte_pattern(32, seed))

    def sequence(container, field, values):
        return container.model_fields[field].annotation(data=values)

    pubkey = spec.XMSSPubkey(byte_pattern(32, 3))
    signature = spec.XMSSSignature(byte_pattern(2404, 8))
    proof = spec.AttestationProof(data=byte_pattern(97, 14))
    data = spec.AttestationData(
        slot=17,
        beacon_block_root=root(16),
        source=spec.Checkpoint(epoch=1, root=root(17)),
        target=spec.Checkpoint(epoch=2, root=root(18)),
    )
    attestation = spec.Attestation(
        aggregation_bits=sequence(
            spec.Attestation, "aggregation_bits", [True, False, True, False, True]
        ),
        data=data,
        committee_bits=spec.CommitteeBits(
            data=[i in (1, spec.MAX_COMMITTEES_PER_SLOT_PQ - 1)
                  for i in range(spec.MAX_COMMITTEES_PER_SLOT_PQ)]
        ),
    )
    indexed_attestation = spec.IndexedAttestation(
        attesting_indices=sequence(
            spec.IndexedAttestation, "attesting_indices", [1, 4, 5, 10, 95]
        ),
        data=data,
        proof=proof,
    )
    attester_slashing = spec.AttesterSlashing(
        attestation_1=indexed_attestation,
        attestation_2=spec.IndexedAttestation(
            attesting_indices=indexed_attestation.attesting_indices,
            data=spec.AttestationData(slot=18, beacon_block_root=root(19)),
            proof=spec.AttestationProof(data=b"second proof"),
        ),
    )
    aggregate = spec.AggregateAndProof(aggregator_index=34, aggregate=attestation, proof=proof)
    signed_aggregate = spec.SignedAggregateAndProof(message=aggregate, signature=signature)
    single = spec.SingleAttestation(
        committee_index=2, attester_index=5, data=data, signature=signature
    )
    header = spec.SignedBeaconBlockHeader(
        message=spec.BeaconBlockHeader(
            slot=17, proposer_index=11, parent_root=root(20), body_root=root(21)
        ),
        signature=signature,
    )
    slashing = spec.ProposerSlashing(
        signed_header_1=header,
        signed_header_2=spec.SignedBeaconBlockHeader(
            message=spec.BeaconBlockHeader(
                slot=17, proposer_index=11, parent_root=root(20), body_root=root(22)
            ),
            signature=spec.XMSSSignature(byte_pattern(2404, 9)),
        ),
    )
    validator_request = spec.ValidatorPreregistrationRequest(
        pubkey=pubkey, withdrawal_credentials=root(23), vrf_root=root(24)
    )
    builder_request = spec.BuilderPreregistrationRequest(pubkey=pubkey, withdrawal_credentials=root(25))
    validator_prereg = spec.ValidatorPreregistration(
        pubkey=pubkey, withdrawal_credentials=root(23), vrf_root=root(24), expiry_slot=123
    )
    builder_prereg = spec.BuilderPreregistration(
        pubkey=pubkey, withdrawal_credentials=root(25), expiry_slot=456
    )
    exit_request = spec.VoluntaryExitRequest(pubkey=pubkey)
    request = spec.DepositRequest(
        pubkey=spec.Bytes48(bytes(16) + bytes(pubkey)),
        withdrawal_credentials=root(27),
        amount=32_000_000_000,
        signature=spec.Bytes96(byte_pattern(96, 28)),
        index=12,
    )
    requests = spec.ExecutionRequests(
        deposits=spec.DepositRequests(data=[request]),
        validator_preregistrations=spec.ValidatorPreregistrationRequests(data=[validator_request]),
        builder_preregistrations=spec.BuilderPreregistrationRequests(data=[builder_request]),
        voluntary_exits=spec.VoluntaryExitRequests(data=[exit_request]),
    )
    bid = spec.SignedExecutionPayloadBid(
        message=spec.ExecutionPayloadBid(
            parent_block_hash=root(30),
            block_hash=root(31),
            gas_limit=30_000_000,
            slot=17,
            builder_index=5,
            execution_requests_root=requests.hash_tree_root(),
        ),
        signature=signature,
    )
    envelope = spec.ExecutionPayloadEnvelope(
        payload=spec.ExecutionPayload(block_number=63, slot_number=17, block_hash=root(31)),
        execution_requests=requests,
        builder_index=5,
        beacon_block_root=root(32),
        parent_beacon_block_root=root(33),
    )
    signed_envelope = spec.SignedExecutionPayloadEnvelope(message=envelope, signature=signature)
    payload_attestation = spec.PayloadAttestationMessage(
        validator_index=18,
        data=spec.PayloadAttestationData(
            slot=17, beacon_block_root=root(32), payload_present=True
        ),
        signature=signature,
    )
    preferences = spec.SignedProposerPreferences(
        message=spec.ProposerPreferences(
            dependent_root=root(33), proposal_slot=17, validator_index=11, target_gas_limit=30_000_000
        ),
        signature=signature,
    )
    vrf_proof = spec.VRFProof(data=[spec.Bytes32(byte_pattern(32, i)) for i in range(32)])
    body = spec.BeaconBlockBody(
        randao_reveal=vrf_proof,
        graffiti=root(34),
        proposer_slashings=sequence(spec.BeaconBlockBody, "proposer_slashings", [slashing]),
        attester_slashings=sequence(spec.BeaconBlockBody, "attester_slashings", [attester_slashing]),
        attestations=sequence(spec.BeaconBlockBody, "attestations", [attestation]),
        signed_execution_payload_bid=bid,
        parent_execution_requests=requests,
        proof=proof,
    )
    block = spec.BeaconBlock(
        slot=17, proposer_index=11, parent_root=root(33), state_root=root(35), body=body
    )
    signed_block = spec.SignedBeaconBlock(message=block, signature=signature)
    committee = spec.AggregationCommittee(data=[1, 3, 9, 200, 19, 1029])
    committees = spec.AggregationCommittees(
        data=[committee, spec.AggregationCommittee(data=[5, 21])]
    )
    window = spec.AggregationCommitteeWindow(
        data=[committees] + [spec.AggregationCommittees()] *
        (len(spec.AggregationCommitteeWindow().data) - 1)
    )
    objects = [
        pubkey, signature, proof, vrf_proof, attestation, indexed_attestation,
        attester_slashing, aggregate, signed_aggregate, single, header, slashing,
        validator_request, builder_request, validator_prereg, builder_prereg, exit_request,
        request, requests, bid, envelope, signed_envelope, payload_attestation, preferences,
        body, block, signed_block, committee, committees, window,
    ]

    fixtures = {}
    for populated in objects:
        name = type(populated).__name__
        fixtures[name] = []
        for value in (type(populated)(), populated):
            fixture = {"ssz": value.encode_bytes().hex(), "root": "0x" + value.hash_tree_root().hex()}
            if isinstance(value, spec.ExecutionRequests):
                fixture["execution_requests"] = [
                    "0x" + request.hex() for request in spec.get_execution_requests_list(value)
                ]
            fixtures[name].append(fixture)
    return fixtures


for preset in (mainnet, minimal):
    name = preset.__name__.rsplit(".", 1)[1]
    output = Path(__file__).with_name(f"{name}.json")
    output.write_text(json.dumps(generate(preset), indent=2, sort_keys=True) + "\n")
