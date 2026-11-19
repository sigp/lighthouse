"""Generate PQ SSZ fixtures using the built consensus-specs pyspec.

Run with the Python environment from consensus-specs at
a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c after running its make build target.
"""

import gzip
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
    validator = spec.Validator(
        pubkey=pubkey, vrf_root=root(40), withdrawal_credentials=root(41),
        effective_balance=32_000_000_000, slashed=True,
        activation_eligibility_epoch=1, activation_epoch=2,
        exit_epoch=3, withdrawable_epoch=4,
    )
    validators = spec.Validators(data=[
        validator,
        spec.Validator(
            pubkey=spec.XMSSPubkey(byte_pattern(32, 42)), vrf_root=root(43),
            withdrawal_credentials=root(44), effective_balance=33_000_000_000,
            exit_epoch=spec.FAR_FUTURE_EPOCH, withdrawable_epoch=spec.FAR_FUTURE_EPOCH,
        ),
    ])
    builder = spec.Builder(
        pubkey=spec.XMSSPubkey(byte_pattern(32, 45)),
        version=1, execution_address=spec.ExecutionAddress(byte_pattern(20, 46)),
        balance=4_000_000_000, deposit_epoch=2, withdrawable_epoch=5,
    )
    builders = spec.Builders(data=[
        builder,
        spec.Builder(
            pubkey=spec.XMSSPubkey(byte_pattern(32, 47)),
            execution_address=spec.ExecutionAddress(byte_pattern(20, 48)),
            balance=5_000_000_000, withdrawable_epoch=spec.FAR_FUTURE_EPOCH,
        ),
    ])
    eth1_data = spec.Eth1Data(deposit_root=root(49), deposit_count=2, block_hash=root(50))
    builder_withdrawal = spec.BuilderPendingWithdrawal(
        fee_recipient=builder.execution_address, amount=123, builder_index=1,
    )

    def vector(name, first):
        annotation = spec.BeaconState.model_fields[name].annotation
        values = list(annotation().data)
        values[0] = first
        return annotation(data=values)

    state = spec.BeaconState(
        genesis_time=1_700_000_000,
        genesis_validators_root=validators.hash_tree_root(),
        slot=17,
        fork=spec.Fork(
            previous_version=spec.config.GLOAS_FORK_VERSION,
            current_version=spec.config.PQ_FORK_VERSION,
        ),
        latest_block_header=header.message,
        block_roots=vector("block_roots", root(51)),
        state_roots=vector("state_roots", root(52)),
        historical_roots=sequence(spec.BeaconState, "historical_roots", [root(53)]),
        eth1_data=eth1_data,
        eth1_data_votes=sequence(spec.BeaconState, "eth1_data_votes", [eth1_data]),
        eth1_deposit_index=2,
        validators=validators,
        balances=spec.Balances(data=[30_000_000_000, 34_000_000_000]),
        randao_mixes=vector("randao_mixes", spec.Bytes32(byte_pattern(32, 54))),
        slashings=vector("slashings", 32_000_000_000),
        previous_epoch_participation=spec.EpochParticipation(data=[1, 2]),
        current_epoch_participation=spec.EpochParticipation(data=[3, 4]),
        justification_bits=vector("justification_bits", True),
        previous_justified_checkpoint=spec.Checkpoint(epoch=1, root=root(55)),
        current_justified_checkpoint=spec.Checkpoint(epoch=2, root=root(56)),
        finalized_checkpoint=spec.Checkpoint(epoch=3, root=root(57)),
        inactivity_scores=spec.InactivityScores(data=[7, 11]),
        latest_block_hash=root(58),
        next_withdrawal_index=9,
        next_withdrawal_validator_index=1,
        historical_summaries=sequence(spec.BeaconState, "historical_summaries", [
            spec.HistoricalSummary(block_summary_root=root(59), state_summary_root=root(60)),
        ]),
        deposit_requests_start_index=10,
        deposit_balance_to_consume=11,
        exit_balance_to_consume=12,
        earliest_exit_epoch=13,
        consolidation_balance_to_consume=14,
        earliest_consolidation_epoch=15,
        pending_deposits=spec.PendingDeposits(data=[
            spec.PendingDeposit(
                pubkey=request.pubkey, withdrawal_credentials=request.withdrawal_credentials,
                amount=request.amount, signature=request.signature, slot=16,
            ),
        ]),
        pending_partial_withdrawals=spec.PendingPartialWithdrawals(data=[
            spec.PendingPartialWithdrawal(validator_index=1, amount=123, withdrawable_epoch=6),
        ]),
        pending_consolidations=spec.PendingConsolidations(data=[
            spec.PendingConsolidation(source_index=0, target_index=1),
        ]),
        proposer_lookahead=vector("proposer_lookahead", 1),
        builders=builders,
        next_withdrawal_builder_index=1,
        execution_payload_availability=vector("execution_payload_availability", True),
        builder_pending_payments=vector("builder_pending_payments", spec.BuilderPendingPayment(
            weight=456, withdrawal=builder_withdrawal, proposer_index=1,
        )),
        builder_pending_withdrawals=spec.BuilderPendingWithdrawals(data=[builder_withdrawal]),
        latest_execution_payload_bid=bid.message,
        payload_expected_withdrawals=spec.Withdrawals(data=[
            spec.Withdrawal(index=1, validator_index=1, address=builder.execution_address, amount=789),
        ]),
        ptc_window=vector("ptc_window", spec.PayloadTimelinessCommittee(
            data=[1] * len(spec.PayloadTimelinessCommittee().data),
        )),
        validator_preregistrations=spec.ValidatorPreregistrations(data=[validator_prereg]),
        builder_preregistrations=spec.BuilderPreregistrations(data=[builder_prereg]),
        aggregation_committee_window=window,
    )
    objects = [
        pubkey, signature, proof, vrf_proof, attestation, indexed_attestation,
        attester_slashing, aggregate, signed_aggregate, single, header, slashing,
        validator_request, builder_request, validator_prereg, builder_prereg, exit_request,
        request, requests, bid, envelope, signed_envelope, payload_attestation, preferences,
        body, block, signed_block, committee, committees, window, validator, builder, state,
    ]

    fixtures = {}
    preset = spec.__name__.rsplit(".", 1)[1]
    for populated in objects:
        name = type(populated).__name__
        fixtures[name] = []
        for case, value in zip(("default", "populated"), (type(populated)(), populated)):
            ssz = value.encode_bytes()
            fixture = {"root": "0x" + value.hash_tree_root().hex()}
            if isinstance(value, spec.BeaconState):
                output = Path(__file__).with_name(f"{preset}.state-{case}.ssz.gz")
                output.write_bytes(gzip.compress(ssz, mtime=0))
            else:
                fixture["ssz"] = ssz.hex()
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
