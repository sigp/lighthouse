use ssz::{Decode, Encode};
use ssz_types::{ProgressiveVariableList, typenum::Unsigned};
use types::{test_utils::test_arbitrary_instance, *};

fn round_trip<T: Encode + Decode>(value: &T) -> Result<T, ssz::DecodeError> {
    T::from_ssz_bytes(&value.as_ssz_bytes())
}

fn check_limits<E: EthSpec>() {
    // Exercise the enclosing wire containers, including nested variable-length lists.
    macro_rules! check {
        ($container:expr, $($field:ident).+, $limit:ty) => {{
            let mut value = $container.clone();
            let item = test_arbitrary_instance();
            value.$($field).+ = ProgressiveVariableList::new(vec![item; <$limit>::to_usize()]);
            assert!(round_trip(&value).is_ok(), stringify!($($field).+));
            value.$($field).+.push(test_arbitrary_instance());
            assert!(round_trip(&value).is_err(), stringify!($($field).+));
        }};
    }

    let spec = ForkName::Gloas.make_genesis_spec(E::default_spec());
    let block = BeaconBlockGloas::<E>::empty(&spec);
    check!(block, body.proposer_slashings, E::MaxProposerSlashings);
    check!(
        block,
        body.attester_slashings,
        E::MaxAttesterSlashingsElectra
    );
    check!(block, body.attestations, E::MaxAttestationsElectra);
    check!(block, body.deposits, E::MaxDeposits);
    check!(block, body.voluntary_exits, E::MaxVoluntaryExits);
    check!(
        block,
        body.bls_to_execution_changes,
        E::MaxBlsToExecutionChanges
    );
    check!(block, body.payload_attestations, E::MaxPayloadAttestations);
    check!(
        block,
        body.signed_execution_payload_bid
            .message
            .blob_kzg_commitments,
        E::MaxBlobCommitmentsPerBlock
    );

    let envelope = ExecutionPayloadEnvelope::<E>::empty();
    check!(envelope, payload.withdrawals, E::MaxWithdrawalsPerPayload);
    check!(
        envelope,
        execution_requests.withdrawals,
        E::MaxWithdrawalRequestsPerPayload
    );
    check!(
        envelope,
        execution_requests.consolidations,
        E::MaxConsolidationRequestsPerPayload
    );
    check!(
        envelope,
        execution_requests.builder_deposits,
        E::MaxBuilderDepositRequestsPerPayload
    );
    check!(
        envelope,
        execution_requests.builder_exits,
        E::MaxBuilderExitRequestsPerPayload
    );

    // Gloas deliberately removed the Electra deposit-request limit.
    let mut envelope = envelope;
    envelope.execution_requests.deposits = ProgressiveVariableList::new(vec![
        test_arbitrary_instance(); E::max_deposit_requests_per_payload() + 1
    ]);
    assert!(round_trip(&envelope).is_ok());

    let attestation: IndexedAttestationGloas<E> = test_arbitrary_instance();
    check!(attestation, attesting_indices, E::MaxValidatorsPerSlot);
    let column: DataColumnSidecarGloas<E> = test_arbitrary_instance();
    check!(column, column, E::MaxBlobCommitmentsPerBlock);
    check!(column, kzg_proofs, E::MaxBlobCommitmentsPerBlock);
    let partial_column: PartialDataColumnSidecarGloas<E> = test_arbitrary_instance();
    check!(partial_column, column, E::MaxBlobCommitmentsPerBlock);
    check!(partial_column, kzg_proofs, E::MaxBlobCommitmentsPerBlock);
}

#[test]
fn progressive_list_limits() {
    check_limits::<MainnetEthSpec>();
    check_limits::<MinimalEthSpec>();
    check_limits::<GnosisEthSpec>();
}
