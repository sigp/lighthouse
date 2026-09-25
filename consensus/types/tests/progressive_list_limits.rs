use ssz::{Decode, Encode};
use ssz_types::{ProgressiveVariableList, typenum::Unsigned};
use types::{test_utils::test_arbitrary_instance, *};

fn round_trip<T: Encode + Decode>(value: &T) -> Result<T, ssz::DecodeError> {
    T::from_ssz_bytes(&value.as_ssz_bytes())
}

fn check_over_limit<T: Clone + Encode + Decode + 'static, N: Unsigned>(
    list: &ProgressiveVariableList<T, N>,
    item: T,
) {
    let mut values = list.clone().into_vec();
    values.push(item);
    // Encode the oversized list as a Vec: the bounded list cannot be constructed anymore.
    assert!(ProgressiveVariableList::<T, N>::from_ssz_bytes(&values.as_ssz_bytes()).is_err());
    assert!(ProgressiveVariableList::<T, N>::new(values).is_err());
}

fn check_limits<E: EthSpec>() {
    // Exercise the enclosing wire containers, including nested variable-length lists.
    macro_rules! check {
        ($container:expr, $($field:ident).+, $limit:ty) => {{
            let mut value = $container.clone();
            let item = test_arbitrary_instance();
            value.$($field).+ = ProgressiveVariableList::new(vec![item; <$limit>::to_usize()]).unwrap();
            assert!(round_trip(&value).is_ok(), stringify!($($field).+));
            check_over_limit(&value.$($field).+, test_arbitrary_instance());
            assert!(value.$($field).+.push(test_arbitrary_instance()).is_err());
            assert_eq!(value.$($field).+.len(), <$limit>::to_usize());
            assert!(round_trip(&value).is_ok(), stringify!($($field).+));
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
    ])
    .unwrap();
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

#[test]
fn progressive_block_body_errors_propagate() {
    type E = MinimalEthSpec;
    for fork in [ForkName::Gloas, ForkName::Heze] {
        let spec = fork.make_genesis_spec(E::default_spec());
        let mut block = BeaconBlock::<E>::empty(&spec);
        let mut body = block.body_mut();
        body.set_deposits_from_iter(vec![
            test_arbitrary_instance();
            <E as EthSpec>::MaxDeposits::to_usize()
        ])
        .unwrap();
        assert!(matches!(
            body.deposits_push(test_arbitrary_instance()),
            Err(BeaconStateError::SszTypesError(_))
        ));
        assert!(matches!(
            body.set_deposits_from_iter(vec![
                test_arbitrary_instance();
                <E as EthSpec>::MaxDeposits::to_usize() + 1
            ]),
            Err(BeaconStateError::SszTypesError(_))
        ));

        for _ in 0..<E as EthSpec>::MaxProposerSlashings::to_usize() {
            body.proposer_slashings_push(test_arbitrary_instance())
                .unwrap();
        }
        assert!(matches!(
            body.proposer_slashings_push(test_arbitrary_instance()),
            Err(BeaconStateError::SszTypesError(_))
        ));

        for _ in 0..<E as EthSpec>::MaxVoluntaryExits::to_usize() {
            body.voluntary_exits_push(test_arbitrary_instance())
                .unwrap();
        }
        assert!(matches!(
            body.voluntary_exits_push(test_arbitrary_instance()),
            Err(BeaconStateError::SszTypesError(_))
        ));
        assert_eq!(
            block.body().deposits().len(),
            <E as EthSpec>::MaxDeposits::to_usize()
        );
    }
}

#[test]
fn progressive_column_min_size_matches_encoding() {
    type E = MainnetEthSpec;
    let sidecar = DataColumnSidecarGloas::<E> {
        index: 0,
        column: ProgressiveVariableList::new(vec![Cell::<E>::default()]).unwrap(),
        kzg_proofs: ProgressiveVariableList::new(vec![KzgProof::empty()]).unwrap(),
        slot: Slot::new(0),
        beacon_block_root: Hash256::ZERO,
    };
    assert_eq!(
        DataColumnSidecarGloas::<E>::min_size(),
        sidecar.as_ssz_bytes().len()
    );
}
