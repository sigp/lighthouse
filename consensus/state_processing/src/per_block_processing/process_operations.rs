use super::*;
use crate::common::{increase_balance, initiate_validator_exit, slash_validator};
use crate::per_block_processing::errors::{BlockProcessingError, IntoWithIndex};
use crate::VerifySignatures;
use safe_arith::SafeArith;

pub fn process_operations<'a, T: EthSpec>(
    state: &mut BeaconState<T>,
    block_body: BeaconBlockBodyRef<'a, T>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    process_proposer_slashings(
        state,
        block_body.proposer_slashings(),
        verify_signatures,
        spec,
    )?;
    process_attester_slashings(
        state,
        block_body.attester_slashings(),
        verify_signatures,
        spec,
    )?;
    match block_body {
        BeaconBlockBodyRef::Base(_) => {
            base::process_attestations(state, block_body.attestations(), verify_signatures, spec)?;
            base::process_deposits(state, block_body.deposits(), spec)?;
        }
        BeaconBlockBodyRef::Altair(_) => {
            altair::process_attestations(
                state,
                block_body.attestations(),
                verify_signatures,
                spec,
            )?;
            altair::process_deposits(state, block_body.deposits(), spec)?;
        }
    }
    process_exits(state, block_body.voluntary_exits(), verify_signatures, spec)?;
    Ok(())
}

pub mod base {
    use super::*;

    /// Validates each `Attestation` and updates the state, short-circuiting on an invalid object.
    ///
    /// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
    /// an `Err` describing the invalid object or cause of failure.
    pub fn process_attestations<T: EthSpec>(
        state: &mut BeaconState<T>,
        attestations: &[Attestation<T>],
        verify_signatures: VerifySignatures,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        // Ensure the previous epoch cache exists.
        state.build_committee_cache(RelativeEpoch::Previous, spec)?;

        let proposer_index = state.get_beacon_proposer_index(state.slot(), spec)? as u64;

        // Verify and apply each attestation.
        for (i, attestation) in attestations.iter().enumerate() {
            verify_attestation_for_block_inclusion(state, attestation, verify_signatures, spec)
                .map_err(|e| e.into_with_index(i))?;

            let pending_attestation = PendingAttestation {
                aggregation_bits: attestation.aggregation_bits.clone(),
                data: attestation.data.clone(),
                inclusion_delay: state.slot().safe_sub(attestation.data.slot)?.as_u64(),
                proposer_index,
            };

            if attestation.data.target.epoch == state.current_epoch() {
                state
                    .as_base_mut()?
                    .current_epoch_attestations
                    .push(pending_attestation)?;
            } else {
                state
                    .as_base_mut()?
                    .previous_epoch_attestations
                    .push(pending_attestation)?;
            }
        }

        Ok(())
    }

    /// Validates each `Deposit` and updates the state, short-circuiting on an invalid object.
    ///
    /// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
    /// an `Err` describing the invalid object or cause of failure.
    pub fn process_deposits<T: EthSpec>(
        state: &mut BeaconState<T>,
        deposits: &[Deposit],
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        let expected_deposit_len = std::cmp::min(
            T::MaxDeposits::to_u64(),
            state.get_outstanding_deposit_len()?,
        );
        block_verify!(
            deposits.len() as u64 == expected_deposit_len,
            BlockProcessingError::DepositCountInvalid {
                expected: expected_deposit_len as usize,
                found: deposits.len(),
            }
        );

        // Verify merkle proofs in parallel.
        deposits
            .par_iter()
            .enumerate()
            .try_for_each(|(i, deposit)| {
                verify_deposit_merkle_proof(
                    state,
                    deposit,
                    state.eth1_deposit_index().safe_add(i as u64)?,
                    spec,
                )
                .map_err(|e| e.into_with_index(i))
            })?;

        // Update the state in series.
        for deposit in deposits {
            process_deposit(state, deposit, spec, false)?;
        }

        Ok(())
    }

    /// Process a single deposit, optionally verifying its merkle proof.
    pub fn process_deposit<T: EthSpec>(
        state: &mut BeaconState<T>,
        deposit: &Deposit,
        spec: &ChainSpec,
        verify_merkle_proof: bool,
    ) -> Result<(), BlockProcessingError> {
        let deposit_index = state.eth1_deposit_index() as usize;
        if verify_merkle_proof {
            verify_deposit_merkle_proof(state, deposit, state.eth1_deposit_index(), spec)
                .map_err(|e| e.into_with_index(deposit_index))?;
        }

        state.eth1_deposit_index_mut().safe_add_assign(1)?;

        // Get an `Option<u64>` where `u64` is the validator index if this deposit public key
        // already exists in the beacon_state.
        let validator_index = get_existing_validator_index(state, &deposit.data.pubkey)
            .map_err(|e| e.into_with_index(deposit_index))?;

        let amount = deposit.data.amount;

        if let Some(index) = validator_index {
            // Update the existing validator balance.
            increase_balance(state, index as usize, amount)?;
        } else {
            // The signature should be checked for new validators. Return early for a bad
            // signature.
            if verify_deposit_signature(&deposit.data, spec).is_err() {
                return Ok(());
            }

            // Create a new validator.
            let validator = Validator {
                pubkey: deposit.data.pubkey,
                withdrawal_credentials: deposit.data.withdrawal_credentials,
                activation_eligibility_epoch: spec.far_future_epoch,
                activation_epoch: spec.far_future_epoch,
                exit_epoch: spec.far_future_epoch,
                withdrawable_epoch: spec.far_future_epoch,
                effective_balance: std::cmp::min(
                    amount.safe_sub(amount.safe_rem(spec.effective_balance_increment)?)?,
                    spec.max_effective_balance,
                ),
                slashed: false,
            };
            state.validators_mut().push(validator)?;
            state.balances_mut().push(deposit.data.amount)?;
        }

        Ok(())
    }
}

pub mod altair {
    use super::*;

    // FIXME(altair): implement, add a `process_attestation` function
    pub fn process_attestations<T: EthSpec>(
        _state: &mut BeaconState<T>,
        _attestations: &[Attestation<T>],
        _verify_signatures: VerifySignatures,
        _spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        unimplemented!("process_attestations")
    }

    // FIXME(altair): implement, add a `process_deposit` function
    pub fn process_deposits<T: EthSpec>(
        _state: &mut BeaconState<T>,
        _deposits: &[Deposit],
        _spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        unimplemented!("process_deposits")
    }
}

/// Validates each `ProposerSlashing` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
pub fn process_proposer_slashings<T: EthSpec>(
    state: &mut BeaconState<T>,
    proposer_slashings: &[ProposerSlashing],
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    // Verify and apply proposer slashings in series.
    // We have to verify in series because an invalid block may contain multiple slashings
    // for the same validator, and we need to correctly detect and reject that.
    proposer_slashings
        .iter()
        .enumerate()
        .try_for_each(|(i, proposer_slashing)| {
            verify_proposer_slashing(proposer_slashing, &state, verify_signatures, spec)
                .map_err(|e| e.into_with_index(i))?;

            slash_validator(
                state,
                proposer_slashing.signed_header_1.message.proposer_index as usize,
                None,
                spec,
            )?;

            Ok(())
        })
}

/// Validates each `AttesterSlashing` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
pub fn process_attester_slashings<T: EthSpec>(
    state: &mut BeaconState<T>,
    attester_slashings: &[AttesterSlashing<T>],
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    for (i, attester_slashing) in attester_slashings.iter().enumerate() {
        verify_attester_slashing(&state, &attester_slashing, verify_signatures, spec)
            .map_err(|e| e.into_with_index(i))?;

        let slashable_indices =
            get_slashable_indices(&state, &attester_slashing).map_err(|e| e.into_with_index(i))?;

        for i in slashable_indices {
            slash_validator(state, i as usize, None, spec)?;
        }
    }

    Ok(())
}

/// Validates each `Exit` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
pub fn process_exits<T: EthSpec>(
    state: &mut BeaconState<T>,
    voluntary_exits: &[SignedVoluntaryExit],
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    // Verify and apply each exit in series. We iterate in series because higher-index exits may
    // become invalid due to the application of lower-index ones.
    for (i, exit) in voluntary_exits.iter().enumerate() {
        verify_exit(&state, exit, verify_signatures, spec).map_err(|e| e.into_with_index(i))?;

        initiate_validator_exit(state, exit.message.validator_index as usize, spec)?;
    }
    Ok(())
}
