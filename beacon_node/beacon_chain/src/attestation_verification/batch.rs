//! These two `batch_...` functions provide verification of batches of attestations. They provide
//! significant CPU-time savings by performing batch verification of BLS signatures.
//!
//! In each function, attestations are "indexed" (i.e., the `IndexedAttestation` is computed), to
//! determine if they should progress to signature verification. Then, all attestations which were
//! successfully indexed have their signatures verified in a batch. If that signature batch fails
//! then all attestation signatures are verified independently.
//!
//! The outcome of each function is a `Vec<Result>` with a one-to-one mapping to the `aggregates`
//! input. Each result provides the exact success or failure result of the corresponding
//! attestation.
use super::{
    CheckAttestationSignature, Error, IndexedAggregatedAttestation, IndexedUnaggregatedAttestation,
    VerifiedAggregatedAttestation, VerifiedUnaggregatedAttestation,
};
use crate::{
    beacon_chain::{HEAD_LOCK_TIMEOUT, VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT},
    metrics, BeaconChain, BeaconChainError, BeaconChainTypes,
};
use bls::verify_signature_sets;
use state_processing::signature_sets::{
    indexed_attestation_signature_set_from_pubkeys, signed_aggregate_selection_proof_signature_set,
    signed_aggregate_signature_set,
};
use std::borrow::Cow;
use types::*;

pub fn batch_verify_aggregated_attestations<'a, T: BeaconChainTypes>(
    aggregates: impl Iterator<Item = &'a SignedAggregateAndProof<T::EthSpec>>,
    chain: &BeaconChain<T>,
) -> Result<Vec<Result<VerifiedAggregatedAttestation<'a, T>, Error>>, Error> {
    let mut num_indexed = 0;
    let mut num_failed = 0;

    // Perform indexing of all attestations, collecting the results.
    let indexing_results = aggregates
        .map(|aggregate| {
            let result = IndexedAggregatedAttestation::verify(aggregate, chain);
            if result.is_ok() {
                num_indexed += 1;
            } else {
                num_failed += 1;
            }
            result
        })
        .collect::<Vec<_>>();

    // May be set to `No` if batch verification succeeds.
    let mut check_signatures = CheckAttestationSignature::Yes;

    // Perform batch BLS verification, if any attestation signatures are worth checking.
    if num_indexed > 0 {
        let signature_setup_timer =
            metrics::start_timer(&metrics::ATTESTATION_PROCESSING_SIGNATURE_SETUP_TIMES);

        let pubkey_cache = chain
            .validator_pubkey_cache
            .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
            .ok_or(BeaconChainError::ValidatorPubkeyCacheLockTimeout)?;

        let fork = chain
            .canonical_head
            .try_read_for(HEAD_LOCK_TIMEOUT)
            .ok_or(BeaconChainError::CanonicalHeadLockTimeout)
            .map(|head| head.beacon_state.fork())?;

        let mut signature_sets = Vec::with_capacity(num_indexed * 3);

        // Iterate, flattening to get only the `Ok` values.
        for indexed in indexing_results.iter().flatten() {
            let signed_aggregate = &indexed.signed_aggregate;
            let indexed_attestation = &indexed.indexed_attestation;

            signature_sets.push(
                signed_aggregate_selection_proof_signature_set(
                    |validator_index| pubkey_cache.get(validator_index).map(Cow::Borrowed),
                    signed_aggregate,
                    &fork,
                    chain.genesis_validators_root,
                    &chain.spec,
                )
                .map_err(BeaconChainError::SignatureSetError)?,
            );
            signature_sets.push(
                signed_aggregate_signature_set(
                    |validator_index| pubkey_cache.get(validator_index).map(Cow::Borrowed),
                    signed_aggregate,
                    &fork,
                    chain.genesis_validators_root,
                    &chain.spec,
                )
                .map_err(BeaconChainError::SignatureSetError)?,
            );
            signature_sets.push(
                indexed_attestation_signature_set_from_pubkeys(
                    |validator_index| pubkey_cache.get(validator_index).map(Cow::Borrowed),
                    &indexed_attestation.signature,
                    indexed_attestation,
                    &fork,
                    chain.genesis_validators_root,
                    &chain.spec,
                )
                .map_err(BeaconChainError::SignatureSetError)?,
            );
        }

        metrics::stop_timer(signature_setup_timer);

        let _signature_verification_timer =
            metrics::start_timer(&metrics::ATTESTATION_PROCESSING_SIGNATURE_TIMES);

        if verify_signature_sets(signature_sets.iter()) {
            // Since all the signatures verified in a batch, there's no reason for them to be
            // checked again later.
            check_signatures = CheckAttestationSignature::No
        }
    }

    // Complete the attestation verification, potentially verifying all signatures independently.
    let final_results = indexing_results
        .into_iter()
        .map(|result| match result {
            Ok(indexed) => {
                VerifiedAggregatedAttestation::from_indexed(indexed, chain, check_signatures)
            }
            Err(e) => Err(e),
        })
        .collect();

    Ok(final_results)
}

pub fn batch_verify_unaggregated_attestations<'a, T: BeaconChainTypes>(
    attestations: impl Iterator<Item = (&'a Attestation<T::EthSpec>, Option<SubnetId>)>,
    chain: &BeaconChain<T>,
) -> Result<Vec<Result<VerifiedUnaggregatedAttestation<'a, T>, Error>>, Error> {
    let mut num_partially_verified = 0;
    let mut num_failed = 0;

    // Perform partial verification of all attestations, collecting the results.
    let partial_results = attestations
        .map(|(attn, subnet_opt)| {
            let result = IndexedUnaggregatedAttestation::verify(attn, subnet_opt, chain);
            if result.is_ok() {
                num_partially_verified += 1;
            } else {
                num_failed += 1;
            }
            result
        })
        .collect::<Vec<_>>();

    // May be set to `No` if batch verification succeeds.
    let mut check_signatures = CheckAttestationSignature::Yes;

    // Perform batch BLS verification, if any attestation signatures are worth checking.
    if num_partially_verified > 0 {
        let signature_setup_timer =
            metrics::start_timer(&metrics::ATTESTATION_PROCESSING_SIGNATURE_SETUP_TIMES);

        let pubkey_cache = chain
            .validator_pubkey_cache
            .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
            .ok_or(BeaconChainError::ValidatorPubkeyCacheLockTimeout)?;

        let fork = chain
            .canonical_head
            .try_read_for(HEAD_LOCK_TIMEOUT)
            .ok_or(BeaconChainError::CanonicalHeadLockTimeout)
            .map(|head| head.beacon_state.fork())?;

        let mut signature_sets = Vec::with_capacity(num_partially_verified * 3);

        // Iterate, flattening to get only the `Ok` values.
        for partially_verified in partial_results.iter().flatten() {
            let indexed_attestation = &partially_verified.indexed_attestation;

            let signature_set = indexed_attestation_signature_set_from_pubkeys(
                |validator_index| pubkey_cache.get(validator_index).map(Cow::Borrowed),
                &indexed_attestation.signature,
                indexed_attestation,
                &fork,
                chain.genesis_validators_root,
                &chain.spec,
            )
            .map_err(BeaconChainError::SignatureSetError)?;

            signature_sets.push(signature_set);
        }

        metrics::stop_timer(signature_setup_timer);

        let _signature_verification_timer =
            metrics::start_timer(&metrics::ATTESTATION_PROCESSING_SIGNATURE_TIMES);

        if verify_signature_sets(signature_sets.iter()) {
            // Since all the signatures verified in a batch, there's no reason for them to be
            // checked again later.
            check_signatures = CheckAttestationSignature::No
        }
    }

    // Complete the attestation verification, potentially verifying all signatures independently.
    let final_results = partial_results
        .into_iter()
        .map(|result| match result {
            Ok(partial) => {
                VerifiedUnaggregatedAttestation::from_indexed(partial, chain, check_signatures)
            }
            Err(e) => Err(e),
        })
        .collect();

    Ok(final_results)
}
