use std::borrow::Cow;

use crate::attestation_verification::verify_attestation_target_root;
use crate::attestation_verification::verify_head_block_is_known;
use crate::attestation_verification::Error;
use crate::metrics;
use crate::{
    attestation_verification::verify_attestation_propagation_slot_range, BeaconChain,
    BeaconChainError, BeaconChainTypes,
};
use eth2::types::attestation::SingleAttestation;
use state_processing::signature_sets::single_attestation_signature_set_from_pubkeys;
use types::{EthSpec, SubnetId};

pub struct SingleAttestationVerification {
    pub single_attestation: SingleAttestation,
    pub subnet_id: SubnetId,
}

impl SingleAttestationVerification {
    pub fn verify_early_checks<T: BeaconChainTypes>(
        single_attestation: &SingleAttestation,
        chain: &BeaconChain<T>,
    ) -> Result<(), Error> {
        let attestation_epoch = single_attestation
            .data
            .slot
            .epoch(T::EthSpec::slots_per_epoch());

        // Check the attestation's epoch matches its target.
        if attestation_epoch != single_attestation.data.target.epoch {
            return Err(Error::InvalidTargetEpoch {
                slot: single_attestation.data.slot,
                epoch: single_attestation.data.target.epoch,
            });
        }

        // MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance).
        //
        // We do not queue future attestations for later processing.
        verify_attestation_propagation_slot_range::<T::SlotClock, T::EthSpec>(
            &chain.slot_clock,
            single_attestation.data.slot,
            &chain.spec,
        )?;

        // Sanity check to ensure the attestation index is set to zero post Electra.
        if single_attestation.data.index != 0 {
            return Err(Error::CommitteeIndexNonZero(
                single_attestation.data.index as usize,
            ));
        }

        // Attestations must be for a known block. If the block is unknown, we simply drop the
        // attestation and do not delay consideration for later.
        //
        // Enforce a maximum skip distance for unaggregated attestations.
        let head_block = verify_head_block_is_known(
            chain,
            single_attestation.data.beacon_block_root,
            single_attestation.data.slot,
            chain.config.import_max_skip_slots,
        )?;

        // Check the attestation target root is consistent with the head root.
        verify_attestation_target_root::<T::EthSpec>(
            &head_block,
            single_attestation.data.target.root,
            single_attestation.data.slot,
        )?;

        Ok(())
    }

    /// Run the checks that apply to the indexed attestation before the signature is checked.
    pub fn verify_middle_checks<T: BeaconChainTypes>(
        single_attestation: &SingleAttestation,
        subnet_id: Option<SubnetId>,
        chain: &BeaconChain<T>,
    ) -> Result<(u64, SubnetId), Error> {
        let attestation_epoch = single_attestation
            .data
            .slot
            .epoch(T::EthSpec::slots_per_epoch());

        let committees_per_slot = chain.with_committee_cache(
            single_attestation.data.target.root,
            attestation_epoch,
            |committee_cache, _| {
                let beacon_committee = committee_cache
                    .get_beacon_committee(
                        single_attestation.data.slot,
                        single_attestation.attester_index as u64,
                    )
                    .ok_or(Error::NoCommitteeForSlotAndIndex {
                        slot: single_attestation.data.slot,
                        index: single_attestation.committee_index,
                    })
                    .map_err(|_| BeaconChainError::AttestationCommitteeIndexNotSet)?;

                if !beacon_committee
                    .committee
                    .contains(&(single_attestation.committee_index as usize))
                {
                    // TODO(single-attestation) return a error
                    todo!()
                }
                Ok(committee_cache.committees_per_slot())
            },
        )?;

        let expected_subnet_id = SubnetId::compute_subnet_for_single_attestation::<T::EthSpec>(
            single_attestation,
            committees_per_slot,
            &chain.spec,
        )
        .map_err(BeaconChainError::from)?;

        // If a subnet was specified, ensure that subnet is correct.
        if let Some(subnet_id) = subnet_id {
            if subnet_id != expected_subnet_id {
                return Err(Error::InvalidSubnetId {
                    received: subnet_id,
                    expected: expected_subnet_id,
                });
            }
        };

        /*
         * The attestation is the first valid attestation received for the participating validator
         * for the slot, attestation.data.slot.
         */
        if chain
            .observed_gossip_attesters
            .read()
            .validator_has_been_observed(
                single_attestation.data.target.epoch,
                single_attestation.attester_index,
            )
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::PriorAttestationKnown {
                validator_index: single_attestation.attester_index as u64,
                epoch: single_attestation.data.target.epoch,
            });
        }

        Ok((single_attestation.attester_index as u64, expected_subnet_id))
    }

    /// Verify the attestation, producing extra information about whether it might be slashable.
    pub fn verify_slashable<'a, T: BeaconChainTypes>(
        single_attestation: &'a SingleAttestation,
        subnet_id: Option<SubnetId>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, SingleAttestationSlashInfo<'a, Error>> {
        if let Err(e) = Self::verify_early_checks(single_attestation, chain) {
            return Err(SingleAttestationSlashInfo::SignatureNotChecked(
                single_attestation,
                e,
            ));
        }

        if let Err(e) = Self::verify_signature(single_attestation, chain) {
            return Err(SingleAttestationSlashInfo::SignatureInvalid(e));
        }

        // TODO(single-attestation) what to do with these?
        let (_validator_index, expected_subnet_id) =
            match Self::verify_middle_checks(single_attestation, subnet_id, chain) {
                Ok(t) => t,
                Err(e) => {
                    return Err(SingleAttestationSlashInfo::SignatureValid(
                        single_attestation,
                        e,
                    ))
                }
            };

        if let Err(e) = Self::verify_late_checks(single_attestation, chain) {
            return Err(SingleAttestationSlashInfo::SignatureValid(
                single_attestation,
                e,
            ));
        }

        Ok(SingleAttestationVerification {
            single_attestation: single_attestation.clone(),
            subnet_id: expected_subnet_id,
        })
    }

    pub fn verify<T: BeaconChainTypes>(
        single_attestation: &SingleAttestation,
        subnet_id: Option<SubnetId>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, Error> {
        Self::verify_slashable(single_attestation, subnet_id, chain)
            .inspect(|_verified_unaggregated| {
                if let Some(_slasher) = chain.slasher.as_ref() {
                    // TODO(single-attestation) add to the slasher queue
                    // slasher.accept_attestation(verified_unaggregated.indexed_attestation.clone());
                }
            })
            .map_err(|slash_info| process_slash_info(slash_info, chain))
    }

    pub fn verify_signature<T: BeaconChainTypes>(
        single_attestation: &SingleAttestation,
        chain: &BeaconChain<T>,
    ) -> Result<(), Error> {
        let signature_setup_timer =
            metrics::start_timer(&metrics::ATTESTATION_PROCESSING_SIGNATURE_SETUP_TIMES);
        let pubkey_cache = chain.validator_pubkey_cache.read();
        let pubkey = pubkey_cache
            .get(single_attestation.attester_index)
            .map(Cow::Borrowed)
            .ok_or(Error::InvalidSignature)?;

        let fork = chain
            .spec
            .fork_at_epoch(single_attestation.data.target.epoch);

        let signature_set = single_attestation_signature_set_from_pubkeys(
            pubkey,
            single_attestation,
            &fork,
            chain.genesis_validators_root,
            &chain.spec,
        )
        .map_err(BeaconChainError::SignatureSetError)?;

        metrics::stop_timer(signature_setup_timer);
        let _signature_verification_timer =
            metrics::start_timer(&metrics::ATTESTATION_PROCESSING_SIGNATURE_TIMES);

        if signature_set.verify() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Run the checks that apply after the signature has been checked.
    fn verify_late_checks<T: BeaconChainTypes>(
        single_attestation: &SingleAttestation,
        chain: &BeaconChain<T>,
    ) -> Result<(), Error> {
        // Now that the attestation has been fully verified, store that we have received a valid
        // attestation from this validator.
        //
        // It's important to double check that the attestation still hasn't been observed, since
        // there can be a race-condition if we receive two attestations at the same time and
        // process them in different threads.
        if chain
            .observed_gossip_attesters
            .write()
            .observe_validator(
                single_attestation.data.target.epoch,
                single_attestation.attester_index,
            )
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::PriorAttestationKnown {
                validator_index: single_attestation.attester_index as u64,
                epoch: single_attestation.data.target.epoch,
            });
        }
        Ok(())
    }
}

/// Information about invalid attestations which might still be slashable despite being invalid.
pub enum SingleAttestationSlashInfo<'a, TErr> {
    /// The attestation is invalid, but its signature wasn't checked.
    SignatureNotChecked(&'a SingleAttestation, TErr),
    /// The attestation's signature is invalid, so it will never be slashable.
    SignatureInvalid(TErr),
    /// The signature is valid but the attestation is invalid in some other way.
    SignatureValid(&'a SingleAttestation, TErr),
}

/// After processing an attestation normally, optionally process it further for the slasher.
///
/// This maps an `AttestationSlashInfo` error back into a regular `Error`, performing signature
/// checks on attestations that failed verification for other reasons.
///
/// No substantial extra work will be done if there is no slasher configured.
fn process_slash_info<T: BeaconChainTypes>(
    _slash_info: SingleAttestationSlashInfo<Error>,
    _chain: &BeaconChain<T>,
) -> Error {
    todo!()
    // use AttestationSlashInfo::*;

    // if let Some(slasher) = chain.slasher.as_ref() {
    //     let (indexed_attestation, check_signature, err) = match slash_info {
    //         SignatureNotChecked(attestation, err) => {
    //             if let Error::UnknownHeadBlock { .. } = err {
    //                 if attestation.data().beacon_block_root == attestation.data().target.root {
    //                     return err;
    //                 }
    //             }
    //             match obtain_indexed_attestation_and_committees_per_slot(chain, attestation) {
    //                 Ok((indexed, _)) => (indexed, true, err),
    //                 Err(e) => {
    //                     debug!(
    //                         chain.log,
    //                         "Unable to obtain indexed form of attestation for slasher";
    //                         "attestation_root" => format!("{:?}", attestation.tree_hash_root()),
    //                         "error" => format!("{:?}", e)
    //                     );
    //                     return err;
    //                 }
    //             }
    //         }
    //         SignatureNotCheckedIndexed(indexed, err) => (indexed, true, err),
    //         SignatureInvalid(e) => return e,
    //         SignatureValid(indexed, err) => (indexed, false, err),
    //     };

    //     if check_signature {
    //         if let Err(e) = verify_attestation_signature(chain, &indexed_attestation) {
    //             debug!(
    //                 chain.log,
    //                 "Signature verification for slasher failed";
    //                 "error" => format!("{:?}", e),
    //             );
    //             return err;
    //         }
    //     }

    //     // Supply to slasher.
    //     slasher.accept_attestation(indexed_attestation);

    //     err
    // } else {
    //     match slash_info {
    //         SignatureNotChecked(_, e)
    //         | SignatureNotCheckedIndexed(_, e)
    //         | SignatureInvalid(e)
    //         | SignatureValid(_, e) => e,
    //     }
    // }
}
