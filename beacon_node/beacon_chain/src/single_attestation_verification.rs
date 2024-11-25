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

pub struct SingleAttestationVerification(SingleAttestation);

impl SingleAttestationVerification {
    pub fn verify_early_checks<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<(), Error> {
        let attestation_epoch = self.0.data.slot.epoch(T::EthSpec::slots_per_epoch());

        // Check the attestation's epoch matches its target.
        if attestation_epoch != self.0.data.target.epoch {
            return Err(Error::InvalidTargetEpoch {
                slot: self.0.data.slot,
                epoch: self.0.data.target.epoch,
            });
        }

        // MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance).
        //
        // We do not queue future attestations for later processing.
        verify_attestation_propagation_slot_range::<T::SlotClock, T::EthSpec>(
            &chain.slot_clock,
            self.0.data.slot,
            &chain.spec,
        )?;

        // Sanity check to ensure the attestation index is set to zero post Electra.
        if self.0.data.index != 0 {
            return Err(Error::CommitteeIndexNonZero(self.0.data.index as usize));
        }

        // Attestations must be for a known block. If the block is unknown, we simply drop the
        // attestation and do not delay consideration for later.
        //
        // Enforce a maximum skip distance for unaggregated attestations.
        let head_block = verify_head_block_is_known(
            chain,
            self.0.data.beacon_block_root,
            self.0.data.slot,
            chain.config.import_max_skip_slots,
        )?;

        // Check the attestation target root is consistent with the head root.
        verify_attestation_target_root::<T::EthSpec>(
            &head_block,
            self.0.data.target.root,
            self.0.data.slot,
        )?;

        Ok(())
    }

    /// Run the checks that apply to the indexed attestation before the signature is checked.
    pub fn verify_middle_checks<T: BeaconChainTypes>(
        &self,
        subnet_id: Option<SubnetId>,
        chain: &BeaconChain<T>,
    ) -> Result<(u64, SubnetId), Error> {
        let attestation_epoch = self.0.data.slot.epoch(T::EthSpec::slots_per_epoch());

        let committees_per_slot = chain.with_committee_cache(
            self.0.data.target.root,
            attestation_epoch,
            |committee_cache, _| {
                let beacon_committee = committee_cache
                    .get_beacon_committee(self.0.data.slot, self.0.attester_index as u64)
                    .ok_or(Error::NoCommitteeForSlotAndIndex {
                        slot: self.0.data.slot,
                        index: self.0.committee_index,
                    })
                    .map_err(|_| BeaconChainError::AttestationCommitteeIndexNotSet)?;

                if !beacon_committee
                    .committee
                    .contains(&(self.0.committee_index as usize))
                {
                    // TODO(single-attestation) return a error
                    todo!()
                }
                Ok(committee_cache.committees_per_slot())
            },
        )?;

        let expected_subnet_id = SubnetId::compute_subnet_for_single_attestation::<T::EthSpec>(
            &self.0,
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
            .validator_has_been_observed(self.0.data.target.epoch, self.0.attester_index as usize)
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::PriorAttestationKnown {
                validator_index: self.0.attester_index as u64,
                epoch: self.0.data.target.epoch,
            });
        }

        Ok((self.0.attester_index as u64, expected_subnet_id))
    }

    /// Verify the attestation, producing extra information about whether it might be slashable.
    pub fn verify_slashable<'a, T: BeaconChainTypes>(
        &'a self,
        subnet_id: Option<SubnetId>,
        chain: &BeaconChain<T>,
    ) -> Result<(), SingleAttestationSlashInfo<'a, Error>> {
        if let Err(e) = self.verify_early_checks(chain) {
            return Err(SingleAttestationSlashInfo::SignatureNotChecked(&self.0, e));
        }

        if let Err(e) = self.verify_signature(chain) {
            return Err(SingleAttestationSlashInfo::SignatureInvalid(e));
        }

        // TODO(single-attestation) what to do with these?
        let (validator_index, expected_subnet_id) =
            match self.verify_middle_checks(subnet_id, chain) {
                Ok(t) => t,
                Err(e) => return Err(SingleAttestationSlashInfo::SignatureValid(&self.0, e)),
            };

        if let Err(e) = self.verify_late_checks(chain) {
            return Err(SingleAttestationSlashInfo::SignatureValid(&self.0, e));
        }

        Ok(())
    }

    pub fn verify_signature<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<(), Error> {
        let signature_setup_timer =
            metrics::start_timer(&metrics::ATTESTATION_PROCESSING_SIGNATURE_SETUP_TIMES);
        let pubkey_cache = chain.validator_pubkey_cache.read();
        let pubkey = pubkey_cache
            .get(self.0.attester_index)
            .map(Cow::Borrowed)
            .ok_or(Error::InvalidSignature)?;

        let fork = chain.spec.fork_at_epoch(self.0.data.target.epoch);

        let signature_set = single_attestation_signature_set_from_pubkeys(
            pubkey,
            &self.0,
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
    fn verify_late_checks<T: BeaconChainTypes>(&self, chain: &BeaconChain<T>) -> Result<(), Error> {
        // Now that the attestation has been fully verified, store that we have received a valid
        // attestation from this validator.
        //
        // It's important to double check that the attestation still hasn't been observed, since
        // there can be a race-condition if we receive two attestations at the same time and
        // process them in different threads.
        if chain
            .observed_gossip_attesters
            .write()
            .observe_validator(self.0.data.target.epoch, self.0.attester_index)
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::PriorAttestationKnown {
                validator_index: self.0.attester_index as u64,
                epoch: self.0.data.target.epoch,
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
