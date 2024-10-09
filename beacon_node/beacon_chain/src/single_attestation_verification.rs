use crate::{
    attestation_verification::{
        process_slash_info, verify_attestation_signature, verify_propagation_slot_range,
        AttestationSlashInfo, CheckAttestationSignature, Error,
    },
    BeaconChain, BeaconChainError, BeaconChainTypes,
};
use proto_array::Block as ProtoBlock;
use types::{
    BeaconCommittee, EthSpec, IndexedAttestation, IndexedAttestationElectra, SingleAttestation,
    SubnetId, VariableList,
};

/// A helper trait implemented on wrapper types that can be progressed to a state where they can be
/// verified for application to fork choice.
pub trait ToVerifiedSingleAttestation<T: BeaconChainTypes>: Sized {
    fn attestation(&self) -> &SingleAttestation;

    fn indexed_attestation(&self) -> &IndexedAttestation<T::EthSpec>;

    // Inefficient default implementation. This is overridden for gossip verified attestations.
    fn into_attestation_and_indices(self) -> (SingleAttestation, Vec<u64>) {
        let attestation = self.attestation().clone();
        let attesting_indices = vec![self.attestation().attester_index as u64];
        (attestation, attesting_indices)
    }
}

/// Wraps an `Attestation` that has been fully verified for propagation on the gossip network.
pub struct VerifiedSingleAttestation<'a, T: BeaconChainTypes> {
    attestation: &'a SingleAttestation,
    indexed_attestation: IndexedAttestation<T::EthSpec>,
    subnet_id: SubnetId,
}

/// Wraps a `SingleAttestation` that has been verified up until the point that an `IndexedAttestation` can
/// be derived.
///
/// These attestations have *not* undergone signature verification.
pub struct IndexedSingleAttestation<'a, T: BeaconChainTypes> {
    attestation: &'a SingleAttestation,
    pub indexed_attestation: IndexedAttestation<T::EthSpec>,
    subnet_id: SubnetId,
    validator_index: u64,
}

impl<'a, T: BeaconChainTypes> VerifiedSingleAttestation<'a, T> {
    pub fn into_indexed_attestation(self) -> IndexedAttestation<T::EthSpec> {
        self.indexed_attestation
    }
}

impl<'a, T: BeaconChainTypes> VerifiedSingleAttestation<'a, T> {
    /// Run the checks that apply after the signature has been checked.
    fn verify_late_checks(
        attestation: &SingleAttestation,
        validator_index: u64,
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
            .observe_validator(attestation.data.target.epoch, validator_index as usize)
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::PriorAttestationKnown {
                validator_index,
                epoch: attestation.data.target.epoch,
            });
        }
        Ok(())
    }

    /// Verify the `single_attestation`.
    pub fn verify(
        single_attestation: &'a SingleAttestation,
        subnet_id: Option<SubnetId>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, Error> {
        let indexed = IndexedSingleAttestation::verify(single_attestation, subnet_id, chain)?;
        Self::from_indexed(indexed, chain, CheckAttestationSignature::Yes)
    }

    /// Complete the verification of an indexed attestation.
    pub fn from_indexed(
        attestation: IndexedSingleAttestation<'a, T>,
        chain: &BeaconChain<T>,
        check_signature: CheckAttestationSignature,
    ) -> Result<Self, Error> {
        Self::verify_slashable(attestation, chain, check_signature)
            .map(|verified_unaggregated| verified_unaggregated.apply_to_slasher(chain))
            .map_err(|slash_info| process_slash_info(*slash_info, chain))
    }

    fn apply_to_slasher(self, chain: &BeaconChain<T>) -> Self {
        if let Some(slasher) = chain.slasher.as_ref() {
            slasher.accept_attestation(self.indexed_attestation.clone());
        }
        self
    }

    /// Verify the attestation, producing extra information about whether it might be slashable.
    fn verify_slashable(
        attestation: IndexedSingleAttestation<'a, T>,
        chain: &BeaconChain<T>,
        check_signature: CheckAttestationSignature,
    ) -> Result<Self, Box<AttestationSlashInfo<'a, T, Error>>> {
        use AttestationSlashInfo::*;

        let IndexedSingleAttestation {
            attestation,
            indexed_attestation,
            subnet_id,
            validator_index,
        } = attestation;

        match check_signature {
            CheckAttestationSignature::Yes => {
                if let Err(e) = verify_attestation_signature(chain, &indexed_attestation) {
                    return Err(Box::new(SignatureInvalid(e)));
                }
            }
            CheckAttestationSignature::No => (),
        };

        if let Err(e) = Self::verify_late_checks(attestation, validator_index, chain) {
            return Err(Box::new(SignatureValid(indexed_attestation, e)));
        }

        Ok(Self {
            attestation,
            indexed_attestation,
            subnet_id,
        })
    }

    /// Returns the correct subnet for the attestation.
    pub fn subnet_id(&self) -> SubnetId {
        self.subnet_id
    }

    /// Returns the wrapped `attestation`.
    pub fn attestation(&self) -> &'a SingleAttestation {
        self.attestation
    }

    /// Returns the wrapped `indexed_attestation`.
    pub fn indexed_attestation(&self) -> &IndexedAttestation<T::EthSpec> {
        &self.indexed_attestation
    }

    /// Returns a mutable reference to the underlying attestation.
    ///
    /// Only use during testing since modifying the `IndexedAttestation` can cause the attestation
    /// to no-longer be valid.
    pub fn __indexed_attestation_mut(&mut self) -> &mut IndexedAttestation<T::EthSpec> {
        &mut self.indexed_attestation
    }
}

impl<'a, T: BeaconChainTypes> IndexedSingleAttestation<'a, T> {
    /// Run the checks that happen before an indexed attestation is constructed.
    pub fn verify_early_checks(
        attestation: &'a SingleAttestation,
        chain: &BeaconChain<T>,
    ) -> Result<(), Error> {
        let attestation_epoch = attestation.data.slot.epoch(T::EthSpec::slots_per_epoch());

        // Check the attestation's epoch matches its target.
        if attestation_epoch != attestation.data.target.epoch {
            return Err(Error::InvalidTargetEpoch {
                slot: attestation.data.slot,
                epoch: attestation.data.target.epoch,
            });
        }

        // Ensure attestation is within the last ATTESTATION_PROPAGATION_SLOT_RANGE slots (within a
        // MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance).
        //
        // We do not queue future attestations for later processing.
        verify_propagation_slot_range::<T::SlotClock, T::EthSpec>(
            &chain.slot_clock,
            &attestation.data,
            &chain.spec,
        )?;

        // Ensure the attestation index is set to zero post Electra.
        if attestation.data.index != 0 {
            return Err(Error::CommitteeIndexNonZero(
                attestation.data.index as usize,
            ));
        }

        // Attestations must be for a known block. If the block is unknown, we simply drop the
        // attestation and do not delay consideration for later.
        //
        // Enforce a maximum skip distance for unaggregated attestations.
        let head_block =
            verify_head_block_is_known(chain, attestation, chain.config.import_max_skip_slots)?;

        // Check the attestation target root is consistent with the head root.
        verify_attestation_target_root::<T::EthSpec>(&head_block, attestation)?;

        Ok(())
    }

    /// Run the checks that apply to the indexed attestation before the signature is checked.
    pub fn verify_middle_checks(
        attestation: &'a SingleAttestation,
        indexed_attestation: &IndexedAttestation<T::EthSpec>,
        committees_per_slot: u64,
        subnet_id: Option<SubnetId>,
        chain: &BeaconChain<T>,
    ) -> Result<(u64, SubnetId), Error> {
        let expected_subnet_id = SubnetId::compute_subnet_for_single_attestation::<T::EthSpec>(
            attestation,
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

        let validator_index = *indexed_attestation
            .attesting_indices_first()
            .ok_or(Error::NotExactlyOneAggregationBitSet(0))?;

        /*
         * The attestation is the first valid attestation received for the participating validator
         * for the slot, attestation.data.slot.
         */
        if chain
            .observed_gossip_attesters
            .read()
            .validator_has_been_observed(attestation.data.target.epoch, validator_index as usize)
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::PriorAttestationKnown {
                validator_index,
                epoch: attestation.data.target.epoch,
            });
        }

        Ok((validator_index, expected_subnet_id))
    }

    /// Returns `Ok(Self)` if the `attestation` is valid to be (re)published on the gossip
    /// network.
    ///
    /// `subnet_id` is the subnet from which we received this attestation. This function will
    /// verify that it was received on the correct subnet.
    pub fn verify(
        attestation: &'a SingleAttestation,
        subnet_id: Option<SubnetId>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, Error> {
        Self::verify_slashable(attestation, subnet_id, chain)
            .inspect(|verified_unaggregated| {
                if let Some(slasher) = chain.slasher.as_ref() {
                    slasher.accept_attestation(verified_unaggregated.indexed_attestation.clone());
                }
            })
            .map_err(|slash_info| process_slash_info(*slash_info, chain))
    }

    /// Verify the attestation, producing extra information about whether it might be slashable.
    pub fn verify_slashable(
        attestation: &'a SingleAttestation,
        subnet_id: Option<SubnetId>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, Box<AttestationSlashInfo<'a, T, Error>>> {
        use AttestationSlashInfo::*;

        if let Err(e) = Self::verify_early_checks(attestation, chain) {
            return Err(Box::new(SignatureNotCheckedSingleAttestation(
                attestation,
                e,
            )));
        }

        let (indexed_attestation, committees_per_slot) =
            match obtain_indexed_attestation_and_committees_per_slot(chain, attestation) {
                Ok(x) => x,
                Err(e) => {
                    return Err(Box::new(SignatureNotCheckedSingleAttestation(
                        attestation,
                        e,
                    )));
                }
            };

        let (validator_index, expected_subnet_id) = match Self::verify_middle_checks(
            attestation,
            &indexed_attestation,
            committees_per_slot,
            subnet_id,
            chain,
        ) {
            Ok(t) => t,
            Err(e) => return Err(Box::new(SignatureNotCheckedIndexed(indexed_attestation, e))),
        };

        Ok(Self {
            attestation,
            indexed_attestation,
            subnet_id: expected_subnet_id,
            validator_index,
        })
    }

    /// Returns a mutable reference to the underlying attestation.
    ///
    /// Only use during testing since modifying the `IndexedAttestation` can cause the attestation
    /// to no-longer be valid.
    pub fn __indexed_attestation_mut(&mut self) -> &mut IndexedAttestation<T::EthSpec> {
        &mut self.indexed_attestation
    }
}

/// Returns `Ok(())` if the `attestation.data.beacon_block_root` is known to this chain.
///
/// The block root may not be known for two reasons:
///
/// 1. The block has never been verified by our application.
/// 2. The block is prior to the latest finalized block.
///
/// Case (1) is the exact thing we're trying to detect. However case (2) is a little different, but
/// it's still fine to reject here because there's no need for us to handle attestations that are
/// already finalized.
fn verify_head_block_is_known<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    attestation: &SingleAttestation,
    max_skip_slots: Option<u64>,
) -> Result<ProtoBlock, Error> {
    let block_opt = chain
        .canonical_head
        .fork_choice_read_lock()
        .get_block(&attestation.data.beacon_block_root)
        .or_else(|| {
            chain
                .early_attester_cache
                .get_proto_block(attestation.data.beacon_block_root)
        });

    if let Some(block) = block_opt {
        // Reject any block that exceeds our limit on skipped slots.
        if let Some(max_skip_slots) = max_skip_slots {
            if attestation.data.slot > block.slot + max_skip_slots {
                return Err(Error::TooManySkippedSlots {
                    head_block_slot: block.slot,
                    attestation_slot: attestation.data.slot,
                });
            }
        }

        Ok(block)
    } else if chain.is_pre_finalization_block(attestation.data.beacon_block_root)? {
        Err(Error::HeadBlockFinalized {
            beacon_block_root: attestation.data.beacon_block_root,
        })
    } else {
        // The block is either:
        //
        // 1) A pre-finalization block that has been pruned. We'll do one network lookup
        //    for it and when it fails we will penalise all involved peers.
        // 2) A post-finalization block that we don't know about yet. We'll queue
        //    the attestation until the block becomes available (or we time out).
        Err(Error::UnknownHeadBlock {
            beacon_block_root: attestation.data.beacon_block_root,
        })
    }
}

/// Verifies that the `attestation.data.target.root` is indeed the target root of the block at
/// `attestation.data.beacon_block_root`.
pub fn verify_attestation_target_root<E: EthSpec>(
    head_block: &ProtoBlock,
    attestation: &SingleAttestation,
) -> Result<(), Error> {
    // Check the attestation target root.
    let head_block_epoch = head_block.slot.epoch(E::slots_per_epoch());
    let attestation_epoch = attestation.data.slot.epoch(E::slots_per_epoch());
    if head_block_epoch > attestation_epoch {
        // The epoch references an invalid head block from a future epoch.
        //
        // This check is not in the specification, however we guard against it since it opens us up
        // to weird edge cases during verification.
        //
        // Whilst this attestation *technically* could be used to add value to a block, it is
        // invalid in the spirit of the protocol. Here we choose safety over profit.
        //
        // Reference:
        // https://github.com/ethereum/eth2.0-specs/pull/2001#issuecomment-699246659
        return Err(Error::InvalidTargetRoot {
            attestation: attestation.data.target.root,
            // It is not clear what root we should expect in this case, since the attestation is
            // fundamentally invalid.
            expected: None,
        });
    } else {
        let target_root = if head_block_epoch == attestation_epoch {
            // If the block is in the same epoch as the attestation, then use the target root
            // from the block.
            head_block.target_root
        } else {
            // If the head block is from a previous epoch then skip slots will cause the head block
            // root to become the target block root.
            //
            // We know the head block is from a previous epoch due to a previous check.
            head_block.root
        };

        // Reject any attestation with an invalid target root.
        if target_root != attestation.data.target.root {
            return Err(Error::InvalidTargetRoot {
                attestation: attestation.data.target.root,
                expected: Some(target_root),
            });
        }
    }

    Ok(())
}

pub fn get_indexed_attestation<E: EthSpec>(
    committees: &[BeaconCommittee],
    attestation: &SingleAttestation,
) -> Result<IndexedAttestation<E>, Error> {
    for committee in committees {
        if committee.slot == attestation.data.slot
            && committee.index == attestation.attester_index as u64
        {
            // TODO(single-attestation) RAISE ERROR
            todo!()
        }
    }

    let attesting_indices = vec![attestation.attester_index as u64];

    Ok(IndexedAttestation::Electra(IndexedAttestationElectra {
        // TODO(single-attestation) UNWRAP
        attesting_indices: VariableList::new(attesting_indices).unwrap(),
        data: attestation.data.clone(),
        signature: attestation.signature.clone(),
    }))
}

/// Assists in readability.
type CommitteesPerSlot = u64;

/// Returns the `indexed_attestation` and committee count per slot for the `single_attestation`.
pub fn obtain_indexed_attestation_and_committees_per_slot<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    attestation: &SingleAttestation,
) -> Result<(IndexedAttestation<T::EthSpec>, CommitteesPerSlot), Error> {
    // TODO(single-attestation) ERROR types
    let result = chain
        .with_committee_cache(
            attestation.data.target.root,
            attestation.data.slot.epoch(T::EthSpec::slots_per_epoch()),
            |committee_cache, _| {
                let committees = committee_cache
                    .get_beacon_committees_at_slot(attestation.data.slot)
                    .map_err(|_| Error::InvalidSignature).map_err(|_| BeaconChainError::AttestationCommitteeIndexNotSet)?;
                let indexed_attestation =
                    get_indexed_attestation(&committees, attestation).map_err(|_s| BeaconChainError::AttestationCommitteeIndexNotSet)?;

                Ok((indexed_attestation, committees.len() as u64))
            },
        )?;

    Ok(result)
}
