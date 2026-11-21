use super::{
    Error, IndexedAggregatedAttestation, IndexedUnaggregatedAttestation,
    VerifiedAggregatedAttestation, VerifiedUnaggregatedAttestation, verify_committee_index,
};
use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes, metrics, observed_aggregates::ObserveOutcome,
};
use pq_prover::Proof;
use state_processing::{per_block_processing::errors::AttestationInvalid, pq};
use types::{
    AttestationRef, Domain, EthSpec, ForkName, IndexedAttestation, IndexedAttestationPq,
    SignedAggregateAndProof, SignedAggregateAndProofPq, SignedRoot, SingleAttestation,
    SingleAttestationPq, SubnetId,
};

impl<'a, T: BeaconChainTypes> VerifiedUnaggregatedAttestation<'a, T> {
    pub(super) fn verify_pq(
        single_attestation: &'a SingleAttestation,
        attestation: &SingleAttestationPq,
        subnet_id: Option<SubnetId>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, Error> {
        if chain
            .spec
            .fork_name_at_slot::<T::EthSpec>(attestation.data.slot)
            != ForkName::Pq
        {
            return Err(Error::InvalidSignature);
        }
        IndexedUnaggregatedAttestation::verify_early_checks(single_attestation, chain)?;
        let index =
            IndexedUnaggregatedAttestation::verify_middle_checks(single_attestation, chain)?;
        let head = chain.head_snapshot();
        let state = &head.beacon_state;
        let validator = state
            .validators()
            .get(index as usize)
            .ok_or(Error::ValidatorIndexTooHigh(index as usize))?;
        let domain = chain.spec.get_domain(
            attestation.data.target.epoch,
            Domain::BeaconAttester,
            &state.fork(),
            state.genesis_validators_root(),
        );
        let leaf = pq::attestation_leaf_index(attestation.data.target.epoch)
            .map_err(BeaconChainError::from)?;
        {
            let _timer = metrics::start_timer(&metrics::PQ_XMSS_VERIFY_SECONDS);
            if !pq::verify_signature(
                &validator.pubkey,
                leaf,
                attestation.data.signing_root(domain),
                &attestation.signature,
            ) {
                return Err(Error::InvalidSignature);
            }
        }
        let (aggregate, subnet_id) =
            Self::verify_late_checks(single_attestation, index, subnet_id, chain)?;
        if let AttestationRef::Pq(aggregate) = aggregate.to_ref() {
            chain.insert_pq_signature(attestation, &aggregate.aggregation_bits);
        }
        Ok(Self {
            attestation: aggregate,
            single_attestation,
            indexed_attestation: IndexedAttestation::Pq(IndexedAttestationPq {
                attesting_indices: vec![index].try_into()?,
                data: attestation.data.clone(),
                // Fork choice consumes the authenticated indices only.
                proof: Default::default(),
            }),
            subnet_id,
        })
    }
}

impl<'a, T: BeaconChainTypes> VerifiedAggregatedAttestation<'a, T> {
    pub(super) fn verify_pq(
        signed_aggregate: &'a SignedAggregateAndProof<T::EthSpec>,
        aggregate: &SignedAggregateAndProofPq<T::EthSpec>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, Error> {
        let attestation = &aggregate.message.aggregate;
        let data = &attestation.data;
        if chain.spec.fork_name_at_slot::<T::EthSpec>(data.slot) != ForkName::Pq {
            return Err(Error::InvalidSignature);
        }
        verify_committee_index(AttestationRef::Pq(attestation), ForkName::Pq)?;
        let key = IndexedAggregatedAttestation::verify_early_checks(signed_aggregate, chain)?;
        let index = attestation
            .committee_index()
            .ok_or(Error::NotExactlyOneCommitteeBitSet(0))?;
        let aggregator_index = aggregate.message.aggregator_index;
        let mut state = chain.head_beacon_state_cloned();
        if data.target.epoch
            > state
                .current_epoch()
                .saturating_add(chain.spec.min_seed_lookahead.as_u64())
        {
            state = chain.state_at_slot(
                data.target.epoch.start_slot(T::EthSpec::slots_per_epoch()),
                crate::StateSkipConfig::WithoutStateRoots,
            )?;
        }
        state
            .build_all_committee_caches(&chain.spec)
            .map_err(BeaconChainError::from)?;
        let committee = state.get_beacon_committee(data.slot, index).map_err(|_| {
            Error::NoCommitteeForSlotAndIndex {
                slot: data.slot,
                index,
            }
        })?;
        if committee.committee.len() != attestation.aggregation_bits.len() {
            return Err(Error::Invalid(
                state_processing::per_block_processing::errors::BlockOperationError::Invalid(
                    AttestationInvalid::BadAggregationBitfieldLength {
                        committee_len: committee.committee.len(),
                        bitfield_len: attestation.aggregation_bits.len(),
                    },
                ),
            ));
        }
        if !pq::is_aggregator(&state, data.slot, index, aggregator_index)
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::AggregatorNotInCommittee { aggregator_index });
        }
        let validator = state
            .validators()
            .get(aggregator_index as usize)
            .ok_or(Error::AggregatorPubkeyUnknown(aggregator_index))?;
        let domain = chain.spec.get_domain(
            data.target.epoch,
            Domain::AggregateAndProof,
            &state.fork(),
            state.genesis_validators_root(),
        );
        let leaf = pq::slot_leaf_index(data.slot, pq::LEAF_OFFSET_AGGREGATE_AND_PROOF)
            .map_err(BeaconChainError::from)?;
        {
            let _timer = metrics::start_timer(&metrics::PQ_XMSS_VERIFY_SECONDS);
            if !pq::verify_signature(
                &validator.pubkey,
                leaf,
                signed_aggregate.message().signing_root(domain),
                &aggregate.signature,
            ) {
                return Err(Error::InvalidSignature);
            }
        }
        let indices = committee
            .committee
            .iter()
            .zip(attestation.aggregation_bits.iter())
            .filter_map(|(index, bit)| bit.then_some(*index as u64))
            .collect::<Vec<_>>();
        let statement = pq::attestation_statement(&state, data, &indices, &chain.spec)
            .map_err(BeaconChainError::from)?;
        let backend = &chain
            .pq_provers
            .as_ref()
            .ok_or(BeaconChainError::MissingPqProver)?
            .aggregate;
        {
            let _timer = metrics::start_timer(&metrics::PQ_AGGREGATE_VERIFY_SECONDS);
            if !backend
                .verify(
                    std::slice::from_ref(&statement),
                    &Proof::from_bytes(aggregate.message.proof.to_vec()),
                )
                .map_err(BeaconChainError::PqProverError)?
            {
                return Err(Error::InvalidSignature);
            }
        }
        // Register the aggregator before touching the aggregate cache. In
        // particular a concurrent duplicate must not add an otherwise unseen
        // aggregate to the cache and prevent another validator publishing it.
        if chain
            .observed_aggregators
            .write()
            .observe_validator(data.target.epoch, aggregator_index as usize)
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::AggregatorAlreadyKnown(aggregator_index));
        }
        if let ObserveOutcome::Subset = chain
            .observed_attestations
            .write()
            .observe_item(AttestationRef::Pq(attestation), Some(key))
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::AttestationSupersetKnown(key));
        }
        let mut indices = indices;
        indices.sort_unstable();
        Ok(Self {
            pq_statement: Some(statement),
            signed_aggregate,
            indexed_attestation: IndexedAttestation::Pq(IndexedAttestationPq {
                attesting_indices: indices.try_into()?,
                data: data.clone(),
                proof: aggregate.message.proof.clone(),
            }),
        })
    }
}
