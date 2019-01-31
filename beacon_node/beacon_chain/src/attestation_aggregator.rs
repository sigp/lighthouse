use std::collections::{HashMap, HashSet};
use types::{
    beacon_state::CommitteesError, AggregateSignature, Attestation, AttestationData, BeaconState,
    Bitfield, ChainSpec, FreeAttestation, Signature,
};

const PHASE_0_CUSTODY_BIT: bool = false;

pub struct AttestationAggregator {
    store: HashMap<Vec<u8>, Attestation>,
}

#[derive(Debug, PartialEq)]
pub enum ProcessOutcome {
    AggregationNotRequired,
    Aggregated,
    NewAttestationCreated,
}

#[derive(Debug, PartialEq)]
pub enum ProcessError {
    BadValidatorIndex,
    BadSignature,
    BadSlot,
    BadShard,
    CommitteesError(CommitteesError),
}

impl AttestationAggregator {
    pub fn new() -> Self {
        Self {
            store: HashMap::new(),
        }
    }

    pub fn process_free_attestation(
        &mut self,
        state: &BeaconState,
        free_attestation: &FreeAttestation,
        spec: &ChainSpec,
    ) -> Result<ProcessOutcome, ProcessError> {
        // let validator_index = free_attestation.validator_index as usize;
        let (slot, shard, committee_index) = state.attestation_slot_and_shard_for_validator(
            free_attestation.validator_index as usize,
            spec,
        )?;

        if free_attestation.data.slot != slot {
            return Err(ProcessError::BadSlot);
        }
        if free_attestation.data.shard != shard {
            return Err(ProcessError::BadShard);
        }

        let signable_message = free_attestation.data.signable_message(PHASE_0_CUSTODY_BIT);
        let validator_pubkey = &state
            .validator_registry
            .get(free_attestation.validator_index as usize)
            .ok_or_else(|| ProcessError::BadValidatorIndex)?
            .pubkey;

        if !free_attestation
            .signature
            .verify(&signable_message, &validator_pubkey)
        {
            return Err(ProcessError::BadSignature);
        }

        if let Some(existing_attestation) = self.store.get(&signable_message) {
            if let Some(updated_attestation) = aggregate_attestation(
                existing_attestation,
                &free_attestation.signature,
                committee_index as usize,
            ) {
                self.store.insert(signable_message, updated_attestation);
                Ok(ProcessOutcome::Aggregated)
            } else {
                Ok(ProcessOutcome::AggregationNotRequired)
            }
        } else {
            let mut aggregate_signature = AggregateSignature::new();
            aggregate_signature.add(&free_attestation.signature);
            let mut aggregation_bitfield = Bitfield::new();
            aggregation_bitfield.set(committee_index as usize, true);
            let new_attestation = Attestation {
                data: free_attestation.data.clone(),
                aggregation_bitfield,
                custody_bitfield: Bitfield::new(),
                aggregate_signature,
            };
            self.store.insert(signable_message, new_attestation);
            Ok(ProcessOutcome::NewAttestationCreated)
        }
    }

    /// Returns all known attestations which are:
    ///
    /// a) valid for the given state
    /// b) not already in `state.latest_attestations`.
    pub fn get_attestations_for_state(
        &self,
        state: &BeaconState,
        spec: &ChainSpec,
    ) -> Vec<Attestation> {
        let mut known_attestation_data: HashSet<AttestationData> = HashSet::new();

        state.latest_attestations.iter().for_each(|attestation| {
            known_attestation_data.insert(attestation.data.clone());
        });

        self.store
            .values()
            .filter_map(|attestation| {
                if state
                    .validate_attestation_without_signature(attestation, spec)
                    .is_ok()
                    && !known_attestation_data.contains(&attestation.data)
                {
                    Some(attestation.clone())
                } else {
                    None
                }
            })
            .collect()
    }
}

fn aggregate_attestation(
    existing_attestation: &Attestation,
    signature: &Signature,
    committee_index: usize,
) -> Option<Attestation> {
    let already_signed = existing_attestation
        .aggregation_bitfield
        .get(committee_index)
        .unwrap_or(false);

    if already_signed {
        None
    } else {
        let mut aggregation_bitfield = existing_attestation.aggregation_bitfield.clone();
        aggregation_bitfield.set(committee_index, true);
        let mut aggregate_signature = existing_attestation.aggregate_signature.clone();
        aggregate_signature.add(&signature);

        Some(Attestation {
            aggregation_bitfield,
            aggregate_signature,
            ..existing_attestation.clone()
        })
    }
}

impl From<CommitteesError> for ProcessError {
    fn from(e: CommitteesError) -> ProcessError {
        ProcessError::CommitteesError(e)
    }
}
