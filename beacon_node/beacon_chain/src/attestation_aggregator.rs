use state_processing::validate_attestation_without_signature;
use std::collections::{HashMap, HashSet};
use types::{
    beacon_state::CommitteesError, AggregateSignature, Attestation, AttestationData, BeaconState,
    Bitfield, ChainSpec, FreeAttestation, Signature,
};

const PHASE_0_CUSTODY_BIT: bool = false;

/// Provides the functionality to:
///
///  - Recieve a `FreeAttestation` and aggregate it into an `Attestation` (or create a new if it
///  doesn't exist).
///  - Store all aggregated or created `Attestation`s.
///  - Produce a list of attestations that would be valid for inclusion in some `BeaconState` (and
///  therefore valid for inclusion in a `BeaconBlock`.
///
///  Note: `Attestations` are stored in memory and never deleted. This is not scalable and must be
///  rectified in a future revision.
#[derive(Default)]
pub struct AttestationAggregator {
    store: HashMap<Vec<u8>, Attestation>,
}

pub struct Outcome {
    pub valid: bool,
    pub message: Message,
}

pub enum Message {
    /// The free attestation was added to an existing attestation.
    Aggregated,
    /// The free attestation has already been aggregated to an existing attestation.
    AggregationNotRequired,
    /// The free attestation was transformed into a new attestation.
    NewAttestationCreated,
    /// The supplied `validator_index` is not in the committee for the given `shard` and `slot`.
    BadValidatorIndex,
    /// The given `signature` did not match the `pubkey` in the given
    /// `state.validator_registry`.
    BadSignature,
    /// The given `slot` does not match the validators committee assignment.
    BadSlot,
    /// The given `shard` does not match the validators committee assignment.
    BadShard,
}

macro_rules! some_or_invalid {
    ($expression: expr, $error: expr) => {
        match $expression {
            Some(x) => x,
            None => {
                return Ok(Outcome {
                    valid: false,
                    message: $error,
                });
            }
        }
    };
}

impl AttestationAggregator {
    /// Instantiates a new AttestationAggregator with an empty database.
    pub fn new() -> Self {
        Self {
            store: HashMap::new(),
        }
    }

    /// Accepts some `FreeAttestation`, validates it and either aggregates it upon some existing
    /// `Attestation` or produces a new `Attestation`.
    ///
    /// The "validation" provided is not complete, instead the following points are checked:
    ///  - The given `validator_index` is in the committee for the given `shard` for the given
    ///  `slot`.
    ///  - The signature is verified against that of the validator at `validator_index`.
    pub fn process_free_attestation(
        &mut self,
        state: &BeaconState,
        free_attestation: &FreeAttestation,
        spec: &ChainSpec,
    ) -> Result<Outcome, CommitteesError> {
        let (slot, shard, committee_index) = some_or_invalid!(
            state.attestation_slot_and_shard_for_validator(
                free_attestation.validator_index as usize,
                spec,
            )?,
            Message::BadValidatorIndex
        );

        if free_attestation.data.slot != slot {
            return Ok(Outcome {
                valid: false,
                message: Message::BadSlot,
            });
        }
        if free_attestation.data.shard != shard {
            return Ok(Outcome {
                valid: false,
                message: Message::BadShard,
            });
        }

        let signable_message = free_attestation.data.signable_message(PHASE_0_CUSTODY_BIT);

        let validator_record = some_or_invalid!(
            state
                .validator_registry
                .get(free_attestation.validator_index as usize),
            Message::BadValidatorIndex
        );

        if !free_attestation.signature.verify(
            &signable_message,
            spec.domain_attestation,
            &validator_record.pubkey,
        ) {
            return Ok(Outcome {
                valid: false,
                message: Message::BadSignature,
            });
        }

        if let Some(existing_attestation) = self.store.get(&signable_message) {
            if let Some(updated_attestation) = aggregate_attestation(
                existing_attestation,
                &free_attestation.signature,
                committee_index as usize,
            ) {
                self.store.insert(signable_message, updated_attestation);
                Ok(Outcome {
                    valid: true,
                    message: Message::Aggregated,
                })
            } else {
                Ok(Outcome {
                    valid: true,
                    message: Message::AggregationNotRequired,
                })
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
            Ok(Outcome {
                valid: true,
                message: Message::NewAttestationCreated,
            })
        }
    }

    /// Returns all known attestations which are:
    ///
    /// - Valid for the given state
    /// - Not already in `state.latest_attestations`.
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
                if validate_attestation_without_signature(&state, attestation, spec).is_ok()
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

/// Produces a new `Attestation` where:
///
/// - `signature` is added to `Attestation.aggregate_signature`
/// - Attestation.aggregation_bitfield[committee_index]` is set to true.
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
