mod aggregate_and_proof;
mod attestation;
mod attestation_data;
mod attestation_duty;
mod beacon_committee;
mod checkpoint;
mod indexed_attestation;
mod indexed_payload_attestation;
mod participation_flags;
mod payload_attestation;
mod payload_attestation_data;
mod payload_attestation_message;
mod pending_attestation;
mod ptc;
mod selection_proof;
mod shuffling_id;
mod signed_aggregate_and_proof;
mod subnet_id;

pub use aggregate_and_proof::{
    AggregateAndProof, AggregateAndProofBase, AggregateAndProofElectra, AggregateAndProofRef,
};
pub use attestation::{
    Attestation, AttestationBase, AttestationElectra, AttestationOnDisk, AttestationRef,
    AttestationRefMut, AttestationRefOnDisk, Error as AttestationError, SingleAttestation,
};
pub use attestation_data::AttestationData;
pub use attestation_duty::AttestationDuty;
pub use beacon_committee::{BeaconCommittee, OwnedBeaconCommittee};
pub use checkpoint::Checkpoint;
pub use indexed_attestation::{
    IndexedAttestation, IndexedAttestationBase, IndexedAttestationElectra, IndexedAttestationRef,
};
pub use indexed_payload_attestation::IndexedPayloadAttestation;
pub use participation_flags::ParticipationFlags;
pub use payload_attestation::PayloadAttestation;
pub use payload_attestation_data::PayloadAttestationData;
pub use payload_attestation_message::PayloadAttestationMessage;
pub use pending_attestation::PendingAttestation;
pub use ptc::PTC;
pub use selection_proof::SelectionProof;
pub use shuffling_id::AttestationShufflingId;
pub use signed_aggregate_and_proof::{
    SignedAggregateAndProof, SignedAggregateAndProofBase, SignedAggregateAndProofElectra,
    SignedAggregateAndProofRefMut,
};
pub use subnet_id::SubnetId;

pub type CommitteeIndex = u64;
