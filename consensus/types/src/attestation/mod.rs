mod aggregate_and_proof;
mod attestation;
mod attestation_data;
mod attestation_duty;
mod beacon_committee;
mod checkpoint;
mod indexed_attestation;
mod participation_flags;
mod pending_attestation;
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
pub use participation_flags::ParticipationFlags;
pub use pending_attestation::PendingAttestation;
pub use selection_proof::SelectionProof;
pub use shuffling_id::AttestationShufflingId;
pub use signed_aggregate_and_proof::{
    SignedAggregateAndProof, SignedAggregateAndProofBase, SignedAggregateAndProofElectra,
    SignedAggregateAndProofRefMut,
};
pub use subnet_id::SubnetId;

pub type CommitteeIndex = u64;
