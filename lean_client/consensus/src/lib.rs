pub mod attestation;
pub use attestation::{Attestation, AttestationData, Checkpoint, SignedAttestation, Slot};
pub mod helpers;
pub use helpers::is_justifiable_slot;
pub mod lean_block;
pub mod lean_state;
pub mod validator;
