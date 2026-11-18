mod attester_slashing;
mod proposer_slashing;

pub use attester_slashing::{
    AttesterSlashing, AttesterSlashingBase, AttesterSlashingElectra, AttesterSlashingGloas,
    AttesterSlashingOnDisk, AttesterSlashingPq, AttesterSlashingRef, AttesterSlashingRefOnDisk,
};
pub use proposer_slashing::ProposerSlashing;
