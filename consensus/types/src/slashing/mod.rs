mod attester_slashing;
mod proposer_slashing;

pub use attester_slashing::{
    AttesterSlashing, AttesterSlashingBase, AttesterSlashingElectra, AttesterSlashingGloas,
    AttesterSlashingOnDisk, AttesterSlashingRef, AttesterSlashingRefOnDisk,
};
pub use proposer_slashing::ProposerSlashing;
