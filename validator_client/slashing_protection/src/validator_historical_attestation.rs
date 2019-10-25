use types::Epoch;

#[derive(Debug, Clone)]
pub struct ValidatorHistoricalAttestation {
	source_epoch: Epoch,
	target_epoch: Epoch,
	signing_root: Vec<u8>, // tree_hash_root
}

impl ValidatorHistoricalAttestation {
	pub fn new(source_epoch: Epoch, target_epoch: Epoch, signing_root: &[u8]) -> Self {
		Self {
			source_epoch,
			target_epoch,
			signing_root: signing_root.to_vec(),
		}
	}
}