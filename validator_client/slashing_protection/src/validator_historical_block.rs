use types::Epoch;

#[derive(Debug, Clone)]
pub struct ValidatorHistoricalBlock {
	epoch: Epoch,
	signing_root: Vec<u8>, // tree_hash_root
}

impl ValidatorHistoricalBlock {
	pub fn new(epoch: Epoch, signing_root: &[u8]) -> Self {
		Self {
			epoch,
			signing_root: signing_root.to_vec(),
		}
	}
}