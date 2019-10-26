use types::{Slot, BeaconBlockHeader, Hash256};

#[derive(Debug, Clone)]
pub struct ValidatorHistoricalBlock {
	pub slot: Slot,
	pub signing_root: Hash256,
}

impl ValidatorHistoricalBlock {
	pub fn from(header: &BeaconBlockHeader) -> Self {
		Self {
			slot: header.slot,
			signing_root: header.canonical_root(),
		}
	}
}