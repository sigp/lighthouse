use crate::Uint256;
use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};

#[derive(Default, Debug, PartialEq, Hash, Clone, Copy, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BlsFieldElement(pub Uint256);