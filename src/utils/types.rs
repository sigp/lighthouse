use super::ethereum_types::{ H256, H160 };
use super::active_state::ActiveState;
use super::crystallized_state::CrystallizedState;
use super::boolean_bitfield::BooleanBitfield;

pub use super::blake2::Blake2s;
pub use super::ethereum_types::U256;

// TODO: presently the compiler accepts these two types
// as interchangable. This is somewhat loose typing, 
// which is bad. Make the compiler think they're incompatible.
pub type Sha256Digest = H256;
pub type Blake2sDigest = H256;

pub type Address = H160;

pub struct StateHash {
    pub active_state: Blake2sDigest,
    pub crystallized_state: Blake2sDigest
}

impl StateHash {
    pub fn zero() -> Self {
        Self {
            active_state: Blake2sDigest::zero(),
            crystallized_state: Blake2sDigest::zero()
        }
    }

    pub fn from_states(active: &ActiveState, crystal: &CrystallizedState) -> Self {
        Self {
            active_state: active.blake2s_hash(),
            crystallized_state: crystal.blake2s_hash()
        }
    }
}

pub type Bitfield = BooleanBitfield;
