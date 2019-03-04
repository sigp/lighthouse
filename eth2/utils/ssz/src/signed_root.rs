use crate::TreeHash;

pub trait SignedRoot: TreeHash {
    fn signed_root(&self) -> Vec<u8>;
}
