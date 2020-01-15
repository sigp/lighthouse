use crate::Hash256;

pub struct SigningRoot {
    pub object_root: Hash256,
    pub domain: u64,
}
