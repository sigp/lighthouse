use tree_hash_derive::CachedTreeHashSubTree;

#[derive(Clone, Debug, CachedTreeHashSubTree)]
pub struct Inner {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub d: u64,
}
