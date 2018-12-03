#[derive(Debug, Clone, PartialEq)]
pub struct ForkData {
    pub pre_fork_version: u64,
    pub post_fork_version: u64,
    pub fork_slot: u64,
}
