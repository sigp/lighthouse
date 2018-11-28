/// ForkData helps track which fork the current beacon chain is currently on in the case of planned hard forks (e.g. to upgrade the beacon chain).
#[derive(Debug, PartialEq)]
pub struct ForkData {
    pub pre_fork_version: u64,
    pub post_fork_version: u64,
    pub fork_slot_number: u64,
}
