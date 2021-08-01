pub mod altair {
    pub const TIMELY_SOURCE_FLAG_INDEX: usize = 0;
    pub const TIMELY_TARGET_FLAG_INDEX: usize = 1;
    pub const TIMELY_HEAD_FLAG_INDEX: usize = 2;
    pub const TIMELY_SOURCE_WEIGHT: u64 = 14;
    pub const TIMELY_TARGET_WEIGHT: u64 = 26;
    pub const TIMELY_HEAD_WEIGHT: u64 = 14;
    pub const SYNC_REWARD_WEIGHT: u64 = 2;
    pub const PROPOSER_WEIGHT: u64 = 8;
    pub const WEIGHT_DENOMINATOR: u64 = 64;
    pub const SYNC_COMMITTEE_SUBNET_COUNT: u64 = 4;
    pub const TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE: u64 = 16;

    pub const PARTICIPATION_FLAG_WEIGHTS: [u64; NUM_FLAG_INDICES] = [
        TIMELY_SOURCE_WEIGHT,
        TIMELY_TARGET_WEIGHT,
        TIMELY_HEAD_WEIGHT,
    ];

    pub const NUM_FLAG_INDICES: usize = 3;
}
