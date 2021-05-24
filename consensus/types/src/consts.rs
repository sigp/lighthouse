pub mod altair {
    pub const TIMELY_HEAD_FLAG_INDEX: u32 = 0;
    pub const TIMELY_SOURCE_FLAG_INDEX: u32 = 1;
    pub const TIMELY_TARGET_FLAG_INDEX: u32 = 2;
    pub const TIMELY_HEAD_WEIGHT: u64 = 12;
    pub const TIMELY_SOURCE_WEIGHT: u64 = 12;
    pub const TIMELY_TARGET_WEIGHT: u64 = 24;
    pub const SYNC_REWARD_WEIGHT: u64 = 8;
    pub const PROPOSER_WEIGHT: u64 = 8;
    pub const WEIGHT_DENOMINATOR: u64 = 64;
    //FIXME(sean): updated in the latest spec
    pub const SYNC_COMMITTEE_SUBNET_COUNT: u64 = 8;
    pub const TARGET_AGGREGATORS_PER_SYNC_COMMITTEE: u64 = 4;

    pub const FLAG_INDICES_AND_WEIGHTS: [(u32, u64); NUM_FLAG_INDICES] = [
        (TIMELY_HEAD_FLAG_INDEX, TIMELY_HEAD_WEIGHT),
        (TIMELY_SOURCE_FLAG_INDEX, TIMELY_SOURCE_WEIGHT),
        (TIMELY_TARGET_FLAG_INDEX, TIMELY_TARGET_WEIGHT),
    ];

    pub const NUM_FLAG_INDICES: usize = 3;
}
