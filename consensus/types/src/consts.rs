pub mod phase0 {
    pub const GENESIS_SLOT: crate::Slot = crate::Slot::new(0);
    // pub const GENESIS_EPOCH: u64 = 0;
    pub const FAR_FUTURE_EPOCH: crate::Epoch = crate::Epoch::new(u64::MAX);
    pub const BASE_REWARDS_PER_EPOCH: u64 = 4;
    pub const DEPOSIT_CONTRACT_TREE_DEPTH: u64 = 32;
    pub const JUSTIFICATION_BITS_LENGTH: u64 = 4;

    // Withdrawal prefixes
    pub const BLS_WITHDRAWAL_PREFIX: u8 = 0x00;
    pub const ETH1_ADDRESS_WITHDRAWAL_PREFIX: u8 = 0x01;
}

pub mod domains {
    // Phase 0
    pub const DOMAIN_BEACON_PROPOSER: u32 = 0;
    pub const DOMAIN_BEACON_ATTESTER: u32 = 1;
    pub const DOMAIN_RANDAO: u32 = 2;
    pub const DOMAIN_DEPOSIT: u32 = 3;
    pub const DOMAIN_VOLUNTARY_EXIT: u32 = 4;
    pub const DOMAIN_SELECTION_PROOF: u32 = 5;
    pub const DOMAIN_AGGREGATE_AND_PROOF: u32 = 6;

    // Altair
    pub const DOMAIN_SYNC_COMMITTEE: u32 = 7;
    pub const DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF: u32 = 8;
    pub const DOMAIN_CONTRIBUTION_AND_PROOF: u32 = 9;

    // Capella
    pub const DOMAIN_BLS_TO_EXECUTION_CHANGE: u32 = 10;

    // Electra
    pub const DOMAIN_CONSOLIDATION: u32 = 0x0B;

    pub use crate::application_domain::APPLICATION_DOMAIN_BUILDER;
}

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
pub mod bellatrix {
    pub const INTERVALS_PER_SLOT: u64 = 3;
}
pub mod deneb {
    pub use crate::VERSIONED_HASH_VERSION_KZG;
}

pub mod electra {
    pub const UNSET_DEPOSIT_REQUESTS_START_INDEX: u64 = u64::MAX;
    pub const FULL_EXIT_REQUEST_AMOUNT: u64 = 0;
    pub const COMPOUNDING_WITHDRAWAL_PREFIX: u8 = 0x02;
}

pub use phase0::*;
