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
    pub const BASIS_POINTS: u64 = 10_000;
}
pub mod deneb {
    pub use kzg::VERSIONED_HASH_VERSION_KZG;
}
pub mod gloas {
    pub const BUILDER_INDEX_SELF_BUILD: u64 = u64::MAX;
    pub const BUILDER_INDEX_FLAG: u64 = 1 << 40;

    /// Version for an execution payload builder.
    pub const PAYLOAD_BUILDER_VERSION: u8 = 0;

    // Fork choice constants
    pub type PayloadStatus = u8;
    pub const PAYLOAD_STATUS_EMPTY: PayloadStatus = 0;
    pub const PAYLOAD_STATUS_FULL: PayloadStatus = 1;
    pub const PAYLOAD_STATUS_PENDING: PayloadStatus = 2;

    pub const ATTESTATION_TIMELINESS_INDEX: usize = 0;
    pub const PTC_TIMELINESS_INDEX: usize = 1;
    pub const NUM_BLOCK_TIMELINESS_DEADLINES: usize = 2;
}
pub mod pq {
    /// The number of aggregators sampled for each beacon committee.
    pub const AGGREGATORS_PER_COMMITTEE: u64 = 1 << 2;

    // XMSS
    pub const XMSS_SIGNATURE_SIZE: u64 = 2404;
    /// The first `XMSS_RESERVED_LEAVES` leaves are for messages without a leaf of their own.
    pub const XMSS_RESERVED_LEAVES: u64 = 1 << 15;
    pub const XMSS_ATTESTATION_LEAVES: u64 = 1 << 29;
    pub const XMSS_BUILDER_BID_LEAVES: u64 = 1 << 30;
    pub const XMSS_LEAVES_PER_SLOT: u64 = 1 << 3;

    // VRF
    pub const VRF_TREE_DEPTH: u64 = 31;

    // XMSS leaf offsets
    pub const LEAF_OFFSET_BEACON_PROPOSER: u64 = 0;
    pub const LEAF_OFFSET_AGGREGATE_AND_PROOF: u64 = 1;
    pub const LEAF_OFFSET_PTC_ATTESTER: u64 = 2;
    pub const LEAF_OFFSET_PROPOSER_PREFERENCES: u64 = 3;
    pub const LEAF_OFFSET_EXECUTION_PAYLOAD_ENVELOPE: u64 = 4;

    /// A request's 48-byte public key field is this prefix followed by an XMSS public key.
    pub const XMSS_DEPOSIT_PREFIX: [u8; 16] = [0; 16];

    // Legacy domains
    pub const LEGACY_XMSS_PUBKEY_DOMAIN: u8 = 0x00;
    pub const LEGACY_VRF_ROOT_DOMAIN: u8 = 0x01;

    // Execution-layer triggered requests
    pub const VALIDATOR_PREREGISTRATION_REQUEST_TYPE: u8 = 0x07;
    pub const BUILDER_PREREGISTRATION_REQUEST_TYPE: u8 = 0x08;
    pub const VOLUNTARY_EXIT_REQUEST_TYPE: u8 = 0x09;
}
