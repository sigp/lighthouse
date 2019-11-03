use crate::ChainSpec;

macro_rules! struct_definition {
    ($($element: ident: $ty: ty),+) => {
        pub struct YamlConfig {
            $(
                $element: $ty
            )*
        }

        impl YamlConfig {
            pub fn from_spec(spec: ChainSpec) -> Self {
                Self {
                    $(
                        $element: spec.$element,
                    )*
                }
            }

            pub fn to_spec(self, base_spec: ChainSpec) -> ChainSpec {
                ChainSpec {
                    $(
                        $element: self.$element,
                    )*
                    .. base_spec
                }
            }
        }
    }
}

struct_definition!(shuffle_round_count: u8);

/*
// Mainnet preset
// Note: the intention of this file (for now) is to illustrate what a mainnet configuration could look like.
// Some of these constants may still change before the launch of Phase 0.


// Misc
SHARD_COUNT: u64,
TARGET_COMMITTEE_SIZE: u64,
MAX_VALIDATORS_PER_COMMITTEE: u64,
MIN_PER_EPOCH_CHURN_LIMIT: u64,
CHURN_LIMIT_QUOTIENT: u64,
SHUFFLE_ROUND_COUNT: u64,
MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: u64,
MIN_GENESIS_TIME: u64,
// Deposit contract
DEPOSIT_CONTRACT_ADDRESS: 0x1234567890123456789012345678901234567890
// Gwei values
MIN_DEPOSIT_AMOUNT: u64,
MAX_EFFECTIVE_BALANCE: u64,
EJECTION_BALANCE: u64,
EFFECTIVE_BALANCE_INCREMENT: u64,
// Initial values
GENESIS_SLOT: u64,
BLS_WITHDRAWAL_PREFIX: 0x00
// Time parameters
SECONDS_PER_SLOT: u64,
MIN_ATTESTATION_INCLUSION_DELAY: u64,
SLOTS_PER_EPOCH: u64,
MIN_SEED_LOOKAHEAD: u64,
ACTIVATION_EXIT_DELAY: u64,
SLOTS_PER_ETH1_VOTING_PERIOD: u64,
SLOTS_PER_HISTORICAL_ROOT: u64,
MIN_VALIDATOR_WITHDRAWABILITY_DELAY: u64,
PERSISTENT_COMMITTEE_PERIOD: u64,
MAX_EPOCHS_PER_CROSSLINK: u64,
MIN_EPOCHS_TO_INACTIVITY_PENALTY: u64,
EARLY_DERIVED_SECRET_PENALTY_MAX_FUTURE_EPOCHS: u64,
// State vector lengths
EPOCHS_PER_HISTORICAL_VECTOR: u64,
EPOCHS_PER_SLASHINGS_VECTOR: u64,
HISTORICAL_ROOTS_LIMIT: u64,
VALIDATOR_REGISTRY_LIMIT: u64,
// Reward and penalty quotients
BASE_REWARD_FACTOR: u64,
WHISTLEBLOWER_REWARD_QUOTIENT: u64,
PROPOSER_REWARD_QUOTIENT: u64,
INACTIVITY_PENALTY_QUOTIENT: u64,
MIN_SLASHING_PENALTY_QUOTIENT: u64,
// Max operations per block
MAX_PROPOSER_SLASHINGS: u64,
MAX_ATTESTER_SLASHINGS: u64,
MAX_ATTESTATIONS: u64,
MAX_DEPOSITS: u64,
MAX_VOLUNTARY_EXITS: u64,
MAX_TRANSFERS: u64,
// Signature domains
DOMAIN_BEACON_PROPOSER: 0x00000000
DOMAIN_RANDAO: 0x01000000
DOMAIN_ATTESTATION: 0x02000000
DOMAIN_DEPOSIT: 0x03000000
DOMAIN_VOLUNTARY_EXIT: 0x04000000
DOMAIN_TRANSFER: 0x05000000
DOMAIN_CUSTODY_BIT_CHALLENGE: 0x06000000
DOMAIN_SHARD_PROPOSER: 0x80000000
DOMAIN_SHARD_ATTESTER: 0x81000000
*/
