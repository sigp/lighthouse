use super::ChainSpec;
use bls::{Keypair, PublicKey, SecretKey};

use types::{Address, Hash256, ValidatorRecord};

/// The size of a validators deposit in GWei.
pub const DEPOSIT_GWEI: u64 = 32_000_000_000;

impl ChainSpec {
    /// Returns a `ChainSpec` compatible with the specification from Ethereum Foundation.
    ///
    /// Of course, the actual foundation specs are unknown at this point so these are just a rough
    /// estimate.
    pub fn foundation() -> Self {
        Self {
            /*
             * Misc
             */
            shard_count: 1_024,
            target_committee_size: 256,
            ejection_balance: 16,
            max_balance_churn_quotient: 32,
            gwei_per_eth: u64::pow(10, 9),
            beacon_chain_shard_number: u64::max_value(),
            bls_withdrawal_prefix_byte: 0x00,
            max_casper_votes: 1_024,
            latest_randao_mixes_length: 8_192,
            /*
             *  Deposit contract
             */
            deposit_contract_address: Address::from("TBD".as_bytes()),
            deposit_contract_tree_depth: 32,
            min_deposit: 1,
            max_deposit: 32,
            /*
             * Initial Values
             */
            initial_fork_version: 0,
            initial_slot_number: 0,
            zero_hash: Hash256::zero(),
            /*
             * Time parameters
             */
            slot_duration: 6,
            min_attestation_inclusion_delay: 4,
            epoch_length: 64,
            min_validator_registry_change_interval: 256,
            pow_receipt_root_voting_period: 1_024,
            shard_persistent_committee_change_period: u64::pow(2, 17),
            collective_penalty_calculation_period: u64::pow(2, 20),
            zero_balance_validator_ttl: u64::pow(2, 22),
            /*
             * Reward and penalty quotients
             */
            base_reward_quotient: 2_048,
            whistleblower_reward_quotient: 512,
            includer_reward_quotient: 8,
            inactivity_penalty_quotient: u64::pow(2, 34),
            /*
             * Max operations per block
             */
            max_proposer_slashings: 16,
            max_casper_slashings: 15,
            max_attestations: 128,
            max_deposits: 16,
            max_exits: 16,
            /*
             * Intialization parameters
             */
            initial_validators: initial_validators_for_testing(),
            initial_balances: initial_balances_for_testing(),
            genesis_time: 1_544_672_897,
            processed_pow_receipt_root: Hash256::from("pow_root".as_bytes()),
        }
    }
}

/// Generate a set of validator records to use with testing until the real chain starts.
fn initial_validators_for_testing() -> Vec<ValidatorRecord> {
    // Some dummy private keys to start with.
    let key_strings = vec![
        "jzjxxgjajfjrmgodszzsgqccmhnyvetcuxobhtynojtpdtbj",
        "gpeehcjudxdijzhjgirfuhahmnjutlchjmoffxmimbdejakd",
        "ntrrdwwebodokuwaclhoqreqyodngoyhurvesghjfxeswoaj",
        "cibmzkqrzdgdlrvqaxinwpvyhcgjkeysrsjkqtkcxvznsvth",
        "erqrfuahdwprsstkawggounxmihzhrvbhchcyiwtaypqcedr",
    ];

    let mut initial_validators = Vec::with_capacity(key_strings.len());
    for key_string in key_strings {
        let keypair = {
            let secret_key = match SecretKey::from_bytes(&key_string.as_bytes()) {
                Ok(key) => key,
                Err(_) => unreachable!(), // Keys are static and should not fail.
            };
            let public_key = PublicKey::from_secret_key(&secret_key);
            Keypair {
                sk: secret_key,
                pk: public_key,
            }
        };
        let validator_record = ValidatorRecord {
            pubkey: keypair.pk.clone(),
            ..std::default::Default::default()
        };
        initial_validators.push(validator_record);
    }

    initial_validators
}

fn initial_balances_for_testing() -> Vec<u64> {
    vec![DEPOSIT_GWEI; 4]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_foundation_spec_can_be_constructed() {
        let _ = ChainSpec::foundation();
    }
}
