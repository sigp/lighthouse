use super::ChainSpec;
use bls::{Keypair, PublicKey, SecretKey, Signature};

use crate::{Address, Eth1Data, Hash256, Slot, Validator};

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
            target_committee_size: 128,
            ejection_balance: 16 * u64::pow(10, 9),
            max_balance_churn_quotient: 32,
            beacon_chain_shard_number: u64::max_value(),
            max_casper_votes: 1_024,
            latest_block_roots_length: 8_192,
            latest_randao_mixes_length: 8_192,
            latest_penalized_exit_length: 8_192,
            max_withdrawals_per_epoch: 4,
            /*
             *  Deposit contract
             */
            deposit_contract_address: Address::from("TBD".as_bytes()),
            deposit_contract_tree_depth: 32,
            min_deposit: 1 * u64::pow(10, 9),
            max_deposit: 32 * u64::pow(10, 9),
            /*
             * Initial Values
             */
            genesis_fork_version: 0,
            genesis_slot: Slot::from(0_u64),
            genesis_start_shard: 0,
            far_future_slot: Slot::from(u64::max_value()),
            zero_hash: Hash256::zero(),
            empty_signature: Signature::empty_signature(),
            bls_withdrawal_prefix_byte: 0x00,
            /*
             * Time parameters
             */
            slot_duration: 6,
            min_attestation_inclusion_delay: 4,
            epoch_length: 64,
            seed_lookahead: 64,
            entry_exit_delay: 256,
            eth1_data_voting_period: 1_024,
            min_validator_withdrawal_time: u64::pow(2, 14),
            /*
             * Reward and penalty quotients
             */
            base_reward_quotient: 32,
            whistleblower_reward_quotient: 512,
            includer_reward_quotient: 8,
            inactivity_penalty_quotient: u64::pow(2, 24),
            /*
             * Max operations per block
             */
            max_proposer_slashings: 16,
            max_casper_slashings: 16,
            max_attestations: 128,
            max_deposits: 16,
            max_exits: 16,
            /*
             * Intialization parameters
             */
            initial_validators: initial_validators_for_testing(),
            initial_balances: initial_balances_for_testing(),
            genesis_time: 1_544_672_897,
            intial_eth1_data: Eth1Data {
                deposit_root: Hash256::from("deposit_root".as_bytes()),
                block_hash: Hash256::from("block_hash".as_bytes()),
            },
        }
    }
}

/// Generate a set of validator records to use with testing until the real chain starts.
fn initial_validators_for_testing() -> Vec<Validator> {
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
        let validator = Validator {
            pubkey: keypair.pk.clone(),
            withdrawal_credentials: Hash256::zero(),
            proposer_slots: Slot::from(0_u64),
            activation_slot: Slot::max_value(),
            exit_slot: Slot::max_value(),
            withdrawal_slot: Slot::max_value(),
            penalized_slot: Slot::max_value(),
            exit_count: 0,
            status_flags: None,
            latest_custody_reseed_slot: Slot::from(0_u64),
            penultimate_custody_reseed_slot: Slot::from(0_u64),
        };
        initial_validators.push(validator);
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
