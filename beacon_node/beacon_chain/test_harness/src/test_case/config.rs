use super::yaml_helpers::{as_u64, as_usize, as_vec_u64};
use bls::create_proof_of_possession;
use types::*;
use yaml_rust::Yaml;

pub type DepositTuple = (u64, Deposit, Keypair);
pub type ProposerSlashingTuple = (u64, u64);
pub type AttesterSlashingTuple = (u64, Vec<u64>);

/// Defines the execution of a `BeaconStateHarness` across a series of slots.
#[derive(Debug)]
pub struct Config {
    /// Initial validators.
    pub deposits_for_chain_start: usize,
    /// Number of slots in an epoch.
    pub epoch_length: Option<u64>,
    /// Number of slots to build before ending execution.
    pub num_slots: u64,
    /// Number of slots that should be skipped due to inactive validator.
    pub skip_slots: Option<Vec<u64>>,
    /// Deposits to be included during execution.
    pub deposits: Option<Vec<DepositTuple>>,
    /// Proposer slashings to be included during execution.
    pub proposer_slashings: Option<Vec<ProposerSlashingTuple>>,
    /// Attester slashings to be including during execution.
    pub attester_slashings: Option<Vec<AttesterSlashingTuple>>,
}

impl Config {
    /// Load from a YAML document.
    ///
    /// Expects to receive the `config` section of the document.
    pub fn from_yaml(yaml: &Yaml) -> Self {
        Self {
            deposits_for_chain_start: as_usize(&yaml, "deposits_for_chain_start")
                .expect("Must specify validator count"),
            epoch_length: as_u64(&yaml, "epoch_length"),
            num_slots: as_u64(&yaml, "num_slots").expect("Must specify `config.num_slots`"),
            skip_slots: as_vec_u64(yaml, "skip_slots"),
            deposits: parse_deposits(&yaml),
            proposer_slashings: parse_proposer_slashings(&yaml),
            attester_slashings: parse_attester_slashings(&yaml),
        }
    }
}

/// Parse the `attester_slashings` section of the YAML document.
fn parse_attester_slashings(yaml: &Yaml) -> Option<Vec<AttesterSlashingTuple>> {
    let mut slashings = vec![];

    for slashing in yaml["attester_slashings"].as_vec()? {
        let slot = as_u64(slashing, "slot").expect("Incomplete attester_slashing (slot)");
        let validator_indices = as_vec_u64(slashing, "validator_indices")
            .expect("Incomplete attester_slashing (validator_indices)");

        slashings.push((slot, validator_indices));
    }

    Some(slashings)
}

/// Parse the `proposer_slashings` section of the YAML document.
fn parse_proposer_slashings(yaml: &Yaml) -> Option<Vec<ProposerSlashingTuple>> {
    let mut slashings = vec![];

    for slashing in yaml["proposer_slashings"].as_vec()? {
        let slot = as_u64(slashing, "slot").expect("Incomplete proposer slashing (slot)_");
        let validator_index = as_u64(slashing, "validator_index")
            .expect("Incomplete proposer slashing (validator_index)");

        slashings.push((slot, validator_index));
    }

    Some(slashings)
}

/// Parse the `deposits` section of the YAML document.
fn parse_deposits(yaml: &Yaml) -> Option<Vec<DepositTuple>> {
    let mut deposits = vec![];

    for deposit in yaml["deposits"].as_vec()? {
        let keypair = Keypair::random();
        let proof_of_possession = create_proof_of_possession(&keypair);

        let slot = as_u64(deposit, "slot").expect("Incomplete deposit (slot)");
        let amount =
            as_u64(deposit, "amount").expect("Incomplete deposit (amount)") * 1_000_000_000;

        let deposit = Deposit {
            // Note: `branch` and `index` will need to be updated once the spec defines their
            // validity.
            branch: vec![],
            index: 0,
            deposit_data: DepositData {
                amount,
                timestamp: 1,
                deposit_input: DepositInput {
                    pubkey: keypair.pk.clone(),
                    withdrawal_credentials: Hash256::zero(),
                    proof_of_possession,
                },
            },
        };

        deposits.push((slot, deposit, keypair));
    }

    Some(deposits)
}
