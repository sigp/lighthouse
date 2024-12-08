use eth2::Timeouts;
use tempfile::{Builder as TempBuilder, TempDir};
use tokio::time::Duration;
use validator_dir::insecure_keys::build_deterministic_validator_dirs;

pub mod mock_beacon_node;
pub mod validator_test_rig;

const HTTP_ATTESTATION_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_ATTESTER_DUTIES_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_ATTESTATION_SUBSCRIPTIONS_TIMEOUT_QUOTIENT: u32 = 24;
const HTTP_LIVENESS_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_PROPOSAL_TIMEOUT_QUOTIENT: u32 = 2;
const HTTP_PROPOSER_DUTIES_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_SYNC_COMMITTEE_CONTRIBUTION_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_SYNC_DUTIES_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_GET_BEACON_BLOCK_SSZ_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_GET_DEBUG_BEACON_STATE_QUOTIENT: u32 = 4;
const HTTP_GET_DEPOSIT_SNAPSHOT_QUOTIENT: u32 = 4;
const HTTP_GET_VALIDATOR_BLOCK_TIMEOUT_QUOTIENT: u32 = 4;

pub fn get_optimised_bn_timeouts(slot_duration: Duration) -> Timeouts {
    Timeouts {
        attestation: slot_duration / HTTP_ATTESTATION_TIMEOUT_QUOTIENT,
        attester_duties: slot_duration / HTTP_ATTESTER_DUTIES_TIMEOUT_QUOTIENT,
        attestation_subscriptions: slot_duration / HTTP_ATTESTATION_SUBSCRIPTIONS_TIMEOUT_QUOTIENT,
        liveness: slot_duration / HTTP_LIVENESS_TIMEOUT_QUOTIENT,
        proposal: slot_duration / HTTP_PROPOSAL_TIMEOUT_QUOTIENT,
        proposer_duties: slot_duration / HTTP_PROPOSER_DUTIES_TIMEOUT_QUOTIENT,
        sync_committee_contribution: slot_duration
            / HTTP_SYNC_COMMITTEE_CONTRIBUTION_TIMEOUT_QUOTIENT,
        sync_duties: slot_duration / HTTP_SYNC_DUTIES_TIMEOUT_QUOTIENT,
        get_beacon_blocks_ssz: slot_duration / HTTP_GET_BEACON_BLOCK_SSZ_TIMEOUT_QUOTIENT,
        get_debug_beacon_states: slot_duration / HTTP_GET_DEBUG_BEACON_STATE_QUOTIENT,
        get_deposit_snapshot: slot_duration / HTTP_GET_DEPOSIT_SNAPSHOT_QUOTIENT,
        get_validator_block: slot_duration / HTTP_GET_VALIDATOR_BLOCK_TIMEOUT_QUOTIENT,
    }
}

pub struct ValidatorFiles {
    pub validator_dir: TempDir,
    pub secrets_dir: TempDir,
}

impl ValidatorFiles {
    /// Creates temporary data and secrets dirs.
    pub fn new() -> Result<Self, String> {
        let datadir = TempBuilder::new()
            .prefix("lighthouse-validator-client")
            .tempdir()
            .map_err(|e| format!("Unable to create VC data dir: {:?}", e))?;

        let secrets_dir = TempBuilder::new()
            .prefix("lighthouse-validator-client-secrets")
            .tempdir()
            .map_err(|e| format!("Unable to create VC secrets dir: {:?}", e))?;

        Ok(Self {
            validator_dir: datadir,
            secrets_dir,
        })
    }

    /// Creates temporary data and secrets dirs, preloaded with keystores.
    pub fn with_keystores(keypair_indices: &[usize]) -> Result<Self, String> {
        let this = Self::new()?;

        build_deterministic_validator_dirs(
            this.validator_dir.path().into(),
            this.secrets_dir.path().into(),
            keypair_indices,
        )
        .map_err(|e| format!("Unable to build validator directories: {:?}", e))?;

        Ok(this)
    }
}
