use super::*;
use crate::bls_setting::BlsSetting;
use crate::decode::{ssz_decode_file, ssz_decode_state, yaml_decode_file};
use crate::type_name::TypeName;
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use lighthouse_network::{MessageAcceptance, MessageId, PeerId};
use network::NetworkBeaconProcessor;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use types::{AttesterSlashing, BeaconState, EthSpec, ForkName, ProposerSlashing};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExpectedOutcome {
    Valid,
    Ignore,
    Reject,
}

impl PartialEq<MessageAcceptance> for ExpectedOutcome {
    fn eq(&self, other: &MessageAcceptance) -> bool {
        matches!(
            (self, other),
            (Self::Valid, MessageAcceptance::Accept)
                | (Self::Ignore, MessageAcceptance::Ignore)
                | (Self::Reject, MessageAcceptance::Reject)
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Meta {
    topic: Topic,
    #[serde(default)]
    messages: Vec<MessageMeta>,
    #[serde(default)]
    bls_setting: Option<BlsSetting>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageMeta {
    message: String,
    expected: ExpectedOutcome,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    subnet_id: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    offset_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Topic {
    ProposerSlashing,
    AttesterSlashing,
    // TODO: add support for these topics
    // VoluntaryExit,
    // BlsToExecutionChange,
    // SyncCommittee,
    // SyncCommitteeContributionAndProof,
    // BeaconBlock,
    // BeaconAttestation,
    // BeaconAggregateAndProof,
}

#[derive(Debug)]
pub struct GossipValidation<E: EthSpec> {
    path: PathBuf,
    meta: Meta,
    state: BeaconState<E>,
}

impl<E: EthSpec> LoadCase for GossipValidation<E> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let meta: Meta = yaml_decode_file(&path.join("meta.yaml"))?;
        let spec = &testing_spec::<E>(fork_name);
        let state = ssz_decode_state(&path.join("state.ssz_snappy"), spec)?;

        Ok(Self {
            path: path.to_path_buf(),
            meta,
            state,
        })
    }
}

impl<E: EthSpec + TypeName> Case for GossipValidation<E> {
    fn description(&self) -> String {
        self.path
            .iter()
            .next_back()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        if let Some(bls_setting) = self.meta.bls_setting {
            bls_setting.check()?;
        }

        let spec = testing_spec::<E>(fork_name);
        let tester = GossipTester::new(self, spec)?;

        for message_meta in &self.meta.messages {
            let actual =
                tester.validate_message(&self.path, &self.meta.topic, message_meta, fork_name)?;

            if message_meta.expected != actual {
                return Err(Error::NotEqual(format!(
                    "{}: expected {:?}, got {:?}{}",
                    self.path.display(),
                    message_meta.expected,
                    actual,
                    message_meta
                        .reason
                        .as_ref()
                        .map(|r| format!(" ({r})"))
                        .unwrap_or_default()
                )));
            }
        }

        Ok(())
    }
}

struct GossipTester<E: EthSpec> {
    network_beacon_processor: Arc<NetworkBeaconProcessor<EphemeralHarnessType<E>>>,
}

impl<E: EthSpec> GossipTester<E> {
    fn new(case: &GossipValidation<E>, spec: ChainSpec) -> Result<Self, Error> {
        let genesis_time = case.state.genesis_time();
        let spec = Arc::new(spec);

        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .spec(spec.clone())
            .keypairs(vec![])
            .genesis_state_ephemeral_store(case.state.clone())
            .mock_execution_layer()
            .recalculate_fork_times_with_genesis(genesis_time)
            .mock_execution_layer_all_payloads_valid()
            .build();

        let network_beacon_processor = NetworkBeaconProcessor::null_from_harness(&harness);

        Ok(Self {
            network_beacon_processor: Arc::new(network_beacon_processor),
        })
    }

    fn validate_message(
        &self,
        path: &Path,
        topic: &Topic,
        message_meta: &MessageMeta,
        fork_name: ForkName,
    ) -> Result<MessageAcceptance, Error> {
        match topic {
            Topic::ProposerSlashing => self.validate_proposer_slashing(path, message_meta),
            Topic::AttesterSlashing => {
                self.validate_attester_slashing(path, message_meta, fork_name)
            }
        }
    }

    fn validate_proposer_slashing(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
    ) -> Result<MessageAcceptance, Error> {
        let slashing: ProposerSlashing =
            ssz_decode_file(&path.join(format!("{}.ssz_snappy", message_meta.message)))?;

        let message_id = MessageId::new(&[]);
        let peer_id = PeerId::random();
        Ok(self
            .network_beacon_processor
            .process_gossip_proposer_slashing(message_id, peer_id, slashing))
    }

    fn validate_attester_slashing(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
        fork_name: ForkName,
    ) -> Result<MessageAcceptance, Error> {
        let ssz_path = path.join(format!("{}.ssz_snappy", message_meta.message));
        let slashing: AttesterSlashing<E> = if fork_name.electra_enabled() {
            ssz_decode_file(&ssz_path).map(AttesterSlashing::Electra)?
        } else {
            ssz_decode_file(&ssz_path).map(AttesterSlashing::Base)?
        };

        let message_id = MessageId::new(&[]);
        let peer_id = PeerId::random();
        Ok(self
            .network_beacon_processor
            .process_gossip_attester_slashing(message_id, peer_id, slashing))
    }
}
