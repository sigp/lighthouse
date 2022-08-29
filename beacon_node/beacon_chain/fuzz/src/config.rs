use crate::LogConfig;
use std::time::Duration;
use types::ChainSpec;

pub struct Config {
    pub num_honest_nodes: usize,
    pub total_validators: usize,
    pub attacker_validators: usize,
    pub ticks_per_slot: usize,
    pub min_attacker_proposers_per_slot: usize,
    pub max_attacker_proposers_per_slot: usize,
    /// Maximum delay in ticks before each attacker message must reach at least one honest node.
    ///
    /// For example if this is set to 5, then all attacker messages must be broadcast to at least
    /// one honest node 5 ticks after they were created. They may be broadcast sooner.
    ///
    /// Together with `max_delay_difference`, this parameter sets the ranges on message delays:
    ///
    /// - `first_node_delay` in `0..=max_first_node_delay`
    /// - `node_delay` in `first_node_delay..=first_node_delay + max_delay_difference`
    pub max_first_node_delay: usize,
    /// Maxmimum delay in ticks between an attacker message reaching its first honest node and its
    /// last.
    ///
    /// This is meant to simulate network gossip amongst honest nodes, an attacker can't keep a
    /// message secret if the honest nodes gossip it amongst themselves.
    pub max_delay_difference: usize,
    /// Maximum length of re-org that will be tolerated.
    pub max_reorg_length: usize,
    pub debug: DebugConfig,
}

pub struct DebugConfig {
    /// Log the number of hydra heads.
    pub num_hydra_heads: bool,
    /// Log each block proposal as it occurs.
    pub block_proposals: bool,
    /// Log each proposal by the attacker.
    pub attacker_proposals: bool,
    /// Print debug logs to stderr from the perspective of this honest node.
    pub log_perspective: Option<usize>,
}

impl Default for Config {
    fn default() -> Config {
        Config::with_15pc_attacker()
    }
}

impl Default for DebugConfig {
    fn default() -> Self {
        DebugConfig {
            num_hydra_heads: false,
            block_proposals: false,
            attacker_proposals: false,
            log_perspective: None,
        }
    }
}

impl Config {
    pub fn with_10pc_attacker() -> Self {
        let ticks_per_slot = 3;
        let slots_per_epoch = 8;
        Config {
            num_honest_nodes: 3,
            total_validators: 60,
            attacker_validators: 6,
            ticks_per_slot,
            min_attacker_proposers_per_slot: 0,
            max_attacker_proposers_per_slot: 4,
            max_first_node_delay: 2 * slots_per_epoch * ticks_per_slot,
            max_delay_difference: ticks_per_slot,
            max_reorg_length: 8,
            debug: DebugConfig::default(),
        }
    }

    pub fn with_15pc_attacker() -> Self {
        Config {
            num_honest_nodes: 3,
            attacker_validators: 9,
            ..Config::with_10pc_attacker()
        }
    }

    pub fn with_33pc_attacker() -> Self {
        Config {
            num_honest_nodes: 4,
            attacker_validators: 20,
            ..Config::with_10pc_attacker()
        }
    }

    pub fn with_50pc_attacker() -> Self {
        Config {
            num_honest_nodes: 3,
            attacker_validators: 30,
            ..Config::with_10pc_attacker()
        }
    }

    pub fn is_valid(&self) -> bool {
        self.ticks_per_slot % 3 == 0
            && self.honest_validators() % self.num_honest_nodes == 0
            && self.max_attacker_proposers_per_slot >= self.min_attacker_proposers_per_slot
            && self
                .debug
                .log_perspective
                .map_or(true, |i| i < self.num_honest_nodes)
    }

    pub fn log_config(&self, node_index: usize) -> LogConfig {
        LogConfig {
            max_reorg_length: Some(self.max_reorg_length),
            forward_logs: self.debug.log_perspective == Some(node_index),
            ..LogConfig::default()
        }
    }

    pub fn attacker_log_config(&self) -> LogConfig {
        // Allow the attacker to re-org themself. They'll process their local blocks before the rest
        // of the network with proposer boost.
        LogConfig {
            max_reorg_length: None,
            ..LogConfig::default()
        }
    }

    pub fn honest_validators(&self) -> usize {
        self.total_validators - self.attacker_validators
    }

    pub fn honest_validators_per_node(&self) -> usize {
        self.honest_validators() / self.num_honest_nodes
    }

    pub fn attestation_tick(&self) -> usize {
        self.ticks_per_slot / 3
    }

    pub fn is_block_proposal_tick(&self, tick: usize) -> bool {
        tick % self.ticks_per_slot == 0 && tick != 0
    }

    pub fn is_attestation_tick(&self, tick: usize) -> bool {
        tick % self.ticks_per_slot == self.attestation_tick()
    }

    pub fn min_attacker_proposers(&self, available: usize) -> Option<u32> {
        Some(std::cmp::min(self.min_attacker_proposers_per_slot, available) as u32)
    }

    pub fn max_attacker_proposers(&self, available: usize) -> Option<u32> {
        Some(std::cmp::min(self.max_attacker_proposers_per_slot, available) as u32)
    }

    pub fn tick_duration(&self, spec: &ChainSpec) -> Duration {
        Duration::from_secs(spec.seconds_per_slot) / self.ticks_per_slot as u32
    }
}
