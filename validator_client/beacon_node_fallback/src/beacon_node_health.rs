use super::CandidateError;
use eth2::BeaconNodeHttpClient;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use slog::{warn, Logger};
use std::cmp::Ordering;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use types::Slot;

/// Sync distances between 0 and DEFAULT_SYNC_TOLERANCE are considered `synced`.
/// Sync distance tiers are determined by the different modifiers.
///
/// The default range is the following:
/// Synced: 0..=8
/// Small: 9..=16
/// Medium: 17..=64
/// Large: 65..
const DEFAULT_SYNC_TOLERANCE: Slot = Slot::new(8);
const DEFAULT_SMALL_SYNC_DISTANCE_MODIFIER: Slot = Slot::new(8);
const DEFAULT_MEDIUM_SYNC_DISTANCE_MODIFIER: Slot = Slot::new(48);

type HealthTier = u8;
type SyncDistance = Slot;

/// Helpful enum which is used when pattern matching to determine health tier.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum SyncDistanceTier {
    Synced,
    Small,
    Medium,
    Large,
}

/// Contains the different sync distance tiers which are determined at runtime by the
/// `beacon-nodes-sync-tolerances` flag.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct BeaconNodeSyncDistanceTiers {
    pub synced: SyncDistance,
    pub small: SyncDistance,
    pub medium: SyncDistance,
}

impl Default for BeaconNodeSyncDistanceTiers {
    fn default() -> Self {
        Self {
            synced: DEFAULT_SYNC_TOLERANCE,
            small: DEFAULT_SYNC_TOLERANCE + DEFAULT_SMALL_SYNC_DISTANCE_MODIFIER,
            medium: DEFAULT_SYNC_TOLERANCE
                + DEFAULT_SMALL_SYNC_DISTANCE_MODIFIER
                + DEFAULT_MEDIUM_SYNC_DISTANCE_MODIFIER,
        }
    }
}

impl FromStr for BeaconNodeSyncDistanceTiers {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let values: (u64, u64, u64) = s
            .split(',')
            .map(|s| {
                s.parse()
                    .map_err(|e| format!("Invalid sync distance modifier: {e:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect_tuple()
            .ok_or("Invalid number of sync distance modifiers".to_string())?;

        Ok(BeaconNodeSyncDistanceTiers {
            synced: Slot::new(values.0),
            small: Slot::new(values.0 + values.1),
            medium: Slot::new(values.0 + values.1 + values.2),
        })
    }
}

impl BeaconNodeSyncDistanceTiers {
    /// Takes a given sync distance and determines its tier based on the `sync_tolerance` defined by
    /// the CLI.
    pub fn compute_distance_tier(&self, distance: SyncDistance) -> SyncDistanceTier {
        if distance <= self.synced {
            SyncDistanceTier::Synced
        } else if distance <= self.small {
            SyncDistanceTier::Small
        } else if distance <= self.medium {
            SyncDistanceTier::Medium
        } else {
            SyncDistanceTier::Large
        }
    }
}

/// Execution Node health metrics.
///
/// Currently only considers `el_offline`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum ExecutionEngineHealth {
    Healthy,
    Unhealthy,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum IsOptimistic {
    Yes,
    No,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct BeaconNodeHealthTier {
    pub tier: HealthTier,
    pub sync_distance: SyncDistance,
    pub distance_tier: SyncDistanceTier,
}

impl Display for BeaconNodeHealthTier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Tier{}({})", self.tier, self.sync_distance)
    }
}

impl Ord for BeaconNodeHealthTier {
    fn cmp(&self, other: &Self) -> Ordering {
        let ordering = self.tier.cmp(&other.tier);
        if ordering == Ordering::Equal {
            if self.distance_tier == SyncDistanceTier::Synced {
                // Don't tie-break on sync distance in these cases.
                // This ensures validator clients don't artificially prefer one node.
                ordering
            } else {
                self.sync_distance.cmp(&other.sync_distance)
            }
        } else {
            ordering
        }
    }
}

impl PartialOrd for BeaconNodeHealthTier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl BeaconNodeHealthTier {
    pub fn new(
        tier: HealthTier,
        sync_distance: SyncDistance,
        distance_tier: SyncDistanceTier,
    ) -> Self {
        Self {
            tier,
            sync_distance,
            distance_tier,
        }
    }
}

/// Beacon Node Health metrics.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct BeaconNodeHealth {
    // The index of the Beacon Node. This should correspond with its position in the
    // `--beacon-nodes` list. Note that the `user_index` field is used to tie-break nodes with the
    // same health so that nodes with a lower index are preferred.
    pub user_index: usize,
    // The slot number of the head.
    pub head: Slot,
    // Whether the node is optimistically synced.
    pub optimistic_status: IsOptimistic,
    // The status of the nodes connected Execution Engine.
    pub execution_status: ExecutionEngineHealth,
    // The overall health tier of the Beacon Node. Used to rank the nodes for the purposes of
    // fallbacks.
    pub health_tier: BeaconNodeHealthTier,
}

impl Ord for BeaconNodeHealth {
    fn cmp(&self, other: &Self) -> Ordering {
        let ordering = self.health_tier.cmp(&other.health_tier);
        if ordering == Ordering::Equal {
            // Tie-break node health by `user_index`.
            self.user_index.cmp(&other.user_index)
        } else {
            ordering
        }
    }
}

impl PartialOrd for BeaconNodeHealth {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl BeaconNodeHealth {
    pub fn from_status(
        user_index: usize,
        sync_distance: Slot,
        head: Slot,
        optimistic_status: IsOptimistic,
        execution_status: ExecutionEngineHealth,
        distance_tiers: &BeaconNodeSyncDistanceTiers,
    ) -> Self {
        let health_tier = BeaconNodeHealth::compute_health_tier(
            sync_distance,
            optimistic_status,
            execution_status,
            distance_tiers,
        );

        Self {
            user_index,
            head,
            optimistic_status,
            execution_status,
            health_tier,
        }
    }

    pub fn get_index(&self) -> usize {
        self.user_index
    }

    pub fn get_health_tier(&self) -> BeaconNodeHealthTier {
        self.health_tier
    }

    fn compute_health_tier(
        sync_distance: SyncDistance,
        optimistic_status: IsOptimistic,
        execution_status: ExecutionEngineHealth,
        sync_distance_tiers: &BeaconNodeSyncDistanceTiers,
    ) -> BeaconNodeHealthTier {
        let sync_distance_tier = sync_distance_tiers.compute_distance_tier(sync_distance);
        let health = (sync_distance_tier, optimistic_status, execution_status);

        match health {
            (SyncDistanceTier::Synced, IsOptimistic::No, ExecutionEngineHealth::Healthy) => {
                BeaconNodeHealthTier::new(1, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Small, IsOptimistic::No, ExecutionEngineHealth::Healthy) => {
                BeaconNodeHealthTier::new(2, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Synced, IsOptimistic::No, ExecutionEngineHealth::Unhealthy) => {
                BeaconNodeHealthTier::new(3, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Medium, IsOptimistic::No, ExecutionEngineHealth::Healthy) => {
                BeaconNodeHealthTier::new(4, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Synced, IsOptimistic::Yes, ExecutionEngineHealth::Healthy) => {
                BeaconNodeHealthTier::new(5, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Synced, IsOptimistic::Yes, ExecutionEngineHealth::Unhealthy) => {
                BeaconNodeHealthTier::new(6, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Small, IsOptimistic::No, ExecutionEngineHealth::Unhealthy) => {
                BeaconNodeHealthTier::new(7, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Small, IsOptimistic::Yes, ExecutionEngineHealth::Healthy) => {
                BeaconNodeHealthTier::new(8, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Small, IsOptimistic::Yes, ExecutionEngineHealth::Unhealthy) => {
                BeaconNodeHealthTier::new(9, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Large, IsOptimistic::No, ExecutionEngineHealth::Healthy) => {
                BeaconNodeHealthTier::new(10, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Medium, IsOptimistic::No, ExecutionEngineHealth::Unhealthy) => {
                BeaconNodeHealthTier::new(11, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Medium, IsOptimistic::Yes, ExecutionEngineHealth::Healthy) => {
                BeaconNodeHealthTier::new(12, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Medium, IsOptimistic::Yes, ExecutionEngineHealth::Unhealthy) => {
                BeaconNodeHealthTier::new(13, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Large, IsOptimistic::No, ExecutionEngineHealth::Unhealthy) => {
                BeaconNodeHealthTier::new(14, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Large, IsOptimistic::Yes, ExecutionEngineHealth::Healthy) => {
                BeaconNodeHealthTier::new(15, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Large, IsOptimistic::Yes, ExecutionEngineHealth::Unhealthy) => {
                BeaconNodeHealthTier::new(16, sync_distance, sync_distance_tier)
            }
        }
    }
}

pub async fn check_node_health(
    beacon_node: &BeaconNodeHttpClient,
    log: &Logger,
) -> Result<(Slot, bool, bool), CandidateError> {
    let resp = match beacon_node.get_node_syncing().await {
        Ok(resp) => resp,
        Err(e) => {
            warn!(
                log,
                "Unable connect to beacon node";
                "error" => %e
            );

            return Err(CandidateError::Offline);
        }
    };

    Ok((
        resp.data.head_slot,
        resp.data.is_optimistic,
        resp.data.el_offline,
    ))
}

#[cfg(test)]
mod tests {
    use super::ExecutionEngineHealth::{Healthy, Unhealthy};
    use super::{
        BeaconNodeHealth, BeaconNodeHealthTier, BeaconNodeSyncDistanceTiers, IsOptimistic,
        SyncDistanceTier,
    };
    use crate::Config;
    use std::str::FromStr;
    use types::Slot;

    #[test]
    fn all_possible_health_tiers() {
        let config = Config::default();
        let beacon_node_sync_distance_tiers = config.sync_tolerances;

        let mut health_vec = vec![];

        for head_slot in 0..=64 {
            for optimistic_status in &[IsOptimistic::No, IsOptimistic::Yes] {
                for ee_health in &[Healthy, Unhealthy] {
                    let health = BeaconNodeHealth::from_status(
                        0,
                        Slot::new(0),
                        Slot::new(head_slot),
                        *optimistic_status,
                        *ee_health,
                        &beacon_node_sync_distance_tiers,
                    );
                    health_vec.push(health);
                }
            }
        }

        for health in health_vec {
            let health_tier = health.get_health_tier();
            let tier = health_tier.tier;
            let distance = health_tier.sync_distance;

            let distance_tier = beacon_node_sync_distance_tiers.compute_distance_tier(distance);

            // Check sync distance.
            if [1, 3, 5, 6].contains(&tier) {
                assert!(distance_tier == SyncDistanceTier::Synced)
            } else if [2, 7, 8, 9].contains(&tier) {
                assert!(distance_tier == SyncDistanceTier::Small);
            } else if [4, 11, 12, 13].contains(&tier) {
                assert!(distance_tier == SyncDistanceTier::Medium);
            } else {
                assert!(distance_tier == SyncDistanceTier::Large);
            }

            // Check optimistic status.
            if [1, 2, 3, 4, 7, 10, 11, 14].contains(&tier) {
                assert_eq!(health.optimistic_status, IsOptimistic::No);
            } else {
                assert_eq!(health.optimistic_status, IsOptimistic::Yes);
            }

            // Check execution health.
            if [3, 6, 7, 9, 11, 13, 14, 16].contains(&tier) {
                assert_eq!(health.execution_status, Unhealthy);
            } else {
                assert_eq!(health.execution_status, Healthy);
            }
        }
    }

    fn new_distance_tier(
        distance: u64,
        distance_tiers: &BeaconNodeSyncDistanceTiers,
    ) -> BeaconNodeHealthTier {
        BeaconNodeHealth::compute_health_tier(
            Slot::new(distance),
            IsOptimistic::No,
            Healthy,
            distance_tiers,
        )
    }

    #[test]
    fn sync_tolerance_default() {
        let distance_tiers = BeaconNodeSyncDistanceTiers::default();

        let synced_low = new_distance_tier(0, &distance_tiers);
        let synced_high = new_distance_tier(8, &distance_tiers);

        let small_low = new_distance_tier(9, &distance_tiers);
        let small_high = new_distance_tier(16, &distance_tiers);

        let medium_low = new_distance_tier(17, &distance_tiers);
        let medium_high = new_distance_tier(64, &distance_tiers);
        let large = new_distance_tier(65, &distance_tiers);

        assert_eq!(synced_low.tier, 1);
        assert_eq!(synced_high.tier, 1);
        assert_eq!(small_low.tier, 2);
        assert_eq!(small_high.tier, 2);
        assert_eq!(medium_low.tier, 4);
        assert_eq!(medium_high.tier, 4);
        assert_eq!(large.tier, 10);
    }

    #[test]
    fn sync_tolerance_from_str() {
        // String should set the tiers as:
        // synced: 0..=4
        // small: 5..=8
        // medium 9..=12
        // large: 13..

        let distance_tiers = BeaconNodeSyncDistanceTiers::from_str("4,4,4").unwrap();

        let synced_low = new_distance_tier(0, &distance_tiers);
        let synced_high = new_distance_tier(4, &distance_tiers);

        let small_low = new_distance_tier(5, &distance_tiers);
        let small_high = new_distance_tier(8, &distance_tiers);

        let medium_low = new_distance_tier(9, &distance_tiers);
        let medium_high = new_distance_tier(12, &distance_tiers);

        let large = new_distance_tier(13, &distance_tiers);

        assert_eq!(synced_low.tier, 1);
        assert_eq!(synced_high.tier, 1);
        assert_eq!(small_low.tier, 2);
        assert_eq!(small_high.tier, 2);
        assert_eq!(medium_low.tier, 4);
        assert_eq!(medium_high.tier, 4);
        assert_eq!(large.tier, 10);
    }
}
