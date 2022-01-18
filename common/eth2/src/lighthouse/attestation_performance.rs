use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use types::Epoch;

#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
pub struct AttestationPerformanceStatistics {
    pub active: bool,
    pub head: bool,
    pub target: bool,
    pub source: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay: Option<u64>,
}

#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
pub struct AttestationPerformance {
    pub index: u64,
    pub epochs: HashMap<u64, AttestationPerformanceStatistics>,
}

impl AttestationPerformance {
    pub fn initialize(indices: Vec<u64>) -> Vec<Self> {
        let mut vec = Vec::with_capacity(indices.len());
        for index in indices {
            vec.push(Self {
                index,
                ..Default::default()
            })
        }
        vec
    }
}

/// Query parameters for the `/lighthouse/analysis/attestation_performance` endpoint.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct AttestationPerformanceQuery {
    pub start_epoch: Epoch,
    pub end_epoch: Epoch,
}
