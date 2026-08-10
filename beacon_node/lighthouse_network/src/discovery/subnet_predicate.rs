//! The subnet predicate used for searching for a particular subnet.
use super::*;
use crate::types::{EnrAttestationBitfield, EnrSyncCommitteeBitfield};
use std::ops::Deref;
use tracing::trace;
use types::ChainSpec;
use types::data::compute_subnets_for_node;

/// Returns the predicate for a given subnet.
pub fn subnet_predicate(
    subnets: Vec<Subnet>,
    spec: Arc<ChainSpec>,
) -> impl Fn(&Enr) -> bool + Send {
    move |enr: &Enr| {
        let attestation_bitfield: EnrAttestationBitfield = match enr.attestation_bitfield() {
            Ok(b) => b,
            Err(_e) => return false,
        };

        // Pre-fork/fork-boundary enrs may not contain a syncnets field.
        // Don't return early here.
        let sync_committee_bitfield: Result<EnrSyncCommitteeBitfield, _> =
            enr.sync_committee_bitfield();

        let predicate = subnets.iter().any(|subnet| match subnet {
            Subnet::Attestation(s) => attestation_bitfield
                .get(*s.deref() as usize)
                .unwrap_or(false),
            Subnet::SyncCommittee(s) => sync_committee_bitfield
                .as_ref()
                .is_ok_and(|b| b.get(*s.deref() as usize).unwrap_or(false)),
            Subnet::DataColumn(s) => {
                if let Ok(custody_group_count) = enr.custody_group_count(&spec) {
                    compute_subnets_for_node(enr.node_id().raw(), custody_group_count, &spec)
                        .is_ok_and(|subnets| subnets.contains(s))
                } else {
                    false
                }
            }
        });

        if !predicate {
            trace!(
                peer_id = %enr.peer_id(),
                "Peer found but not on any of the desired subnets"
            );
        }
        predicate
    }
}
