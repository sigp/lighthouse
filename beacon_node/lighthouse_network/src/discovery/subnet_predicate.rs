//! The subnet predicate used for searching for a particular subnet.
use super::*;
use crate::types::{EnrAttestationBitfield, EnrSyncCommitteeBitfield};
use slog::trace;
use std::ops::Deref;
use types::data_column_custody_group::compute_subnets_for_node;
use types::ChainSpec;

/// Returns the predicate for a given subnet.
pub fn subnet_predicate<E>(
    subnets: Vec<Subnet>,
    log: &slog::Logger,
    spec: Arc<ChainSpec>,
) -> impl Fn(&Enr) -> bool + Send
where
    E: EthSpec,
{
    let log_clone = log.clone();

    move |enr: &Enr| {
        let attestation_bitfield: EnrAttestationBitfield<E> = match enr.attestation_bitfield::<E>()
        {
            Ok(b) => b,
            Err(_e) => return false,
        };

        // Pre-fork/fork-boundary enrs may not contain a syncnets field.
        // Don't return early here.
        let sync_committee_bitfield: Result<EnrSyncCommitteeBitfield<E>, _> =
            enr.sync_committee_bitfield::<E>();

        let predicate = subnets.iter().any(|subnet| match subnet {
            Subnet::Attestation(s) => attestation_bitfield
                .get(*s.deref() as usize)
                .unwrap_or(false),
            Subnet::SyncCommittee(s) => sync_committee_bitfield
                .as_ref()
                .is_ok_and(|b| b.get(*s.deref() as usize).unwrap_or(false)),
            Subnet::DataColumn(s) => {
                if let Ok(custody_group_count) = enr.custody_group_count::<E>(&spec) {
                    compute_subnets_for_node(enr.node_id().raw(), custody_group_count, &spec)
                        .is_ok_and(|subnets| subnets.contains(s))
                } else {
                    false
                }
            }
        });

        if !predicate {
            trace!(
                log_clone,
                "Peer found but not on any of the desired subnets";
                "peer_id" => %enr.peer_id()
            );
        }
        predicate
    }
}
