//! The subnet predicate used for searching for a particular subnet.
use super::*;
use crate::types::{EnrAttestationBitfield, EnrSyncCommitteeBitfield};
use itertools::Itertools;
use slog::trace;
use std::ops::Deref;
use types::DataColumnSubnetId;

/// Returns the predicate for a given subnet.
pub fn subnet_predicate<E>(subnets: Vec<Subnet>, log: &slog::Logger) -> impl Fn(&Enr) -> bool + Send
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

        // Pre-fork/fork-boundary enrs may not contain a peerdas custody field.
        // Don't return early here.
        //
        // NOTE: we could map to minimum custody requirement here.
        let custody_subnet_count: Result<u64, _> = enr.custody_subnet_count::<E>();

        let predicate = subnets.iter().any(|subnet| match subnet {
            Subnet::Attestation(s) => attestation_bitfield
                .get(*s.deref() as usize)
                .unwrap_or(false),
            Subnet::SyncCommittee(s) => sync_committee_bitfield
                .as_ref()
                .map_or(false, |b| b.get(*s.deref() as usize).unwrap_or(false)),
            Subnet::DataColumn(s) => custody_subnet_count.map_or(false, |count| {
                let mut subnets = DataColumnSubnetId::compute_custody_subnets::<E>(
                    enr.node_id().raw().into(),
                    count,
                );
                subnets.contains(s)
            }),
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
