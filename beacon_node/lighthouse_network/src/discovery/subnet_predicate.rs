//! The subnet predicate used for searching for a particular subnet.
use super::*;
use crate::types::{EnrAttestationBitfield, EnrSyncCommitteeBitfield};
use itertools::Itertools;
use slog::trace;
use std::ops::Deref;
use types::{ChainSpec, DataColumnSubnetId};

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

        // TODO(das): compute from enr
        let custody_subnet_count = spec.custody_requirement;

        let predicate = subnets.iter().any(|subnet| match subnet {
            Subnet::Attestation(s) => attestation_bitfield
                .get(*s.deref() as usize)
                .unwrap_or(false),
            Subnet::SyncCommittee(s) => sync_committee_bitfield
                .as_ref()
                .map_or(false, |b| b.get(*s.deref() as usize).unwrap_or(false)),
            Subnet::DataColumn(s) => {
                let mut subnets = DataColumnSubnetId::compute_custody_subnets::<E>(
                    enr.node_id().raw().into(),
                    custody_subnet_count,
                    &spec,
                );
                subnets.contains(s)
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
