///! The subnet predicate used for searching for a particular subnet.
use super::*;
use crate::types::{EnrAttestationBitfield, EnrSyncCommitteeBitfield};
use slog::trace;
use std::ops::Deref;

/// Returns the predicate for a given subnet.
pub fn subnet_predicate<TSpec>(
    subnets: Vec<Subnet>,
    log: &slog::Logger,
) -> impl Fn(&Enr) -> bool + Send
where
    TSpec: EthSpec,
{
    let log_clone = log.clone();

    move |enr: &Enr| {
        let attestation_bitfield: EnrAttestationBitfield<TSpec> =
            match enr.attestation_bitfield::<TSpec>() {
                Ok(b) => b,
                Err(_e) => return false,
            };

        // Pre-fork/fork-boundary enrs may not contain a syncnets field.
        // Don't return early here
        let sync_committee_bitfield: Result<EnrSyncCommitteeBitfield<TSpec>, _> =
            enr.sync_committee_bitfield::<TSpec>();

        let predicate = subnets.iter().any(|subnet| match subnet {
            Subnet::Attestation(s) => attestation_bitfield
                .get(*s.deref() as usize)
                .unwrap_or(false),
            Subnet::SyncCommittee(s) => sync_committee_bitfield
                .as_ref()
                .map_or(false, |b| b.get(*s.deref() as usize).unwrap_or(false)),
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
