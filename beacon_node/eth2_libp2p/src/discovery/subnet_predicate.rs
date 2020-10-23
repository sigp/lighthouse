///! The subnet predicate used for searching for a particular subnet.
use super::*;
use slog::trace;
use std::ops::Deref;

/// Returns the predicate for a given subnet.
pub fn subnet_predicate<TSpec>(
    subnet_ids: Vec<SubnetId>,
    log: &slog::Logger,
) -> impl Fn(&Enr) -> bool + Send
where
    TSpec: EthSpec,
{
    let log_clone = log.clone();

    move |enr: &Enr| {
        if let Some(bitfield_bytes) = enr.get(BITFIELD_ENR_KEY) {
            let bitfield = match BitVector::<TSpec::SubnetBitfieldLength>::from_ssz_bytes(
                bitfield_bytes,
            ) {
                Ok(v) => v,
                Err(e) => {
                    warn!(log_clone, "Could not decode ENR bitfield for peer"; "peer_id" => format!("{}", enr.peer_id()), "error" => format!("{:?}", e));
                    return false;
                }
            };

            let matches: Vec<&SubnetId> = subnet_ids
                .iter()
                .filter(|id| bitfield.get(**id.deref() as usize).unwrap_or(false))
                .collect();

            if matches.is_empty() {
                trace!(
                    log_clone,
                    "Peer found but not on any of the desired subnets";
                    "peer_id" => format!("{}", enr.peer_id())
                );
                return false;
            } else {
                trace!(
                   log_clone,
                   "Peer found on desired subnet(s)";
                   "peer_id" => format!("{}", enr.peer_id()),
                   "subnets" => format!("{:?}", matches.as_slice())
                );
                return true;
            }
        }
        false
    }
}
