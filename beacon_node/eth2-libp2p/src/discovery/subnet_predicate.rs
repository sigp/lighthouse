///! The subnet predicate used for searching for a particular subnet.
use super::*;

/// Returns the predicate for a given subnet.
pub fn subnet_predicate<TSpec>(
    subnet_id: SubnetId,
    log: &slog::Logger,
) -> impl Fn(&Enr) -> bool + Send + 'static + Clone
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

            return bitfield.get(*subnet_id as usize).unwrap_or_else(|_| {
                                   debug!(log_clone, "Peer found but not on desired subnet"; "peer_id" => format!("{}", enr.peer_id()));
                false
            });
        }
        false
    }
}
