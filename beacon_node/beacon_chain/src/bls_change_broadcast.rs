use crate::*;
use slot_clock::SlotClock;
use tokio::time::sleep;
use types::EthSpec;

#[allow(dead_code)]
pub async fn bls_change_broadcast<T: BeaconChainTypes>(chain: &BeaconChain<T>) {
    let spec = &chain.spec;
    let slot_clock = &chain.slot_clock;

    let capella_fork_slot = if let Some(epoch) = spec.capella_fork_epoch {
        epoch.start_slot(T::EthSpec::slots_per_epoch())
    } else {
        // Exit now if Capella is not defined.
        return;
    };

    loop {
        match slot_clock.duration_to_slot(capella_fork_slot) {
            Some(duration) => sleep(duration).await,
            None => {
                if chain.slot().map_or(false, |slot| slot >= capella_fork_slot) {
                    // The Capella fork has passed, exit now.
                    return;
                }
                // We were unable to read the slot clock, wait another slot and then try again.
                sleep(slot_clock.slot_duration()).await;
            }
        }

        // It is the start of the Capella fork. We should broadcast any BLS to
        // execution changes already in our op pool.
        todo!();
    }
}
