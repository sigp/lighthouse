use crate::SlotClock;
use lazy_static::lazy_static;
pub use lighthouse_metrics::*;
use types::{EthSpec, Slot};

lazy_static! {
    pub static ref PRESENT_SLOT: Result<IntGauge> =
        try_create_int_gauge("slotclock_present_slot", "The present wall-clock slot");
    pub static ref PRESENT_EPOCH: Result<IntGauge> =
        try_create_int_gauge("slotclock_present_epoch", "The present wall-clock epoch");
    pub static ref SLOTS_PER_EPOCH: Result<IntGauge> =
        try_create_int_gauge("slotclock_slots_per_epoch", "Slots per epoch (constant)");
    pub static ref SECONDS_PER_SLOT: Result<IntGauge> = try_create_int_gauge(
        "slotclock_slot_time_seconds",
        "The duration in seconds between each slot"
    );
}

/// Update the global metrics `DEFAULT_REGISTRY` with info from the slot clock.
pub fn scrape_for_metrics<E: EthSpec, U: SlotClock>(clock: &U) {
    let present_slot = match clock.now() {
        Some(slot) => slot,
        _ => Slot::new(0),
    };

    set_gauge(&PRESENT_SLOT, present_slot.as_u64() as i64);
    set_gauge(
        &PRESENT_EPOCH,
        present_slot.epoch(E::slots_per_epoch()).as_u64() as i64,
    );
    set_gauge(&SLOTS_PER_EPOCH, E::slots_per_epoch() as i64);
    set_gauge(&SECONDS_PER_SLOT, clock.slot_duration().as_secs() as i64);
}
