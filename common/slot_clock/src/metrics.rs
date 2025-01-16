use crate::SlotClock;
pub use metrics::*;
use std::sync::LazyLock;
use types::{EthSpec, Slot};

pub static PRESENT_SLOT: LazyLock<Result<IntGauge>> =
    LazyLock::new(|| try_create_int_gauge("slotclock_present_slot", "The present wall-clock slot"));
pub static PRESENT_EPOCH: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge("slotclock_present_epoch", "The present wall-clock epoch")
});
pub static SLOTS_PER_EPOCH: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge("slotclock_slots_per_epoch", "Slots per epoch (constant)")
});
pub static SECONDS_PER_SLOT: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "slotclock_slot_time_seconds",
        "The duration in seconds between each slot",
    )
});

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
