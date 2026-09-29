use std::iter;
use std::time::Duration;
use types::{ChainSpec, EthSpec, Slot};

#[derive(Debug, Clone, Copy, PartialEq)]
struct SlotEra {
    start_slot: Slot,
    start_time: Duration,
    slot_duration: Duration,
}

impl SlotEra {
    fn start_of(&self, slot: Slot) -> Option<Duration> {
        let slots: u32 = slot
            .as_u64()
            .checked_sub(self.start_slot.as_u64())?
            .try_into()
            .ok()?;
        self.start_time
            .checked_add(self.slot_duration.checked_mul(slots)?)
    }
}

/// The mapping between wall-clock time and slots, as a sequence of eras with fixed slot durations.
#[derive(Debug, Clone, PartialEq)]
pub struct SlotTimeline {
    genesis: SlotEra,
    later_eras: Vec<SlotEra>,
}

impl SlotTimeline {
    pub fn new(genesis_slot: Slot, genesis_duration: Duration, slot_duration: Duration) -> Self {
        Self {
            genesis: SlotEra {
                start_slot: genesis_slot,
                start_time: genesis_duration,
                slot_duration,
            },
            later_eras: vec![],
        }
    }

    pub fn from_spec<E: EthSpec>(genesis_duration: Duration, spec: &ChainSpec) -> Self {
        let mut eras: Vec<_> = spec
            .slot_duration_eras()
            .map(|(epoch, slot_duration_ms)| {
                (
                    epoch.start_slot(E::slots_per_epoch()),
                    Duration::from_millis(slot_duration_ms),
                )
            })
            .collect();
        eras.reverse();

        let mut timeline = Self::new(
            spec.genesis_slot,
            genesis_duration,
            spec.get_slot_duration(),
        );
        for (start_slot, slot_duration) in eras {
            timeline.push_era(start_slot, slot_duration);
        }
        timeline
    }

    fn push_era(&mut self, start_slot: Slot, slot_duration: Duration) {
        if start_slot <= self.genesis.start_slot {
            self.genesis.slot_duration = slot_duration;
            return;
        }
        let previous = self.later_eras.last().copied().unwrap_or(self.genesis);
        if start_slot <= previous.start_slot {
            return;
        }
        if let Some(start_time) = previous.start_of(start_slot) {
            self.later_eras.push(SlotEra {
                start_slot,
                start_time,
                slot_duration,
            });
        }
    }

    fn eras_descending(&self) -> impl Iterator<Item = &SlotEra> {
        self.later_eras
            .iter()
            .rev()
            .chain(iter::once(&self.genesis))
    }

    fn era_for_slot(&self, slot: Slot) -> &SlotEra {
        self.eras_descending()
            .find(|era| slot >= era.start_slot)
            .unwrap_or(&self.genesis)
    }

    pub fn genesis_slot(&self) -> Slot {
        self.genesis.start_slot
    }

    pub fn genesis_duration(&self) -> Duration {
        self.genesis.start_time
    }

    pub fn slot_duration_at(&self, slot: Slot) -> Duration {
        self.era_for_slot(slot).slot_duration
    }

    pub fn min_slot_duration(&self) -> Duration {
        self.eras_descending()
            .map(|era| era.slot_duration)
            .min()
            .unwrap_or(self.genesis.slot_duration)
    }

    pub fn start_of(&self, slot: Slot) -> Option<Duration> {
        if slot < self.genesis.start_slot {
            return None;
        }
        self.era_for_slot(slot).start_of(slot)
    }

    pub fn slot_of(&self, now: Duration) -> Option<Slot> {
        let era = self.eras_descending().find(|era| now >= era.start_time)?;
        let since_era_start = now.checked_sub(era.start_time)?;
        let slots = (since_era_start.as_millis() / era.slot_duration.as_millis()) as u64;
        Some(era.start_slot + slots)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ManualSlotClock, SlotClock};
    use types::{Epoch, MainnetEthSpec, SlotDurationSchedule, SlotDurationScheduleEntry};

    const GENESIS: Duration = Duration::from_secs(1_606_824_023);

    fn spec_with_schedule(entries: &[(u64, u64)]) -> ChainSpec {
        let schedule = SlotDurationSchedule::new(
            entries
                .iter()
                .map(|&(epoch, slot_duration_ms)| SlotDurationScheduleEntry {
                    epoch: Epoch::new(epoch),
                    slot_duration_ms,
                })
                .collect(),
        );
        ChainSpec::mainnet().set_slot_duration_schedule::<MainnetEthSpec>(schedule)
    }

    fn multi_era_spec() -> ChainSpec {
        spec_with_schedule(&[(0, 12000), (10, 10000), (20, 6000)])
    }

    #[test]
    fn single_era_spec_matches_fixed_duration() {
        let spec = ChainSpec::mainnet();
        assert_eq!(
            SlotTimeline::from_spec::<MainnetEthSpec>(GENESIS, &spec),
            SlotTimeline::new(Slot::new(0), GENESIS, Duration::from_secs(12))
        );
    }

    #[test]
    fn timeline_matches_spec_time_functions() {
        let spec = multi_era_spec();
        let timeline = SlotTimeline::from_spec::<MainnetEthSpec>(GENESIS, &spec);
        let genesis_ms = GENESIS.as_millis() as u64;
        for slot in (0..1024).map(Slot::new) {
            let spec_start_ms = spec
                .compute_time_at_slot_ms::<MainnetEthSpec>(genesis_ms, slot)
                .unwrap();
            let start = timeline.start_of(slot).unwrap();
            assert_eq!(start, Duration::from_millis(spec_start_ms), "slot {slot}");
            assert_eq!(timeline.slot_of(start), Some(slot), "slot {slot}");
            let next_start = timeline.start_of(slot + 1).unwrap();
            assert_eq!(
                timeline.slot_of(next_start - Duration::from_millis(1)),
                Some(slot),
                "slot {slot}"
            );
            assert_eq!(
                spec.compute_slot_at_time_ms::<MainnetEthSpec>(
                    genesis_ms,
                    next_start.as_millis() as u64 - 1
                ),
                Ok(slot),
                "slot {slot}"
            );
            assert_eq!(
                timeline.slot_duration_at(slot),
                Duration::from_millis(
                    spec.get_slot_duration_ms(slot.epoch(MainnetEthSpec::slots_per_epoch()))
                ),
                "slot {slot}"
            );
        }
        assert_eq!(timeline.slot_of(GENESIS - Duration::from_millis(1)), None);
        assert_eq!(timeline.min_slot_duration(), Duration::from_secs(6));
    }

    #[test]
    fn clock_follows_slot_duration_changes() {
        let timeline = SlotTimeline::from_spec::<MainnetEthSpec>(GENESIS, &multi_era_spec());
        let clock = ManualSlotClock::from_timeline(timeline);

        clock.set_slot(319);
        assert_eq!(clock.slot_duration(), Duration::from_secs(12));
        assert_eq!(clock.duration_to_next_slot(), Some(Duration::from_secs(12)));

        clock.advance_slot();
        assert_eq!(clock.now(), Some(Slot::new(320)));
        assert_eq!(clock.slot_duration(), Duration::from_secs(10));
        assert_eq!(
            clock.slot_duration_at(Slot::new(319)),
            Duration::from_secs(12)
        );

        clock.advance_time(Duration::from_millis(12_500));
        assert_eq!(clock.now(), Some(Slot::new(321)));
        assert_eq!(
            clock.millis_from_current_slot_start(),
            Some(Duration::from_millis(2_500))
        );
        assert_eq!(
            clock.seconds_from_current_slot_start(),
            Some(Duration::from_secs(2))
        );

        clock.set_slot(630);
        assert_eq!(
            clock.duration_to_next_epoch(MainnetEthSpec::slots_per_epoch()),
            Some(Duration::from_secs(100))
        );

        clock.set_slot(640);
        assert_eq!(clock.slot_duration(), Duration::from_secs(6));
        clock.advance_time(Duration::from_secs(6));
        assert_eq!(clock.now(), Some(Slot::new(641)));

        let frozen = clock.freeze_at(clock.start_of(Slot::new(700)).unwrap());
        assert_eq!(frozen.now(), Some(Slot::new(700)));
        assert_eq!(frozen.timeline(), clock.timeline());
    }

    #[test]
    fn schedule_at_genesis_sets_genesis_duration() {
        let timeline =
            SlotTimeline::from_spec::<MainnetEthSpec>(GENESIS, &spec_with_schedule(&[(0, 6000)]));
        assert_eq!(
            timeline,
            SlotTimeline::new(Slot::new(0), GENESIS, Duration::from_secs(6))
        );
    }
}
