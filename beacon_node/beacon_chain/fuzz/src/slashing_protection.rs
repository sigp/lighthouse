use std::cmp::max;
use std::collections::HashMap;
use types::Epoch;

/// Simple in-memory slashing protection for a group of validators.
#[derive(Debug, Default)]
pub struct SlashingProtection {
    pub validators: HashMap<usize, Watermark>,
}

#[derive(Debug, Default)]
pub struct Watermark {
    pub max_source_epoch: Epoch,
    pub max_target_epoch: Epoch,
}

impl SlashingProtection {
    pub fn can_attest(&self, validator: usize, source_epoch: Epoch, target_epoch: Epoch) -> bool {
        self.validators.get(&validator).map_or(true, |w| {
            source_epoch >= w.max_source_epoch && target_epoch > w.max_target_epoch
        })
    }

    pub fn record_attestation(
        &mut self,
        validator: usize,
        source_epoch: Epoch,
        target_epoch: Epoch,
    ) {
        let entry = self.validators.entry(validator).or_default();
        entry.max_source_epoch = max(source_epoch, entry.max_source_epoch);
        entry.max_target_epoch = max(target_epoch, entry.max_target_epoch);
    }
}
