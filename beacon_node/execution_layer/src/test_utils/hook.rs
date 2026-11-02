use crate::engine_api::PayloadAttributes;
use crate::engines::ForkchoiceState;
use crate::json_structures::*;

type ForkChoiceUpdatedHook = dyn Fn(ForkchoiceState, Option<PayloadAttributes>) -> Option<JsonForkchoiceUpdatedV1Response>
    + Send
    + Sync;

#[derive(Default)]
pub struct Hook {
    forkchoice_updated: Option<Box<ForkChoiceUpdatedHook>>,
}

impl Hook {
    pub fn on_forkchoice_updated(
        &self,
        state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Option<JsonForkchoiceUpdatedV1Response> {
        (self.forkchoice_updated.as_ref()?)(state, payload_attributes)
    }

    pub fn set_forkchoice_updated_hook(&mut self, f: Box<ForkChoiceUpdatedHook>) {
        self.forkchoice_updated = Some(f);
    }
}
