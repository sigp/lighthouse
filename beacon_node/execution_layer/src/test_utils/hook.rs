use crate::json_structures::*;
use serde_json::Value as JsonValue;

type ForkChoiceUpdatedHook = dyn Fn(
        JsonForkchoiceStateV1,
        Option<JsonPayloadAttributes>,
    ) -> Option<JsonForkchoiceUpdatedV1Response>
    + Send
    + Sync;

type NewPayloadHook = dyn Fn(&str, &JsonValue) + Send + Sync;

#[derive(Default)]
pub struct Hook {
    forkchoice_updated: Option<Box<ForkChoiceUpdatedHook>>,
    new_payload: Option<Box<NewPayloadHook>>,
}

impl Hook {
    pub fn on_forkchoice_updated(
        &self,
        state: JsonForkchoiceStateV1,
        payload_attributes: Option<JsonPayloadAttributes>,
    ) -> Option<JsonForkchoiceUpdatedV1Response> {
        (self.forkchoice_updated.as_ref()?)(state, payload_attributes)
    }

    pub fn set_forkchoice_updated_hook(&mut self, f: Box<ForkChoiceUpdatedHook>) {
        self.forkchoice_updated = Some(f);
    }

    pub fn on_new_payload(&self, method: &str, params: &JsonValue) {
        if let Some(f) = self.new_payload.as_ref() {
            f(method, params)
        }
    }

    pub fn set_new_payload_hook(&mut self, f: Box<NewPayloadHook>) {
        self.new_payload = Some(f);
    }
}
