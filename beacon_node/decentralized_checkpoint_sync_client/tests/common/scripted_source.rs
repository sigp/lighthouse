use super::E;
use decentralized_checkpoint_sync_client::{
    LightClientData, LightClientDataSource, RequestLimits, SourceError, SourceErrorKind,
    SourceResponse, SourceResult, UpdateRange,
};
use std::collections::VecDeque;
use types::{Hash256, LightClientBootstrap, LightClientFinalityUpdate, LightClientUpdate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Bootstrap(Hash256),
    Updates(UpdateRange),
    Finality,
}

pub enum Response {
    Bootstrap(Box<LightClientData<LightClientBootstrap<E>>>),
    Updates(Vec<LightClientData<LightClientUpdate<E>>>),
    Finality(Box<LightClientData<LightClientFinalityUpdate<E>>>),
}

pub struct Step {
    pub request: Request,
    pub result: SourceResult<Response>,
}

/// Only the I/O boundary is fake. Scripts may return invalid data for the real core to reject.
pub struct ScriptedSource {
    steps: VecDeque<Step>,
    pub requests: Vec<(Request, RequestLimits)>,
    pub on_request: Option<Box<dyn FnMut() + Send>>,
}

impl ScriptedSource {
    pub fn new(steps: impl IntoIterator<Item = Step>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            requests: vec![],
            on_request: None,
        }
    }

    pub fn assert_finished(&self) {
        assert!(self.steps.is_empty(), "unconsumed source expectations");
    }

    fn take(&mut self, request: Request, limits: RequestLimits) -> SourceResult<Response> {
        self.requests.push((request.clone(), limits));
        let step = self.steps.pop_front().expect("unexpected source request");
        assert_eq!(
            step.request, request,
            "source request does not match script"
        );
        if let Some(on_request) = &mut self.on_request {
            on_request();
        }
        let bytes_received = match &step.result {
            Ok(response) => response.bytes_received,
            Err(error) => error.bytes_received,
        };
        if bytes_received > limits.max_response_bytes() {
            return Err(SourceError {
                kind: SourceErrorKind::ResponseTooLarge {
                    limit: limits.max_response_bytes(),
                },
                bytes_received,
                source: None,
            });
        }
        step.result
    }
}

impl LightClientDataSource<E> for ScriptedSource {
    async fn get_bootstrap(
        &mut self,
        block_root: Hash256,
        limits: RequestLimits,
    ) -> SourceResult<LightClientData<LightClientBootstrap<E>>> {
        let response = self.take(Request::Bootstrap(block_root), limits)?;
        let Response::Bootstrap(data) = response.data else {
            panic!("expected bootstrap response in script");
        };
        Ok(SourceResponse {
            data: *data,
            bytes_received: response.bytes_received,
        })
    }

    async fn get_updates(
        &mut self,
        range: UpdateRange,
        limits: RequestLimits,
    ) -> SourceResult<Vec<LightClientData<LightClientUpdate<E>>>> {
        let response = self.take(Request::Updates(range), limits)?;
        let Response::Updates(data) = response.data else {
            panic!("expected updates response in script");
        };
        Ok(SourceResponse {
            data,
            bytes_received: response.bytes_received,
        })
    }

    async fn get_finality_update(
        &mut self,
        limits: RequestLimits,
    ) -> SourceResult<LightClientData<LightClientFinalityUpdate<E>>> {
        let response = self.take(Request::Finality, limits)?;
        let Response::Finality(data) = response.data else {
            panic!("expected finality response in script");
        };
        Ok(SourceResponse {
            data: *data,
            bytes_received: response.bytes_received,
        })
    }
}
