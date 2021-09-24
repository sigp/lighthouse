use engine_api::{Error as ApiError, *};
use engines::{Engine, EngineError, Engines};
use sensitive_url::SensitiveUrl;
use slog::Logger;
use task_executor::TaskExecutor;

pub use engine_api::http::HttpJsonRpc;

mod engine_api;
mod engines;
pub mod test_utils;

#[derive(Debug)]
pub enum Error {
    ApiError(ApiError),
    EngineErrors(Vec<EngineError>),
}

impl From<ApiError> for Error {
    fn from(e: ApiError) -> Self {
        Error::ApiError(e)
    }
}

pub struct ExecutionLayer {
    engines: Engines<HttpJsonRpc>,
    /// Allows callers to execute async tasks in a non-async environment, if they desire.
    pub executor: TaskExecutor,
}

impl ExecutionLayer {
    pub fn from_urls(
        urls: Vec<SensitiveUrl>,
        executor: TaskExecutor,
        log: Logger,
    ) -> Result<Self, Error> {
        let engines = urls
            .into_iter()
            .map(|url| {
                let id = url.to_string();
                let api = HttpJsonRpc::new(url)?;
                Ok(Engine::new(id, api))
            })
            .collect::<Result<_, ApiError>>()?;

        Ok(Self {
            engines: Engines { engines, log },
            executor,
        })
    }
}

impl ExecutionLayer {
    pub async fn prepare_payload(
        &self,
        parent_hash: Hash256,
        timestamp: u64,
        random: Hash256,
        fee_recipient: Address,
    ) -> Result<PayloadId, Error> {
        self.engines
            .first_success(|engine| {
                engine
                    .api
                    .prepare_payload(parent_hash, timestamp, random, fee_recipient)
            })
            .await
            .map_err(Error::EngineErrors)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
