use engine_api::{http::HttpJsonRpc, Error as ApiError, *};
use engines::{Engine, EngineError, Engines};
use sensitive_url::SensitiveUrl;
use slog::Logger;

mod engine_api;
mod engines;

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

pub struct ExecutionLayer<T> {
    engines: Engines<T>,
}

impl ExecutionLayer<HttpJsonRpc> {
    pub fn from_urls(urls: Vec<SensitiveUrl>, log: Logger) -> Result<Self, Error> {
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
        })
    }
}

impl<T: EngineApi> ExecutionLayer<T> {
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
