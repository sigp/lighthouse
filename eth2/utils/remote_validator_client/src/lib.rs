use bls::PublicKey;
use futures::{future, Future, IntoFuture};
use remote_beacon_node::ValidatorResponse;
use reqwest::{
    r#async::{Client, ClientBuilder, Response},
    StatusCode,
};
use rest_api_vc::{AddValidatorRequest, ValidatorRequest};
use serde::{de::DeserializeOwned, Serialize};
use std::marker::PhantomData;
use std::path::PathBuf;
use std::time::Duration;
use types::EthSpec;
use url::Url;

pub const REQUEST_TIMEOUT_SECONDS: u64 = 5;

/// Connects to a remote Lighthouse (or compatible) validator client via HTTP.
#[derive(Clone)]
pub struct RemoteValidatorClient<E: EthSpec> {
    pub http: HttpClient<E>,
}

impl<E: EthSpec> RemoteValidatorClient<E> {
    /// Uses the default HTTP timeout.
    pub fn new(http_endpoint: String) -> Result<Self, String> {
        Self::new_with_timeout(http_endpoint, Duration::from_secs(REQUEST_TIMEOUT_SECONDS))
    }

    pub fn new_with_timeout(http_endpoint: String, timeout: Duration) -> Result<Self, String> {
        Ok(Self {
            http: HttpClient::new(http_endpoint, timeout)
                .map_err(|e| format!("Unable to create http client: {:?}", e))?,
        })
    }
}

#[derive(Debug)]
pub enum Error {
    /// Unable to parse a URL. Check the server URL.
    UrlParseError(url::ParseError),
    /// The `reqwest` library returned an error.
    ReqwestError(reqwest::Error),
    /// There was an error when encoding/decoding an object using serde.
    SerdeJsonError(serde_json::Error),
    /// The server responded to the request, however it did not return a 200-type success code.
    DidNotSucceed { status: StatusCode, body: String },
}

#[derive(Clone)]
pub struct HttpClient<E> {
    client: Client,
    url: Url,
    timeout: Duration,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> HttpClient<E> {
    /// Creates a new instance (without connecting to the validator client).
    pub fn new(server_url: String, timeout: Duration) -> Result<Self, Error> {
        Ok(Self {
            client: ClientBuilder::new()
                .timeout(timeout)
                .build()
                .expect("should build from static configuration"),
            url: Url::parse(&server_url)?,
            timeout: Duration::from_secs(15),
            _phantom: PhantomData,
        })
    }

    fn url(&self, path: &str) -> Result<Url, Error> {
        self.url.join(path).map_err(|e| e.into())
    }

    pub fn validator(&self) -> Validator<E> {
        Validator(self.clone())
    }

    pub fn json_post<T: Serialize>(
        &self,
        url: Url,
        body: T,
    ) -> impl Future<Item = Response, Error = Error> {
        self.client
            .post(&url.to_string())
            .json(&body)
            .send()
            .map_err(Error::from)
    }

    pub fn json_get<T: DeserializeOwned>(
        &self,
        mut url: Url,
        query_pairs: Vec<(String, String)>,
    ) -> impl Future<Item = T, Error = Error> {
        query_pairs.into_iter().for_each(|(key, param)| {
            url.query_pairs_mut().append_pair(&key, &param);
        });

        self.client
            .get(&url.to_string())
            .send()
            .map_err(Error::from)
            .and_then(|response| error_for_status(response).map_err(Error::from))
            .and_then(|mut success| success.json::<T>().map_err(Error::from))
    }
}

/// Returns an `Error` (with a description) if the `response` was not a 200-type success response.
///
/// Distinct from `Response::error_for_status` because it includes the body of the response as
/// text. This ensures the error message from the server is not discarded.
fn error_for_status(
    mut response: Response,
) -> Box<dyn Future<Item = Response, Error = Error> + Send> {
    let status = response.status();

    if status.is_success() {
        Box::new(future::ok(response))
    } else {
        Box::new(response.text().then(move |text_result| match text_result {
            Err(e) => Err(Error::ReqwestError(e)),
            Ok(body) => Err(Error::DidNotSucceed { status, body }),
        }))
    }
}

/// Provides the functions on the `/validators` endpoint of the validator client http api.
#[derive(Clone)]
pub struct Validator<E>(HttpClient<E>);

impl<E: EthSpec> Validator<E> {
    fn url(&self, path: &str) -> Result<Url, Error> {
        self.0
            .url("validators/")
            .and_then(move |url| url.join(path).map_err(Error::from))
            .map_err(Into::into)
    }

    pub fn get_validators(&self) -> impl Future<Item = Vec<ValidatorResponse>, Error = Error> {
        let client = self.0.clone();
        self.url("")
            .into_future()
            .and_then(move |url| client.json_get(url, vec![]))
    }

    pub fn add_validator(
        &self,
        deposit_amount: u64,
        directory: PathBuf,
    ) -> impl Future<Item = PublicKey, Error = Error> {
        let client = self.0.clone();
        let body = AddValidatorRequest {
            deposit_amount,
            directory: Some(directory),
        };
        self.url("add")
            .into_future()
            .and_then(move |url| client.json_post::<_>(url, body))
            .and_then(|response| error_for_status(response).map_err(Error::from))
            .and_then(|mut success| success.json().map_err(Error::from))
    }

    pub fn remove_validator(&self, validator: &PublicKey) -> impl Future<Item = (), Error = Error> {
        let client = self.0.clone();
        let body = ValidatorRequest {
            validator: validator.clone(),
        };
        self.url("remove")
            .into_future()
            .and_then(move |url| client.json_post::<_>(url, body))
            .and_then(|response| error_for_status(response).map_err(Error::from))
            .and_then(|_| Ok(()))
    }

    pub fn start_validator(&self, validator: &PublicKey) -> impl Future<Item = (), Error = Error> {
        let client = self.0.clone();
        let body = ValidatorRequest {
            validator: validator.clone(),
        };
        self.url("start")
            .into_future()
            .and_then(move |url| client.json_post::<_>(url, body))
            .and_then(|response| error_for_status(response).map_err(Error::from))
            .and_then(|_| Ok(()))
    }

    pub fn stop_validator(&self, validator: &PublicKey) -> impl Future<Item = (), Error = Error> {
        let client = self.0.clone();
        let body = ValidatorRequest {
            validator: validator.clone(),
        };
        self.url("stop")
            .into_future()
            .and_then(move |url| client.json_post::<_>(url, body))
            .and_then(|response| error_for_status(response).map_err(Error::from))
            .and_then(|_| Ok(()))
    }

    pub fn exit_validator(&self, validator: &PublicKey) -> impl Future<Item = (), Error = Error> {
        let client = self.0.clone();
        let body = ValidatorRequest {
            validator: validator.clone(),
        };
        self.url("exit")
            .into_future()
            .and_then(move |url| client.json_post::<_>(url, body))
            .and_then(|response| error_for_status(response).map_err(Error::from))
            .and_then(|_| Ok(()))
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Error {
        Error::ReqwestError(e)
    }
}

impl From<url::ParseError> for Error {
    fn from(e: url::ParseError) -> Error {
        Error::UrlParseError(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::SerdeJsonError(e)
    }
}
